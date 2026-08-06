"""Standalone desktop entry point.

Runs the existing FastAPI app (app.py) on a background thread and shows it
in a native window via pywebview - no browser tab is ever opened.
"""

import ctypes
import os
import re
import socket
import sys
import threading
import time

# In a --windowed PyInstaller build there is no console at all, so
# sys.stdout/sys.stderr are None. Any print() (including the error path
# below if the server is slow to start) would itself raise AttributeError
# and silently kill the whole app with no trace - give them a no-op sink.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

# Two crash mitigations for a real bug we hit: pywebview's WinForms host
# has a broken AccessibleObject.Bounds implementation that can recurse
# infinitely (crashing the whole app) when something walks the window's
# accessibility/automation tree. On this machine that something is NVIDIA
# Overlay, which hooks GPU (Direct3D) presentation surfaces for its
# capture/overlay features - and WebView2 uses D3D11 for GPU-accelerated
# compositing by default, making it a target. Fix: force WebView2 to
# render without GPU compositing (no D3D surface to hook) and disable the
# renderer's accessibility tree (nothing for an automation client to walk).
# This env var is read by the WebView2 runtime itself and OVERRIDES
# whatever AdditionalBrowserArguments pywebview sets internally
# (documented WebView2 behavior), so it must be set before the webview
# module creates any window/environment.
os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = "--disable-gpu --disable-renderer-accessibility"

import uvicorn
import webview

import app as app_module
import config_store

if getattr(sys, 'frozen', False):
    # Packaged .exe: assets bundled alongside templates/static (see
    # build_exe.py) get extracted into this PyInstaller onefile temp dir.
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ICON_PATH = os.path.join(BASE_DIR, "assets", "icon.ico")

DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_BORDER_COLOR = 34
DWMWA_CAPTION_COLOR = 35
DWMWA_TEXT_COLOR = 36

LIGHT_BG, LIGHT_TEXT = "#f3f4f6", "#111827"  # Tailwind gray-100 / gray-900


def _colorref(hex_color: str) -> int:
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    return (b << 16) | (g << 8) | r


def _set_titlebar_theme(hwnd: int) -> None:
    """Best-effort, one-time (at window creation): recolor the native title
    bar/border to match the page's default (light) background instead of
    the OS default, so it blends in rather than clashing.

    Deliberately NOT re-invoked later (e.g. from the dark mode toggle) -
    calling DWM window-attribute APIs again after the window is already
    live is what triggered the accessibility recursion crash above, so this
    runs exactly once, from the native `shown` event, matching how
    pywebview's own internal dark-mode support applies this at startup.
    Silently does nothing on Windows versions that don't support these DWM
    attributes (pre-Windows 11) - the window just keeps the default color.
    """
    try:
        dwmapi = ctypes.windll.dwmapi
        bg = ctypes.c_int(_colorref(LIGHT_BG))
        text = ctypes.c_int(_colorref(LIGHT_TEXT))
        dark_flag = ctypes.c_int(0)

        dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(dark_flag), ctypes.sizeof(dark_flag))
        dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ctypes.byref(bg), ctypes.sizeof(bg))
        dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ctypes.byref(bg), ctypes.sizeof(bg))
        dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, ctypes.byref(text), ctypes.sizeof(text))
    except Exception:
        pass


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(host: str, port: int, timeout: float = 45.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _unique_path(path: str) -> str:
    """Return `path` unchanged if free, otherwise `name (1).ext`, `name (2).ext`,
    ... - mirrors how a browser avoids clobbering a repeat download."""
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    n = 1
    while True:
        candidate = f"{root} ({n}){ext}"
        if not os.path.exists(candidate):
            return candidate
        n += 1


class Api:
    """Exposed to the page as `window.pywebview.api`. WebView2's built-in
    download handling is inconsistent about where a download lands, so the
    Digital Certificate tab's "Export CSV" button calls this directly
    instead - saving straight to the user's Downloads folder and opening it,
    same as a real Explorer double-click would."""

    def export_csv(self, filename: str, content: str) -> dict:
        try:
            downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(downloads_dir, exist_ok=True)

            safe_name = re.sub(r'[\\/:*?"<>|]', "_", filename or "export.csv").strip() or "export.csv"
            if not safe_name.lower().endswith(".csv"):
                safe_name += ".csv"

            path = _unique_path(os.path.join(downloads_dir, safe_name))
            # utf-8-sig (BOM) so Excel renders non-ASCII cert fields (e.g.
            # accented issuer names) correctly instead of as mojibake.
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                f.write(content)

            try:
                os.startfile(path)  # opens with whatever's associated with .csv
            except Exception:
                pass  # saved either way - opening it is a nicety, not required

            return {"success": True, "path": path}
        except Exception as e:
            return {"success": False, "error": str(e)}


class ServerThread(threading.Thread):
    def __init__(self, host: str, port: int):
        super().__init__(daemon=True)
        config = uvicorn.Config(
            app_module.app, host=host, port=port, log_level="warning"
        )
        self.server = uvicorn.Server(config)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


def main():
    config_store.ensure_config_env_exists()

    host = "127.0.0.1"
    port = _find_free_port()

    server_thread = ServerThread(host, port)
    server_thread.start()

    if not _wait_for_server(host, port):
        print("Failed to start local server", file=sys.stderr)
        server_thread.stop()
        sys.exit(1)

    window = webview.create_window(
        "SandBoxEQ",
        f"http://{host}:{port}/",
        js_api=Api(),
        width=1280,
        height=860,
        min_size=(900, 600),
        background_color=LIGHT_BG,
        text_select=True,  # pywebview disables text selection/copy by default
    )

    window.events.closed += server_thread.stop
    window.events.shown += lambda: _set_titlebar_theme(window.native.Handle.ToInt32())

    # Without an explicit icon, the winforms backend falls back to
    # extracting one from sys.executable - which is python.exe (generic
    # icon) when run via `python desktop_app.py`, and only correct in the
    # packaged .exe. Passing it explicitly fixes the taskbar AND the
    # window's own title-bar icon (top-left corner) in both cases.
    icon_kwargs = {"icon": ICON_PATH} if os.path.isfile(ICON_PATH) else {}
    webview.start(**icon_kwargs)

    server_thread.stop()
    server_thread.join(timeout=5)


if __name__ == "__main__":
    main()
