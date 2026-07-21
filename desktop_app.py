"""Standalone desktop entry point.

Runs the existing FastAPI app (app.py) on a background thread and shows it
in a native window via pywebview - no browser tab is ever opened.
"""

import ctypes
import socket
import sys
import threading
import time

import uvicorn
import webview

import app as app_module
import config_store

# NOTE: An earlier version of this window used frameless=True with a custom
# HTML title bar to get a seamless look. That reliably crashed
# (pywebview/WinForms raises "AccessibilityObject.Bounds ... maximum
# recursion depth exceeded" as soon as anything queries the frameless
# window's accessibility info - e.g. Alt+Tab, taskbar thumbnail hover, or
# Narrator - which happens routinely on real machines). Instead, we keep the
# normal native window (reliable resize/snap/accessibility) and recolor its
# title bar/border via the same DWM attributes pywebview itself uses
# internally for dark mode, so it still blends with the page instead of
# using the OS default color.
DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_BORDER_COLOR = 34
DWMWA_CAPTION_COLOR = 35
DWMWA_TEXT_COLOR = 36

LIGHT_BG, LIGHT_TEXT = "#f3f4f6", "#111827"  # Tailwind gray-100 / gray-900
DARK_BG, DARK_TEXT = "#111827", "#f3f4f6"    # Tailwind gray-900 / gray-100


def _colorref(hex_color: str) -> int:
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    return (b << 16) | (g << 8) | r


def _set_titlebar_theme(hwnd: int, is_dark: bool) -> None:
    """Best-effort: recolor the native title bar/border to match the page.
    Silently does nothing on Windows versions that don't support these DWM
    attributes (pre-Windows 11) - the window just keeps the default color."""
    try:
        dwmapi = ctypes.windll.dwmapi
        bg = ctypes.c_int(_colorref(DARK_BG if is_dark else LIGHT_BG))
        text = ctypes.c_int(_colorref(DARK_TEXT if is_dark else LIGHT_TEXT))
        dark_flag = ctypes.c_int(1 if is_dark else 0)

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


def _wait_for_server(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


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


class WindowApi:
    """Exposed to the page as pywebview.api.* - lets the dark-mode toggle
    keep the native title bar in sync with the page's own theme."""

    def __init__(self):
        self.window = None

    def set_theme(self, is_dark: bool):
        hwnd = self.window.native.Handle.ToInt32()
        _set_titlebar_theme(hwnd, is_dark)


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

    api = WindowApi()
    window = webview.create_window(
        "SandBoxEQ",
        f"http://{host}:{port}/",
        width=1280,
        height=860,
        min_size=(900, 600),
        background_color=LIGHT_BG,
        js_api=api,
    )
    api.window = window

    window.events.closed += server_thread.stop
    window.events.shown += lambda: _set_titlebar_theme(window.native.Handle.ToInt32(), False)

    webview.start()

    server_thread.stop()
    server_thread.join(timeout=5)


if __name__ == "__main__":
    main()
