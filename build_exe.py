import PyInstaller.__main__
import os

data_files = [
    '--add-data=templates;templates',
    '--add-data=static;static',
    # Bundled so desktop_app.py can resolve ICON_PATH at runtime (for the
    # window's own title-bar/taskbar icon) even though PyInstaller's
    # --icon flag below already embeds it as the .exe's own resource icon.
    '--add-data=assets;assets',
    # NOTE: config.env is deliberately NOT bundled - the packaged app
    # creates a blank one next to itself on first run (config_store.py),
    # so real API keys never get embedded inside the .exe.
]

PyInstaller.__main__.run([
    'desktop_app.py',          # Native desktop window entry point (no browser tab)
    '--onefile',
    '--windowed',               # No console window behind the app window
    '--noconfirm',
    '--clean',
    '--name=SandBoxEQ',
    '--icon=assets/icon.ico',
    *data_files,
    '--hidden-import=uvicorn',
    '--hidden-import=fastapi',
    '--hidden-import=dotenv',
    '--hidden-import=aiohttp',
    '--hidden-import=colorama',
    '--hidden-import=jinja2',
    '--hidden-import=multipart',
    '--hidden-import=config_store',
    '--hidden-import=url_lookup',
    '--hidden-import=ip_lookup',
    '--hidden-import=ioc_tools',
    '--hidden-import=subnet_tools',
    '--hidden-import=truststore',
    '--hidden-import=webview',
    '--collect-all=webview',
    '--collect-all=clr_loader',
    # The app itself never imports these, but PyInstaller pulls them in
    # transitively from whatever else is installed in the build environment
    # (pygments -> PIL -> numpy) and they more than doubled the .exe (~20 MB
    # -> ~44 MB). Excluded so the size doesn't depend on the build machine.
    '--exclude-module=numpy',
    '--exclude-module=PIL',
    '--exclude-module=pygments',
    # Add more if you use more packages
])
