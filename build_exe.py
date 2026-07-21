import PyInstaller.__main__
import os

data_files = [
    '--add-data=templates;templates',
    '--add-data=static;static',
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
    '--hidden-import=webview',
    '--collect-all=webview',
    '--collect-all=clr_loader',
    # Add more if you use more packages
])
