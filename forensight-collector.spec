# PyInstaller spec for the USB collector (NFR portability: single executable, footprint < 50 MB).
# Build on each target OS:  pyinstaller forensight-collector.spec   ->  dist/forensight-collector(.exe)
# Copy it to the USB stick together with tools/ (winpmem / avml) and rules/ is not needed on the victim.
# The analysis side (Volatility, WeasyPrint, dashboard) stays on the analyst machine and is excluded here.
block_cipher = None

a = Analysis(
    ["cli.py"],
    pathex=["."],
    hiddenimports=["collector.runner", "collector.live", "collector.logs", "collector.artifacts", "collector.memory",
                   "core.manifest", "core.case", "core.signing", "nacl.bindings", "_cffi_backend"],
    excludes=["fastapi", "starlette", "uvicorn", "weasyprint", "pydyf", "fontTools", "PIL", "qrcode", "yara", "Evtx",
              "jinja2", "pytest", "tkinter", "numpy", "pandas", "matplotlib", "api", "analyzer", "demo", "IPython",
              "http.server", "xmlrpc", "pydoc_data"],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [], name="forensight-collector", debug=False, strip=True,
          upx=True, console=True)
