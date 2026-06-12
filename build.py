#!/usr/bin/env python3
"""
WinIntel — PyInstaller build script
Compiles winintel.py into a standalone .exe for use on Windows targets.

Usage (run on Windows or Wine):
    pip install pyinstaller rich
    python build.py
"""

import subprocess, sys, shutil, os
from pathlib import Path

ENTRY   = "winintel.py"
OUTNAME = "winintel"
DIST    = Path("dist")

def main():
    print(f"[*] Building {OUTNAME}.exe ...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--clean",
        "--name", OUTNAME,
        "--add-data", "definitions.json;.",
        "--hidden-import", "rich",
        "--hidden-import", "rich.console",
        "--hidden-import", "rich.panel",
        "--hidden-import", "rich.rule",
        ENTRY,
    ]
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("[!] Build failed"); sys.exit(1)
    exe = DIST / f"{OUTNAME}.exe"
    if exe.exists():
        size = exe.stat().st_size / 1024 / 1024
        print(f"[+] Built: {exe}  ({size:.1f} MB)")
        print(f"[+] Transfer {exe} to target and run:")
        print(f"    winintel.exe -i systeminfo.txt")
        print(f"    systeminfo | winintel.exe --quick")
    else:
        print(f"[!] Expected {exe} not found")

if __name__ == "__main__":
    main()
