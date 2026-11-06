"""Automated Build Script for FlareRedirect Windows Standalone Executable (.exe).
Reads version from version.json, embeds Windows File Version Resource metadata,
compiles via PyInstaller, and produces both dist/FlareRedirect.exe and dist/FlareRedirect_v{version}.exe.
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
VERSION_FILE = ROOT_DIR / "version.json"


def get_version_info():
    version_str = "1.1.0"
    if VERSION_FILE.is_file():
        try:
            with open(VERSION_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                version_str = data.get("version", "1.1.0")
        except Exception:
            pass

    # Clean version string (e.g., '1.1.0' or 'v1.1.0')
    cleaned = version_str.lstrip("vV").strip()
    parts = cleaned.split(".")
    while len(parts) < 4:
        parts.append("0")
    
    try:
        quad = tuple(int(p) for p in parts[:4])
    except ValueError:
        quad = (1, 1, 0, 0)

    return cleaned, quad


def generate_version_info_file(version_str: str, quad: tuple) -> Path:
    target_path = ROOT_DIR / "file_version_info.txt"
    content = f"""# UTF-8
# Windows Version Info Resource for FlareRedirect
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={quad},
    prodvers={quad},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        '040904b0',
        [StringStruct('CompanyName', 'FlareRedirect'),
        StringStruct('FileDescription', 'FlareRedirect - Cloudflare 301 Redirect Engine'),
        StringStruct('FileVersion', '{version_str}.0'),
        StringStruct('InternalName', 'FlareRedirect'),
        StringStruct('LegalCopyright', 'Copyright (c) 2026 FlareRedirect'),
        StringStruct('OriginalFilename', 'FlareRedirect_v{version_str}.exe'),
        StringStruct('ProductName', 'FlareRedirect'),
        StringStruct('ProductVersion', '{version_str}.0')])
      ]), 
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)
    return target_path


def build():
    version_str, quad = get_version_info()
    print("====================================================================")
    print(f"  BUILD FLAREREDIRECT STANDALONE WINDOWS EXECUTABLE (v{version_str})")
    print("====================================================================")
    print(f"Target Version: v{version_str} (Resource quad: {quad})")

    # Generate version info file
    ver_file = generate_version_info_file(version_str, quad)
    print(f"Generated Version Resource: {ver_file.name}")

    # Build PyInstaller command
    icon_path = ROOT_DIR / "src" / "app_icon.ico"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconsole",
        "--onefile",
        f"--name=FlareRedirect_v{version_str}",
        f"--version-file={ver_file}",
        "--clean",
        "--noconfirm",
    ]

    if icon_path.is_file():
        cmd.append(f"--icon={icon_path}")
        cmd.append(f"--add-data={icon_path};src")
        icon_png = ROOT_DIR / "src" / "app_icon.png"
        if icon_png.is_file():
            cmd.append(f"--add-data={icon_png};src")

    # Add entry script
    cmd.append("src/main.py")

    print("\nExecuting PyInstaller command:")
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=str(ROOT_DIR))

    if result.returncode != 0:
        print("\n[ERROR] PyInstaller build failed! Check errors above.")
        sys.exit(result.returncode)

    versioned_exe = ROOT_DIR / "dist" / f"FlareRedirect_v{version_str}.exe"

    # Strict policy: ensure no bare unversioned exe remains in dist/
    bare_exe = ROOT_DIR / "dist" / "FlareRedirect.exe"
    if bare_exe.is_file():
        try:
            bare_exe.unlink()
        except Exception:
            pass

    if versioned_exe.is_file():
        print("\n====================================================================")
        print(f"  BUILD EXECUTABLE SUKSES! (FlareRedirect v{version_str})")
        print("====================================================================")
        print(f"  Executable Versi Resmi : {versioned_exe}")
        print(f"  Windows File Version   : {version_str}.0")
        print(f"  Product Version        : {version_str}.0")
        print("  (Seluruh file .exe dijamin memiliki tag versi resmi)")
        print("====================================================================\n")
    else:
        print(f"\n[ERROR] Output file not found: {versioned_exe}")
        sys.exit(1)


if __name__ == "__main__":
    build()

