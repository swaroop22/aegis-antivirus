"""
Aegis Defender Pro - Standalone Windows Executable Compiler
Uses PyInstaller to compile server.py and all engines into a single standalone .exe with icon.
Run on any Windows computer: python build_windows_exe.py
"""

import os
import subprocess
import sys

def build_exe():
    print('===========================================================')
    print('  BUILDING STANDALONE WINDOWS EXECUTABLE: Aegis Defender')
    print('===========================================================')
    
    try:
        import PyInstaller
    except ImportError:
        print('[*] Installing PyInstaller compiler...')
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
    
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--name=Aegis Defender Pro',
        '--onefile',
        '--icon=assets/app_icon.ico',
        '--add-data=static;static',
        '--add-data=engine;engine',
        '--add-data=data;data',
        '--add-data=assets;assets',
        'server.py'
    ]
    
    print('[+] Running PyInstaller...')
    subprocess.check_call(cmd)
    print('===========================================================')
    print('  BUILD SUCCESSFUL! Binary created in dist/Aegis Defender Pro.exe')
    print('===========================================================')

if __name__ == '__main__':
    build_exe()