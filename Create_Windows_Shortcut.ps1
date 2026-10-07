# ==============================================================================
# Aegis Defender Pro - Windows Desktop Shortcut Creator
# Creates desktop shortcut with custom icon pointing to Aegis Defender Pro
# ==============================================================================
$WshShell = New-Object -ComObject WScript.Shell
$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$ShortcutPath = Join-Path $Desktop 'Aegis Defender Pro.lnk'
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = 'wscript.exe'
$Shortcut.Arguments = '"' + (Join-Path $ScriptDir 'Aegis Defender Pro.vbs') + '"'
$Shortcut.WorkingDirectory = $ScriptDir
$Shortcut.IconLocation = Join-Path $ScriptDir 'assets\app_icon.ico'
$Shortcut.Description = 'Aegis Defender Pro - Next-Gen EDR & Antivirus'
$Shortcut.Save()

Write-Host '[+] Successfully created Aegis Defender Pro shortcut on your Windows Desktop!' -ForegroundColor Green