' ==============================================================================
' Aegis Defender Pro - Silent Windows Desktop App Launcher
' Runs server invisibly in background and opens chromeless desktop app window
' ==============================================================================
Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")

' Get current project directory
ScriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)

' Start server in background without black command window (0 = hidden)
WshShell.Run "cmd /c cd /d """ & ScriptDir & """ && python server.py 8787", 0, False

' Wait for server to bind port
WScript.Sleep 1500

' Open in standalone app window using Edge (available on all Windows 10/11) or Chrome
AppUrl = "http://localhost:8787"
EdgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
ChromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"

If FSO.FileExists(EdgePath) Then
    WshShell.Run """" & EdgePath & """ --app=" & AppUrl & " --window-size=1280,840", 1, False
ElseIf FSO.FileExists(ChromePath) Then
    WshShell.Run """" & ChromePath & """ --app=" & AppUrl & " --window-size=1280,840", 1, False
Else
    WshShell.Run AppUrl, 1, False
End If