' Tawon Monitor launcher - jalan tersembunyi tanpa jendela konsol
' Panggil: wscript.exe "Start Tawon Monitor.vbs"
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""C:\Users\XCODE\sec-tools\TawonTray.ps1""", 0, False
