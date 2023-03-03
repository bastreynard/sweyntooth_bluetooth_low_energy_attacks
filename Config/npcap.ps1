$DownloadUrl = "https://npcap.com/dist/npcap-1.72.exe"
$SaveTo = "C:\temp\npca_installer.exe"

Invoke-WebRequest -uri $DownloadUrl -OutFile $SaveTo
Start-Process -FilePath $SaveTo