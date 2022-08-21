# powershell

### Commands
Start-Service -Name "sshd"
Get-NetIPAddress
Start-Service -Name "sshd"
Set-Service -Name "sshd" -StartupType Automatic

function ShowFileExtensions() 
{
    Push-Location
    Set-Location HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
    Set-ItemProperty . HideFileExt "0"
    Pop-Location
}

function HideFileExtensions() 
{
    Push-Location
    Set-Location HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
    Set-ItemProperty . HideFileExt "1"
    Pop-Location
}

###Run wget without forcing through first run of edge/explorer

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/BGInfo.zip" -OutFile "C:\temp\BGInfo.zip"

Expand-Archive -Path C:\temp\BGInfo.zip -DestinationPath C:\temp\BGInfo


New-SmbShare -Name "testshare" -Path "C:\share\test" -FullAccess "Administrator", "Users"

https://community.spiceworks.com/topic/1680417-powershell-script-windows-10-apps-removal
