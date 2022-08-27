#powershell.exe -noprofile -ExecutionPolicy Bypass -File C:\Users\jr\Desktop\setupwindows.ps1

#TODO
#Uninstall programs
#
function enable_RDP{
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}
function download_applications{
    mkdir c:\temp
    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutFile "C:\temp\firefox.exe"
}
function install_applications{
    c:\temp\firefox.exe
}
function setup_settings{
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchBoxTaskbarMode -Value 0 -Type DWord
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -Value 0 -Type DWord -Force
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Value 0 -Type DWord -Force
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0 -Type DWord -Force
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskbarViewMode -Value 2 -Type DWORD -Force
    New-Item "HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds" -Name EnableFeeds -Value 0 -Type DWORD -Force
    #Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name StoreAppsOnTaskbar -Value 0 -Type DWord -Force
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -Value 0 -Type DWord -Force

    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -Force

    Stop-Process -Processname Explorer -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -Force
}
function uninstall_applications{
    #$application = Get-WmiObject -Class Win32_Product -Filter "Name = 'Windows PC Health Check'"
    #$application.Uninstall()
    #ps onedrive | Stop-Process -Force
    start-process "$env:windir\SysWOW64\OneDriveSetup.exe" "/uninstall"
}
function debloat_store{
    #(Get-AppxPackage -Name * -AllUsers).Name
    foreach ($app in $apps) {    
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage
        Get-AppXProvisionedPackage -Online | where DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online
            
        $appPath="$Env:LOCALAPPDATA\Packages\$app*"
        Remove-Item $appPath -Recurse -Force -ErrorAction 0
    }
}
$apps=@(
    #"Microsoft.GetHelp"
    #"Microsoft.GetStarted"

    #"Microsoft.NarratorQuickStart"
    #"Microsoft.XboxGameCallableUI"
    #"Microsoft.BingWeather"
    #"Microsoft.Microsoft3dViewer"
    #"Microsoft.MicrosoftOfficeHub"
    #"Microsoft.MicrosoftSolitaireCollection"
    #"Microsoft.Office.OneNote"
    #"Microsoft.People"
    #"Microsoft.SkypeApp"
    #"Microsoft.WindowsAlarms"
    #"Microsoft.WindowsFeedbackHub"
    #"Microsoft.Maps"
    #"Microsoft.Xbox.TCUI"
    #"Microsoft.XboxApp"
    #"Microsoft.XboxGameOverlay"
    #"Microsoft.XboxGamingOverlay"
    #"Microsoft.XboxIdentityProvider"
    #"Microsoft.XboxSpeechToTextOverlay"
    #"Microsoft.YourPhone"
    #"Microsoft.ZuneMusic"
    #"Microsoft.ZuneVideo"
    #"SpotifyAB.SpotifyMusic"
    #"Disney.37853FC22B2CE"
    #"Microsoft.Windows.SecHealthUi"
)
#uninstall_applications
#setup_settings
debloat_store
#download_applications
