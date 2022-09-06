#Execution policy bypass
#PowerShell.exe -ExecutionPolicy Bypass -File "THISFILE.ps1"
#powershell.exe -noprofile -ExecutionPolicy Bypass -File THISFILE.ps1

#TODO

function enable_RDP{
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}
function setup_settings{
    #Disable Windows first time run crap...
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
    #Disable new user logon "HI WELCOME TO NEW EXPERIENCE" crap...
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -Value 0 -Type DWord -Force
    #Disable privacy setting questions on new user logon
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OO -Name ShellFeedsTaskbarViewMode -Value 2 -Type DWORD -Force
    #Show file extension
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0 -Type DWord -Force
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskbarViewMode -Value 2 -Type DWORD -Force
    #Remove taskbar icons
    New-Item "HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds" -Name EnableFeeds -Value 0 -Type DWORD -Force
    #Set high performance power management & hard drive always on
    powercfg /SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    powercfg -x -disk-timeout-ac 0
}
function debloat_store{
    #comment and add to variable apps to select specific software
    if($apps.Length -eq 0){
        $apps = (Get-AppxPackage -Name * -AllUsers).Name
    }
    Write-Host('')
    $keepApps
    Read-Host -Prompt "###These apps won't be removed =). Press key to debloat store..."
    foreach ($keepApp in $keepApps){
        if($apps -contains $keepApp){
            $tmpPos = $apps.IndexOf($keepApp)
            $apps[$tmpPos] = ""
        }
    }
        foreach ($app in $apps) {
        if($app -ne ""){
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage
            Get-AppXProvisionedPackage -Online | where DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online
            $appPath="$Env:LOCALAPPDATA\Packages\$app*"
            Remove-Item $appPath -Recurse -Force -ErrorAction 0
        }else{
            Write-Host("App not deleted")
        }
    }
    ps onedrive | Stop-Process -Force
    start-process "$env:windir\SysWOW64\OneDriveSetup.exe" "/uninstall"
}
#keepApps won't be deleted from debloat_store.
$keepApps=@(
"Microsoft.MSPaint"
)
#Manually add apps to delete here
$apps=@(
#Example ->"Microsoft.SkypeAppe"
)
function list_Applications(){
    Get-WmiObject -Class Win32_Product | Select-Object -Property Name
    #Get-WmiObject -Class Win32_Product
}
while(1){
    Write-Host("1. Setup settings")
    Write-Host("2. Debloat store apps")
    Write-Host("3. Enable remote desktop RDP")
    Write-Host("4. List all bloatware from store")
    Write-Host("q. Exit")
    $select = Read-Host -Prompt "Select: "
    switch($select){
        '1' {setup_settings}
        '2' {debloat_store}
        '3' {enable_rdp}
        '4' {(Get-AppxPackage -Name * -AllUsers).Name}
        'q' {Exit}
    }    
}
