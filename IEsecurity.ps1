[CmdletBinding()]
	param(
	    [Parameter(Mandatory=$true)]
        [String]$username,
        [Parameter(Mandatory=$true)]
        [String]$password,
        [Parameter(Mandatory=$true)]
        [String]$domainname
    )
    Start-Sleep -s 150
   New-Item c:\new_file.txt -type file
   Add-Content c:\new_file.txt $username
   Add-Content c:\new_file.txt $password
   $SecurePassword= ConvertTo-SecureString -String $password -AsPlainText -Force
    
function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}
function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
}
Disable-UserAccessControl
Disable-InternetExplorerESC
Add-Content c:\new_file.txt "status"




Add-WindowsFeature ServerEssentialsRole
Add-Content c:\new_file.txt "status1"
$cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $SecurePassword
Add-Content c:\new_file.txt "status2"
Start-WssConfigurationService -Credential $cred -Force
Add-Content c:\new_file.txt "status3"

$string = $domainname
$netbios,$extension = $string.split('.')
Add-Content c:\new_file.txt $string
Add-Content c:\new_file.txt $netbios
Add-Content c:\new_file.txt $extension
$a= "CN=Users,dc=$netbios,dc=$extension"
Add-Content c:\new_file.txt $a
Get-ADUser -Filter * -SearchBase $a -Properties userPrincipalName | foreach { Set-ADUser $_ -UserPrincipalName "$($_.samaccountname)@$netbios.org"}
