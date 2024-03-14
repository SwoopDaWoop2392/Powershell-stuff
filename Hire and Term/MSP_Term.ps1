# IMPORTANT INFORMATION PLEASE READ
#Termination Script v1.0
#This is very roughly put together, but I encourage all to make adjustments for more efficient execution.
#Furthur refinement could include removing AADConnect check which is needed for clients who have On-Prem AD, and Exchange Online but no Azure (Entra) AD Connect
#   Additional refinement could include setting up hardware credential, or token login for O365 services, altering commands to fit MSGraph, 
#   and ensuring all AD info including Manager is filled in.
#This Script was made with blood and tears of SwoopDaWoop's enemies, so don’t be a jerk and steal credit
#
#The intention of this script is providing streamlined and standardized Termination for MSPs and their clients
#This script should be placed and ran from the primary DC or DC with AD Connect of the client domain
#This script relies on filling in client specific information in the section below to use elsewhere in relevant sections 
#Commands and functions have been created with idea that Active Directory is On-Prem and EMAIL is setup as one of the following: 
#    On-Prem Exchange Server
#    On-Prem Exchange Server in Hybrid mode with Exchange online
#    Or just Exchange Online only
#
#The script will use the client variables below along with some other logic to determine which commands to use for what situation
#This is intended to make it easier to roll out to all clients as it's set once per client and forget
#I've surpressed most of output that made the script to "busy" but there is still some that gets through due to the commands
#Unless it's an error and in red text you can ignore it

#These modules will need to be installed in PowerShell
#   Note: This script and these modules are designed for PowerShell 5.1


#Modules to be installed for script
# Install-Module AzureAD
# Install-Module -Name ExchangeOnlineManagement
# Install-Module MSOnline
# Install-Module Microsoft.Graph -Scope AllUsers


#Current Client Script is set for: NAME OF CLIENT HERE (JOE'S COFFE SHOP)


# -----------------CLIENT SPECIFIC VARIABLES---------------------------

#OU of Disabled Users in Client AD
$DisabledUsersOU = "OU=ORGANIZATIONAL UNIT NAME,DC=DOMAIN,DC=COM"

#See SPECIAL CLIENT VARIABLES section in script for file path group memberships will be exported to

#############################################################################################
# Does client have an on-prem exchange? CHANGE THIS BETWEEN $true or $false                 #
# Does client have a Hybrid setup with Exchange Online? CHANGE THIS BETWEEN $true or $false #
# If the Client is Exchange online only $Onprem = $false, $Hybrid = $false                  #
# This is to determine if some parts of script are triggered or not                         #
$Onprem = $True                                                                             #
$Hybrid = $True                                                                             #
#############################################################################################

#On Prem Exchange Server
$OnPremExchangeServer = "exchange_server_name.domain_name.local"

# -----------------CLIENT SPECIFIC VARIABLES END------------------------







#----------------OTHER SCRIPT VARIABLES-------------------------------
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

if ($Onprem) {
    #Connection URI to connect to OnPrem Exchange PowerShell Web Session
    $ConnectionURI = "http://$OnPremExchangeServer/PowerShell/" 
    #Session setup for OnPrem Exchange commands. The Prefix argument is needed so exchange commands like Set-mailbox are targeted to Exchange on Prem (ExOP) or Online
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionURI -Authentication Kerberos
}

#Current Date
$Date = Get-Date -Format d 

#Funtion to get Terminated User's AD account and verify valid for use in script.
function Find-Username {
    $adcount = 0
    #Do-Until loop to get username, check if what was entered gets results in AD, and returns the value 
    Do {
        $username = (Read-Host -Prompt "Enter the terminated user's AD Account Name (JDoe)").trim()
        try {
            $validation = Get-ADUser -Identity $UserName -ErrorAction stop > $null
            $Success = $true
        }
        catch {
            if ($adcount -lt 3) { Write-Host "Unable to find user in AD, please try again." }
        }
        
        $adcount++

    }
    #Until lopp with run until 3 fails or success flag is triggered
    Until($adcount -eq 3 -or $Success)

    if (-not($success)) { Write-host "Unable to find user after 3 attempts. Please verify username and run script again" }
    #returns value to be used in rest of script
    return $username
}

#Function to automatically get and validate manager information. If manager info is not filled in for user being terminated this funtion will return false
function Find-MgrAccount {
    #Gets user being terminated and selects the samaccount information entered in Manager information
    $mgraccount = Get-ADUser -Identity $Username -Properties manager -ErrorAction stop | Select-Object @{label = 'Manager'; Expression = { (Get-ADUser $_.Manager -Properties samaccountname).samaccountname } } | Select-Object  -expandproperty manager
    #If manager information is not filled in for AD, the above will error. This returns false to be checked agasint in other parts of script.
    try {
        $Validation = Get-ADUser -Identity $mgraccount -ErrorAction stop > $null
        Return $mgraccount
    }
    catch {
        return $false
    }
}


function Find-MgrEmail {
    $adcount = 0
    $needinput = $true
    #If manager account doesnt return false, will use that information to get automatically get email address of manager
    #ad-user command used here to keep all onprem options avaliable. No situation where AD emailadress is different than actual email like possible with Onprem AD and O365 exchange.
    if ($false -ne $MGRAccount) {
        $mgremail = Get-ADUser -Identity $MGRAccount -Properties emailaddress -ErrorAction stop | Select-Object -expandproperty emailaddress
        try {
            $Validation = Get-ADUser -filter { EmailAddress -eq $mgremail } -ErrorAction stop > $null
            $Success = $true
            $needinput = $false
        }
        catch {
            $NeedInput = $true
        }
    }
    #if email validation fails or manager account wasnt found prompts for manager email address.
    if ($NeedInput) {
        Do {  
            $mgremail = (Read-Host -Prompt "Please enter the manager's Email Adress").trim()
            try {
                $validation = Get-ADUser -filter { EmailAddress -eq $mgremail } -ErrorAction stop > $null
                $Success = $true
            }
            catch { 
                Write-Host "Unable to find manager email in AD, please try again."
            }
            $adcount++
        }
        Until($adcount -eq 3 -or $Success)
    }

    if (-not($success)) { Write-host "Unable to find user after 3 attempts. Please verify email and run script again" }
    #returns manager email address
    return $MGREmail

}

function Find-UserEmail365 {
    $emailcheck = $null
    $needinput = $false
    $validation = $null
    $Success = $true
    #searches for email based off username in exchange online.
    $useremail = get-exomailbox -filter "alias -like '$username'" -ErrorAction stop | Select-Object -ExpandProperty primarysmtpaddress
    try {
        $validation = Get-EXOMailbox -Identity $useremail -ErrorAction Stop > $null
    }
    catch {
        $needinput = $True
        $Success = $false
    }
    #to verify the search returned the correct result
    if ($false -eq $needinput) {
        Write-Host "Is the following email correct? Email address of user: $useremail"
        $emailcheck = Read-Host -Prompt "(y)es or (n)o?"
    }
    #sets flags for manual intervention if email address returned is not correct
    if ($emailcheck -eq 'n') {
        $needinput = $True 
        $Success = $false
    } 

    if ($needinput) {
        Do { 
            $useremail = (Read-Host -Prompt "Please enter the users's Email Adress").trim()
            try {
                $validation = Get-exomailbox -identity $useremail -ErrorAction stop > $null
                $Success = $true
            }
            catch { 
                Write-Host "Unable to find user email, please try again."
            }
            $adcount++
        }Until($adcount -eq 3 -or $Success)
    }

    if (-not($success)) { Write-host "Unable to find user after 3 attempts. Please verify email and run script again" }
    #returns Useremail for rest of script
    Return $useremail

}

function Find-MgrEmail365 {
    $adcount = 0
    $needinput = $false
    $Success = $true
    #If manager account funtion is not false will search for manager email in O365 exchange
    if ($false -ne $mgraccount) {
        $mgremail = get-exomailbox -filter "alias -like '$mgraccount'" -ErrorAction stop | Select-Object -ExpandProperty primarysmtpaddress
        try {
            $Validation = Get-exomailbox -identity $mgremail -ErrorAction stop > $null
        }
        catch {
            $NeedInput = $true
            $Success = $false
        }
    }

    #verify search
    if ($false -eq $needinput) {
        Write-Host "Is this the correct email address of the manager to be granted access: $mgremail"
        $emailcheck = Read-Host -Prompt "(Y)es or (N)o?"
    }

    if ($emailcheck -eq 'N') {
        $needinput = $true
        $Success = $false
    }

    if ($NeedInput) {
        Do {  
            $mgremail = (Read-Host -Prompt "Please enter the manager's Email Adress").trim()
            try {
                $validation = Get-exomailbox -identity $mgremail -ErrorAction stop > $null
                $Success = $true
            }
            catch { 
                Write-Host "Unable to find manager email in AD, please try again."
            }
            $adcount++
        }Until($adcount -eq 3 -or $Success)
    }

    if (-not($success)) { Write-host "Unable to find user after 3 attempts. Please verify email and run script again" }

    return $mgremail
}


#-----------------SCRIPT FOR TERMINATION--------------------------------
 
#Connect to O365 services
if ($Hybrid -or !$Onprem) {
    Connect-Graph -Scopes User.ReadWrite.All, Organization.Read.All, Group.ReadWrite.All -NoWelcome
    Connect-ExchangeOnline
}
#AD powershell module
Import-Module ActiveDirectory

#Call function to get the Terminated user's information
$username = Find-Username
$UserDisplayName = Get-ADUser -Identity $UserName | Select-Object -ExpandProperty Name 
#Check if manager needs access to user's mailbox and get manager info
$MailboxAccess = Read-Host -Prompt "Does this user's manager or anyone else require access to their mailbox? (Y)es or (N)o"
#setup of different configurations; in order. On Prem exchange server with hybrid O365 exchange online, On Prem exchange server only, O365 Exchange online only.
#Different setups require different commands to get and manipulate information in the rest of the script

#On Prem exchange server with hybrid O365 exchange online
if ($Hybrid) {
    if ($MailboxAccess -eq 'Y') {
        $MGRAccount = Find-MgrAccount
        $MGREmail = Find-MgrEmail365
        if ($false -ne $mgeraccount) {
            $ManagerDisplayname = Get-ADUser -Identity $MGRAccount | Select-Object -ExpandProperty Name 
        }
        else { 
            $ManagerDisplayname = Get-exomailbox -identity $mgremail -ErrorAction stop | Select-Object -ExpandProperty Displayname 
        }
    }
    $useremail = Find-UserEmail365
}

#On Prem exchange server only
if ($Onprem -and ($false -eq $Hybrid)) {
    if ($MailboxAccess -eq 'Y') {
        $MGRAccount = Find-MgrAccount
        $MGREmail = Find-MgrEmail
        if ($false -ne $mgeraccount) {
            $ManagerDisplayname = Get-ADUser -Identity $MGRAccount | Select-Object -ExpandProperty Name 
        }
        else { 
            $ManagerDisplayname = Get-exomailbox -identity $mgremail -ErrorAction stop | Select-Object -ExpandProperty Displayname 
        }
    } 
    $useremail = Get-ADUser -Identity $Username -Properties emailaddress -ErrorAction stop | Select-Object -expandproperty emailaddress
}

# O365 Exchange online only
if ($false -eq $Onprem) {
    if ($MailboxAccess -eq 'Y') {
        $MGRAccount = Find-MgrAccount
        $MGREmail = Find-MgrEmail365
        $ManagerDisplayname = Get-exomailbox -identity $mgremail -Properties Displayname | Select-Object -ExpandProperty Displayname
    }
    $useremail = Find-UserEmail365
}

# Pre Script Actions and checks
if ($MailboxAccess -eq 'Y') {
    Write-Host "Please verify the following information is correct;
    `r`nUser being Terminated: $UserDisplayName
    `r`nUser Name: $UserName
    `r`nUser Email Address: $useremail
    `r`nManager: $ManagerDisplayname
    `r`nManager Email: $MGREmail
    "
}
else {
    Write-Host "Please verify the following information is correct;
    `r`nUser being Terminated: $UserDisplayName
    `r`nUser Name: $UserName
    `r`nUser Email Address: $useremail
    "
}
$Response = Read-Host -Prompt "Is this information Correct? (y)es or (n)o"

if ($Response -ne 'y') {
    Write-Host "(y)es was not selected. Please gather the correct information and run this script again."
    exit
}



###############    SPECIAL CLIENT VARIABLES   ###########################################################################
#Due to the user name being a part of the file names these variables needed to be declared after gathering the username #
$ReportPath = "C:\Users\EXAMPLEUSER\Documents\Terms\$Username.txt"
$365reportpath = "C:\Users\EXAMPLEUSER\Documents\Terms\${Username}365.txt"
########################################################################################################################

#ACTIVE DIRECTORY

# Export Current Group Memberships
Get-ADPrincipalGroupMembership $UserName | Out-File -FilePath $reportpath
# Change password for AD Account-----------------------------------------------You can put your own random password here
Set-ADAccountPassword -Identity $username -NewPassword (ConvertTo-SecureString -AsPlainText "fXJ210F1uTMZ!" -Force)
# Change discription
Set-ADUser $UserName -Description "Disabled $Date"
# Remove user from Groups
$groups = Get-ADPrincipalGroupMembership -Identity $Username
# Remove the user from all groups except for the Domain Users group
foreach ($group in $groups) {
    if ($group.Name -ne "Domain Users") {
        Remove-ADGroupMember -Identity $group -Members $Username -Confirm:$false
    }
}


#EXCHANGE/EMAIL
#OnPrem Commands
if ($Onprem) {
    # Connect to Exchange OnPremises
    Import-PSSession $Session -prefix 'ExOP'
    if ($Hybrid) {
        # Hide email from Global Address List
        Set-ExOPRemoteMailbox -Identity $UserName -HiddenFromAddressListsEnabled $true
        if ($MailboxAccess -eq 'Y') {
            #convert mailbox to shared if manager access needed
            Set-Mailbox -Identity $Username -Type Shared -ErrorAction Stop
            #Delegate access to manager
            Add-MailboxPermission $username -User "$mgremail" -AccessRights FullAccess -InheritanceType all -AutoMapping $True -Erroraction Stop
        }
        #get UserID for commands that dont accept piped (like revoke)
        $O365UserID = get-mguser -UserId $useremail | Select-Object -ExpandProperty Id
        #revoke online sessions
        Revoke-MgUserSignInSession -UserId $O365UserID
        #remove licenses from user
        $UserLicenses = (Get-MgUserLicenseDetail -UserID $Useremail).SkuId
        Set-MgUserLicense -UserId $useremail -RemoveLicenses $UserLicenses -AddLicenses @()
    }
    else {
        Set-ExOPMailbox -Identity $UserName -HiddenFromAddressListsEnabled $true 
        if ($MailboxAccess -eq 'Y') {
            Set-ExOPMailbox -Identity $Username -Type Shared -ErrorAction Stop
            Start-Sleep -s 10
            Add-ExOPMailboxPermission $username -User "$mgremail" -AccessRights FullAccess -InheritanceType all -AutoMapping $True -Erroraction Stop
        }
    } 
    
    Get-PSSession | Remove-PSSession
}

#No on Prem Commands
if (!$Onprem) {
    #Check AD Connect Status
    $ADconnect = Get-MgOrganization | Select-Object OnPremisesSyncEnabled
    $userID = get-mguser -UserId $useremail | Select-Object -ExpandProperty Id
    # Hide email from Global Address List
    Set-Mailbox -Identity $UserName -HiddenFromAddressListsEnabled $true
    #remove licenses from user
    $UserLicenses = (Get-MgUserLicenseDetail -UserID $Useremail).SkuId
        Set-MgUserLicense -UserId $useremail -RemoveLicenses $UserLicenses -AddLicenses @()
    #revoke online sessions
    get-mguser -UserId $useremail | Revoke-MgUserSignInSession
    if ($MailboxAccess -eq 'Y') {
        #convert mailbox to shared if manager access needed
        Set-Mailbox -Identity $Username -Type Shared -ErrorAction Stop
        #Delegate access to manager
        Add-MailboxPermission $username -User "$mgremail" -AccessRights FullAccess -InheritanceType all -AutoMapping $True -Erroraction Stop
        #Check if disconnected O365 user
        if ($false -eq $ADconnect) {
            #Reset O365 password
            Reset-MgUserAuthenticationMethodPassword -UserId $userID -ForceChangePassword
            #Get group membership azure
            Get-MgUserMemberOf -UserId $userID | foreach-object {get-mggroup -groupid $_.id} | Format-List Id, Displayname, GroupTypes | out-file $365reportpath
            #Remove Azure Groups
            Get-MgUserMemberOf -UserId $userID | foreach-object {Remove-AzureADGroupMember -ObjectID $_.id -MemberID $userID}
            #Disable Azure account
            Set-AzureADUser -ObjectID $useremail -AccountEnabled $false
        }
    }

    #Mailbox access not needed with disconnected O365 Account
    if (($MailboxAccess -eq 'N') -and ($false -eq $ADconnect)) {
        #Get group membership azure
        Get-AzureADUserMembership -ObjectId $useremail | Out-File -FilePath $365reportpath
        #Delete Azure account
        Remove-AzureADUser -ObjectId $useremail
    }
}
# Disable AD Account
Disable-ADAccount -Identity $UserName
# Move to disabled users OU
Get-ADUser -identity $username | Move-ADObject -TargetPath $DisabledUsersOU
if ((!$Onprem -and $ADconnect) -or $Hybrid) {
    #Sync to 365    
    Start-ADSyncSyncCycle -PolicyType Delta
}
Disconnect-MgGraph
