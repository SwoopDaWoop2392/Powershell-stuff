# Special notes 
Below are Special notes on specific scripts.

# MSP_Term Notes
IMPORTANT INFORMATION PLEASE READ

Termination Script v1.0

This is very roughly put together, but I encourage all to make adjustments for more efficient execution. Furthur refinement could include removing AADConnect check which is needed for clients who have On-Prem AD, and Exchange Online but no Azure (Entra) AD Connect. Additional refinement could include setting up hardware credential, or token login for O365 services, altering commands to fit MSGraph, and ensuring all AD info including Manager is filled in.
This Script was made with blood and tears of SwoopDaWoop's enemies, so don’t be a jerk and steal credit.

The intention of this script is providing streamlined and standardized Termination for MSPs and their clients. This script should be placed and ran from the primary DC or DC with AD Connect of the client domain. This script relies on filling in client specific information in specific sections to use elsewhere in relevant areas with commands/functions that have been created with idea that Active Directory is On-Prem and EMAIL is setup as one of the following: 
   On-Prem Exchange Server
   On-Prem Exchange Server in Hybrid mode with Exchange online
   Or just Exchange Online only

The script will use the client variables along with some other logic to determine which commands to use for what situation. This is intended to make it easier to roll out to all clients as it's set once per client and forget. I've surpressed most of output that made the script to "busy" but there is still some that gets through due to the commands, but unless it's an error and in red text you can ignore it..

Below is the list of actions performed:

  -Export group memberships (AD)
  
  -Change password (AD)
  
  -Change account description (AD)
  
  -Remove all groups except domain users (AD)
  
  -Hide email from Address Book (On Prem/Exchange Online)
  
  -Convert mailbox to shared and give access to manager (On Prem/Exchange Online – if applicable)
  
  -Block sign-in to O365 (Hybrid/Exchange Online)
  
  -Remove licenses from O365 account (Hybrid/Exchange Online – if applicable)
  
  -If Exchange Online with no Entra Connect
  
  •	Export group membership
  
  •	Remove groups
  
  •	Reset Azure password
  
  •	Disable Azure account 
  
  •	If mailbox access is not needed delete Azure account
  
  -Disable account (AD)
  
  -Move account to disabled users OU (AD)
  
  -Sync with O365 (if applicable)
