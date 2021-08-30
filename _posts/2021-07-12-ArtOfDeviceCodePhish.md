---
title: The Art of the Device Code Phish
date: 2021-7-12
layout: single
classes: wide
tags:
  - Azure
  - AAD
  - Phishing
  - DeviceCode
  - RedTeam
--- 
## Co-Author & Co-Developer: Stephan Borosh
### Index
+ [Overview](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#overview)
+ [Recon - Does the target use Azure Active Directory?](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#recon---does-the-target-use-azure-active-directory)
  + [Install and import AADInternals into powershell](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#install-and-import-aadinternals-into-powershell)
  + [Check if the target domain uses Azure Active Directory](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#check-if-the-target-domain-uses-azure-active-directory)
+ [Infrastruture - Azure Phishing Tenant](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#infrastruture---setting-up-for-the-azure-device-code-phish)
  + [Create an Azure Account](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#create-an-azure-account)
  + [Create an Azure Active Directory Tenant](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#create-an-azure-active-directory-tenant)
  + [Office 365 Licenses & Phish Puppets](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#office-365-licenses--phish-puppets)
+ [Infrastruture - Windows Phishing VM](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#Setup-a-Windows-VM-for-Phishing)
  + [ Setup Windows 10 Outlook Desktop App]()
+ [Phishing]()
  + [Creating a Phishing Email Template]()
  + [Phishing with TokenTactics]()
+ [Hook3d a Phish - Let the Games Begin]()
  + [AzureAD Module - Dumping Users, Apps, Conditial Access Policies ++]()
  + [RefreshTo-AllTheThings]()
  + [Dumping Emails with TokenTactics]()
  + [Opening Outlook Web App in a Browser with TokenTactics]()

## Overview
Guide for Azure Device Code phishing - infrastructure setup to exploitation.

The Azure cloud services can be used by offensive operators to host phishing infrastructure that sometimes bypasses organzations spam filters & email protection services.   
When an Azure user registers a tenant in Azure Active Directory, they are provided with an .onmicrosoft.com domain. This tenant can be used not only to deliver your phishes to some organizations inboxes, but also confuse targeted users who are unfimiliar with how Azure services work.

First read Dr Nestori Syynimaa's blog post. The aim of this post is not to republish his great work, but to build on it; providing a detailed "How to Guide" for red teams aiming to succeed in a successful Device Code Phish. 
+ [o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)

## Azure Phishing Infrastructure Setup

### Azure Subscription Setup
+ Create an Azure account at [azure.microsoft.com](https://azure.microsoft.com/en-us/free/).
  +  You will be required to verify with a valid email, phone number, and credit card.
+ Login to your newly created Azure subscription at [portal.azure.com](https://portal.azure.com/).

### Azure Active Directory Setup
+ Go to the Azure Active Directory (AAD) service from within your Azure portal  
![](/assets/images/gotoAAD.png)
+ Create a new Azure Active Directory Tenant 
  + Azure AD > Overview > Manage Tenant > +Create
![](/assets/images/createTenant.png)
+ Switch to the newly created Azure AD Tenant 
  + Azure AD > Overview > Manage Tenant > Select Tenant > Switch
+ Create an admin user within the your tenants Azure AD 
  + (AAD > Users > New User)
  + Assign them the role Global Administrator  
  ![](/assets/images/newAdminUser.png)
+ During a Red Team engagement you will likely need to share the phishing accounts. Disable the 2FA requirements for the AAD phishing tenant.
  + With the AAD phishing tenant selected, go to the Properties blade, click Manage Security defaults, then toggle Enable Security defaults to No. 

### Office 365 Setup
+ Sign-in to portal.office.com with your new admin user
+ Go to the admin console and get a 25 user subscription for Office Business Premium
+ Create a user that will be used for phishing and assign them a license

### Enable DKIM for Phishing AAD
+ From your windows VM, open a powershell window and install the ExchangeOnlineManagement module
```powershell
Install-Module -Name ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement
```
+ Connect to the EXO module with your admin user you created for your phishing domain and enable DKIM for your tenant
```powershell
Connect-ExchangeOnline -UserPrincipalName admin@msftauth.onmicrosoft.com
# Login to prompt
New-DkimSigningConfig -DomainName msftauth.onmicrosoft.com -Enabled $true
```

## Phishing Operator Setup

### Operator Windows 10 Virtual Machine Setup
+ Download and install your favorite hypervisor. I use VMWare Fusion / Workstation Pro.
+ Create a windows VM using a prebuilt VM package or an ISO.
  - [Windows 10 ISO Download Page](https://www.microsoft.com/en-us/software-download/windows10ISO)
    - Use a mac or linux box for the ISO download
  - [Windows 10 VM Download](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)

##### Operator Outlook Application Setup
+ On your windows 10 VM, install office by going to www.office.com, logging in with your licensed phishing user, and clicking the "Install Office" button on the splash page.
+ I have noticed that while creating HTML emails from different operating systems & email clients, formatting can change drastically. 
  - The Outlook desktop app on windows appears to be the most stable client to send from. You may need to adapt this based on your targets email client environment.

## Azure AD Recon
The Azure Device Code phishing technique is dependant on your target using Azure Active Directory. Before launching an Azure Device Code phishing campaign, it is wise to ensure your target uses Azure.
### Install and import AADInternals into powershell
```powershell
# Install the module
Install-Module AADInternals
# Import the module
Import-Module AADInternals
```
  - https://o365blog.com/aadinternals/#installation

### Check if the target domain uses Azure Active Directory

##### Target is registered to Azure Active Directory
```powershell
Invoke-AADIntReconAsOutsider -Domain theharvester.world | Format-Table
Tenant brand:       The Harvester
Tenant name:        theharvester
Tenant id:          1d5551a0-f4f2-4101-9c3b-394247ec7e08
DesktopSSO enabled: False
Name                          DNS   MX  SPF DMARC Type    STS
----                          ---   --  --- ----- ----    ---
theharvester.onmicrosoft.com True True True False Managed
theharvester.world           True True True False Managed
```
- We observe that the target domain theharvester.world is registered to Azure Active Directory, and their email services are True. This means that the target uses Exchange Online for their email.
  - We can confirm this by using the linux dig tool:
```bash
dig -t MX +short theHarvester.World
0 theharvester-world.mail.protection.outlook.com.
```

##### Target is *NOT* registered to Azure Active Directory
```powershell
Invoke-AADIntReconAsOutsider -Domain isNotRegisteredToAzureAD.com | Format-Table
Domain isNotRegisteredToAzureAD.com is not registered to Azure AD
```

## Phishing

#### Creating a Phishing Email Template
+ You'll want to create a template that makes sense. Obviously, you should adapt if the Azure code template changes but for the time being, you should be able to use a basic template. There's one included in the "TokenTactics" Github repository see: "/resources/example_phish.html"

The basic template will look like this:

![](/assets/images/azure-phish-temp.png)

+ You'll notice that the template already has a device code populated. After you generate a code with TokenTactics, you can edit the HTML code that you'll be using for the template and replace the placeholder code "571012" with the code that you have generated. In addition you'll see that the phishing template's title is "Device Code" - feel free to modify this within the template to "Action Required" depending on the nature of your phishing campaign.

#### Phishing with TokenTactics
+ Download TokenTactics on a Windows Machine: [rvrsh3ll/TokenTactics Tool](https://github.com/rvrsh3ll/TokenTactics)
+ Import the script into Powershell: Import-Module .\TokenTactics.psd1

## Hook3d a Phish - Let the Games Begin

#### AzureAD Module - Dumping Users, Apps, Conditial Access Policies ++

#### RefreshTo-Outlook

#### Dumping Emails with TokenTactics

#### Opening Outlook Web App in a Browser with TokenTactics

## References 
+ [rvrsh3ll/TokenTactics Tool](https://github.com/rvrsh3ll/TokenTactics)  
+ [o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)  
+ [o365blog.com - AAD Internals](https://o365blog.com/aadinternals/)
