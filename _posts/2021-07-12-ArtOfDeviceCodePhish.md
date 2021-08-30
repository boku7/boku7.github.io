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

## Overview
Guide for Azure Device Code phishing - infrastructure setup to exploitation.

The Azure cloud services can be used by offensive operators to host phishing infrastructure that sometimes bypasses organzations spam filters & email protection services.   
When an Azure user registers a tenant in Azure Active Directory, they are provided with an .onmicrosoft.com domain. This tenant can be used not only to deliver your phishes to some organizations inboxes, but also confuse targeted users who are unfimiliar with how Azure services work.

First read Dr Nestori Syynimaa's blog post. The aim of this post is not to republish his great work, but to build on it; providing a detailed "How to Guide" for red teams aiming to succeed in a successful Device Code Phish. 
+ [o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)

## Azure Phishing Infrastructure Setup

### Azure Subscription
+ Create an Azure account at [azure.microsoft.com](https://azure.microsoft.com/en-us/free/).
  +  You will be required to verify with a valid email, phone number, and credit card.
+ Login to your newly created Azure subscription at [portal.azure.com](https://portal.azure.com/).

### Azure Active Directory
+ Go to the Azure Active Directory (AAD) service from within your Azure portal.  
![](/assets/images/gotoAAD.png)
+ Create a new Azure Active Directory Tenant. 
  + Azure AD > Overview > Manage Tenant > +Create
![](/assets/images/createTenant.png)
+ Switch to the newly created Azure AD Tenant. 
  + Azure AD > Overview > Manage Tenant > Select Tenant > Switch
+ Create an admin user within the your tenants Azure AD. 
  + (AAD > Users > New User)
  + Assign them the role Global Administrator.  
  ![](/assets/images/newAdminUser.png)
+ To disable 2FA prompting go to the Properties blade, click Manage Security defaults, then toggle Enable Security defaults to No. 

### Office 365
For your phishing operators you will want to assign them a license that includes Exchange Online & the Microsoft Office desktop application suite. I have found that for Azure Device Code phishing, sending phish emails from the Windows Outlook Desktop application has the most reliablity. Using OWA, different operating systems, and different email clients returns mixed results. Typically a target organization that utilizes Azure AD for their business needs is likely a Windows shop that uses Outlook. You will want to perform solid recon and adjust as needed.

#### Exchange Online & Office Trial Licenses
+ Sign-in to [office.com](https://portal.office.com) with your new admin user.  

![](/assets/images/devcode/loginPhishAdmin.png)  

+ Go to [admin.microsoft.com](https://admin.microsoft.com/Adminportal/Home).
+ Go to Billing > Purchase Services from the admin panel.
+ Select a license package which inclues both Exchange Online and the Office desktop application suite.
  + Microsoft 365 Business Premium & Microsoft 365 E3 are good options.
  + There are many different license packages offered by Microsoft which iclude EXO & Office.
+ After selecting the license package, click the 'Start free trial' hyperlink.  
![](/assets/images/devcode/startE5trial.png)  

+ Prove you're not a R0b0T with a text message, and 'Start your free trial'.
  ![](/assets/images/devcode/robotChallenge.png)





+ Go to the admin console and get a 25 user subscription for Office Business Premium.
+ Create a user that will be used for phishing and assign them a license.

### Enable DKIM for Phishing AAD
+ Open powershell, then install & import the ExchangeOnlineManagement module.
```powershell
Install-Module -Name ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement
```
+ Connect to Exchange Online (EXO) with your admin user and enable DKIM for your AAD tenant.
```powershell
Connect-ExchangeOnline -UserPrincipalName admin@msftauth.onmicrosoft.com
# Login to prompt
New-DkimSigningConfig -DomainName msftauth.onmicrosoft.com -Enabled $true
```

## Phishing Operator Setup

### Windows 10 Virtual Machine
+ Download and install your favorite hypervisor. I use VMWare Fusion / Workstation Pro.
+ Create a windows VM using a prebuilt VM package or an ISO.
  - [Windows 10 ISO Download Page](https://www.microsoft.com/en-us/software-download/windows10ISO)
    - Use a mac or linux box for the ISO download
  - [Windows 10 VM Download](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)

### Outlook Application
+ On your windows 10 VM, install office by going to [office.com](https://www.office.com), login, and click the "Install Office" button from the splash page.
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

## Hooking a Phish

#### AzureAD Module - Dumping Users, Apps, Conditial Access Policies ++

#### RefreshTo-Outlook

#### Dumping Emails with TokenTactics

#### Opening Outlook Web App in a Browser with TokenTactics

## References 
+ [rvrsh3ll/TokenTactics Tool](https://github.com/rvrsh3ll/TokenTactics)  
+ [o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)  
+ [o365blog.com - AAD Internals](https://o365blog.com/aadinternals/)
