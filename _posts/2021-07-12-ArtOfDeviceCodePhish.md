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
  + [Install and import AADInternals into powershellPermalink](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#install-and-import-aadinternals-into-powershell)
  + [Check if the target domain uses Azure Active Directory](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#check-if-the-target-domain-uses-azure-active-directory)
    + [Target is registered to Azure Active Directory](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#target-is-registered-to-azure-active-directory)
    + [Target is NOT registered to Azure Active Directory](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#target-is-not-registered-to-azure-active-directory)
+ [Infrastruture - Setting up for the Azure Device Code Phish](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#infrastruture---setting-up-for-the-azure-device-code-phish)
  + [Create an Azure Account](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#create-an-azure-account)
  + [Create an Azure Active Directory Tenant](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#create-an-azure-active-directory-tenant)
  + [Office 365 Licenses & Phish Puppets](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html#office-365-licenses--phish-puppets)

## Overview
Infrastructure setup & tips for catching a "Device Code Phish" during red team engagements.

First read Dr Nestori Syynimaa's blog post. The aim of this post is not to republish his great work, but to build on it; providing a detailed "How to Guide" for red teams aiming to succeed in a successful Device Code Phish. 
+ [o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)

## Recon - Does the target use Azure Active Directory?
#### Install and import AADInternals into powershell
```powershell
# Install the module
Install-Module AADInternals
# Import the module
Import-Module AADInternals
```
  - https://o365blog.com/aadinternals/#installation

#### Check if the target domain uses Azure Active Directory

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

## Infrastruture - Setting up for the Azure Device Code Phish

#### Create an Azure Account
+ Create an Azure account at [azure.microsoft.com](https://azure.microsoft.com/en-us/free/) & login to [portal.azure.com](https://portal.azure.com/)
- You will need "verify" with an email, phone number, and credit card

#### Create an Azure Active Directory Tenant
+ Go to the Azure Active Directory service from within your Azure portal  
![](/assets/images/gotoAAD.png)
+ Create a new Azure Active Directory Tenant (Azure AD > Overview > Manage Tenant > +Create)  
![](/assets/images/createTenant.png)
+ Switch to the newly created Azure AD Tenant (Azure AD > Overview > Manage Tenant > Select Tenant > Switch)
+ Create an admin user within the your tenants Azure AD (AAD > Users > New User)
  - Assign them the role Global Administrator  
  ![](/assets/images/newAdminUser.png)

#### Office 365 Licenses & Phish Puppets
+ Signin to portal.office.com with your new admin user
+ Go to the admin console and get a 25 user subscription for Office Business Premium
+ Create a user that will be used for phishing and assign them a license


## External References 
[o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)
[o365blog.com - AAD Internals](https://o365blog.com/aadinternals/)
