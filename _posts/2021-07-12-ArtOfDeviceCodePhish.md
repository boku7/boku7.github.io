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

## Overview
Walkthrough of setting up infrastructure on Azure and how to perform "the device code" phishing attack during red team engagements.
Techniques and methodologies Stephan Borosh shared with me.

### Recon - Does the target use Azure Active Directory?
- Install and import AADInternals into powershell
```powershell
# Install the module
Install-Module AADInternals
# Import the module
Import-Module AADInternals
```
  - https://o365blog.com/aadinternals/#installation

- Check if the target domain uses Azure Active Directory

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

##### Target is *NOT* registered to Azure Active Directory
```powershell
Invoke-AADIntReconAsOutsider -Domain isNotRegisteredToAzureAD.com | Format-Table
Domain isNotRegisteredToAzureAD.com is not registered to Azure AD
```

- We observe that the target domain theharvester.world is registered to Azure Active Directory, and their email services are True. This means that the target uses Exchange Online for their email.
  - We can confirm this by using the linux dig tool:
  ```bash
bobby.cooke$ dig -t MX +short theHarvester.World
0 theharvester-world.mail.protection.outlook.com.
  ```

## External References 
[o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)
[o365blog.com - AAD Internals](https://o365blog.com/aadinternals/)
