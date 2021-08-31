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
In this section we will setup an Azure Account Subscription, which will host our malicious Azure Active Directory (AAD) phishing domain 'msftsec.onmicrosoft.com'. We will create an 'Admin' Global Administrator user to acquire 30-day Office 365 trial licenses, setup Exchange Online, enable DKIM, and create phishing accounts for Red Team Operators.

### Azure Account Subscription Setup
+ Go to the Azure Active Directory (AAD) service from within your Azure portal.  

![](/assets/images/devcode/gotoAAD.png)

+ Create a new Azure Active Directory Tenant. 
  + Azure AD > Overview > Manage Tenant > +Create   

![](/assets/images/devcode/createTenant.png)

+ Switch to the newly created Azure AD Tenant. 
  + Azure AD > Overview > Manage Tenant > Select Tenant > Switch
+ Create an admin user within the your tenants Azure AD. 
  + AAD > Users > New User
  + Assign them the role Global Administrator.  

  ![](/assets/images/devcode/newAdminUser.png)
  
+ To disable 2FA prompting go to the Properties blade, click Manage Security defaults, then toggle Enable Security defaults to No. 

### Office 365 Setup
For your phishing operators you will want to assign them a license that includes Exchange Online & the Microsoft Office desktop application suite. I have found that for Azure Device Code phishing, sending phish emails from the Windows Outlook Desktop application has the most reliablity. Using OWA, different operating systems, and different email clients returns mixed results. Typically a target organization that utilizes Azure AD for their business needs is likely a Windows shop that uses Outlook. You will want to perform solid recon and adjust as needed.

#### Exchange Online & Office Trial Licenses
+ Sign-in to [office.com](https://portal.office.com) with your new admin user.  

![](/assets/images/devcode/loginPhishAdmin.png)  

+ Go to [admin.microsoft.com](https://admin.microsoft.com/Adminportal/Home).
+ Go to Billing > Purchase Services from the admin panel.
+ Select a license package with Exchange Online and the Office Application Suite.
  + Microsoft 365 Business Premium & Microsoft 365 E3 are good options.
  + There are many different license packages offered by Microsoft which iclude EXO & Office.
+ After selecting the license package, click the 'Start free trial' hyperlink.   
 
![](/assets/images/devcode/startE5trial.png)  

+ Prove you're not a R0b0T with a text message, 'Start your free trial', then 'Try now'.  

![](/assets/images/devcode/robotChallenge.png)

+ Only 2 more prompts to go!  

![](/assets/images/devcode/confirmTrialLic.png)

+ Create a user to send phishing emails from by going to the Users > Active Users tab and clicking 'Add a user' from the Active Users page.  

![](/assets/images/devcode/activeUsersWindow.png)

+ Give your phishing user a convincing name, as this name will be seen by the target you are attempting to phish.

![](/assets/images/devcode/devopsUser.png)

+ Assign a license to your phishing user.

![](/assets/images/devcode/assignLicense.png)

### Enable DKIM for Malicious Azure AD
+ Open powershell, then install & import the ExchangeOnlineManagement module.
```powershell
Install-Module -Name ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement
```
+ Connect to Exchange Online (EXO) with your admin user and enable DKIM for your AAD tenant.
```powershell
Connect-ExchangeOnline -UserPrincipalName admin@msftsec.onmicrosoft.com
# Login to prompt
New-DkimSigningConfig -DomainName msftsec.onmicrosoft.com -Enabled $true
```
+ Return your DKIM Selector records for testing your domains DKIM setup.
```powershell
PS C:\Users\boku\TokenTactics> Get-DkimSigningConfig –identity msftsec.onmicrosoft.com| Format-List Identity,Selector1CNAME,Selector2CNAME
Identity       : msftsec.onmicrosoft.com
Selector1CNAME : selector1-msftsec-onmicrosoft-com._domainkey.msftsec.onmicrosoft.com
Selector2CNAME : selector2-msftsec-onmicrosoft-com._domainkey.msftsec.onmicrosoft.com
```
+ [Useful blog for Azure DKIM debugging](https://dirteam.com/bas/2020/08/17/field-notes-dkim-and-missing-selector-records/).

## Phishing Operator Setup
In this section we will setup Windows 10 Virtual Machines (VMs) for Red Team Operators, install the desktop Outlook Client on the Operators VMs using the Office 365 trials, enable powershell scripts, install the [AADInternals](https://o365blog.com/aadinternals/) powershell module, install the [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) powershell module, and install the [AzureAD](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0) powershell module. 

### Windows 10 Virtual Machine Setup 
We will need a powershell environment to run the AADInternals, TokenTactics, and AzureAD powershell modules. Sometimes I use [macOS powershell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-macos?view=powershell-7.1) which runs TokenTactics fine. Although I have ran into issues running other modules, as some require DLLs. 

For sending the phishing emails, a windows environment is optional. For HTML&CSS emails, we recommend sending from the Windows Outlook desktop client if the target is a Windows shop that uses Outlook internally. Sending HTML&CSS emails from macOS clients to targets with Windows email clients has had mixed results.

VMWare & VirtualBox are great options for type-2 hypervisors:
+ VMWare offers free 30 day trials for [VMWare Fusion](https://www.vmware.com/products/fusion/fusion-evaluation.html) for macOS & [VMWare Workstation Pro](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html) for Linux or Windows.
+ [VirtualBox](https://www.virtualbox.org/wiki/Downloads) works too.

To create a windows Virtual Machine (VM) you can use a prebuilt VM image for your chosen hypervisor, or you can create your own Windows 10 VM by using the Windows 10 ISO. The Windows 10 ISO does not require a license to use. You can click to skip entering a license key while installing Windows. The unlicensed Windows version works well for this, although you will find difficulty in changing the background. Alternatively you can use the Windows 10 developer prebuilt VM images. The issue with the prebuilt VM's is they will expire and you may end up getting locked out of the VM. The Windows ISO method does not expire.

- [Windows 10 ISO Download](https://www.microsoft.com/en-us/software-download/windows10ISO)
    - Download the ISO from macOS or Linux.
- [Windows 10 Developer VM Download](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)

### Outlook Application Setup for RTO

+ On your windows 10 VM, install office by going to [office.com](https://www.office.com), login, and click 'Install Office' from the splash page.
+ Unfortunately you will need to install the entire Office desktop application Suite just to get the Outlook application.
+ After the download, follow the instructions to install.
+ After installation of the Outlook application on the Red Team Operators VM, login to Outlook using the Red Team Operators phishing email address.
  + For this walkthough, our Red Team Operators phishing email is 'DevOps@msftsec.onmicrosoft.com'.

### Changing the VMs Powershell Execution Policy
+ You'll have to change the Powershell Execution Policy, otherwise you'll be prevented from invoking the script in Windows.
  - Navigate to Windows Settings, click on 'Update & Security'
  - On the left side towards the bottom, you'll see a 'For developers' tab
  - After clicking that, you should see a PowerShell header towards the bottom, click on the 'Apply' button.
  
![](/assets/images/devcode/powershell-global-bypass.png)

+ You're not done though, local user permissions will still be restricted, to fix this, do the following:
  - Run Powershell as Administrator
  - Copy and paste this command in Powershell: 
 ```powershell
 Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
 ```

### [AADInternals PowerShell Module Installation](https://o365blog.com/aadinternals/#installation)
We will be using the AADInternals powershell module to determine if the target uses Azure. AADInternals also has a Device Code phishing functionality, and the TokenTactics module is derived from the epic AADInternals project.
```powershell
# Install the module
Install-Module AADInternals
```
+ Now that the AADInternals module is installed, we can use `import-module` for a powershell session to get access to the AADInternals commands.
+ Just like all the powershell modules, we will need to import them into every new powershell session we want to use them in.

### [TokenTactics PowerShell Module Installation](https://o365blog.com/aadinternals/#installation)

+ Download or clone the [TokenTactics GitHub repository](https://github.com/rvrsh3ll/TokenTactics)

+ Ensure the TokenTactics folder is on the RTOs Window VMs file system.

```powershell
PS C:\Users\boku> cd .\TokenTactics
PS C:\Users\boku\TokenTactics> Import-Module .\TokenTactics.psd1
```

+ You will need to import TokenTactics when you want to use it within a powershell session.
+ Ignore the warning about the naming convention. We did not follow proper Microsoft powershell naming convention, so it throws a warning.

![](/assets/images/devcode/import-mod-warning.png)


### [AzureAD PowerShell Module Installation](https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0)
We will install the AzureAD powershell module for enumerating the targets AzureAD after acquiring a Refresh Token from the Device Code Phish campaign.
```powershell
Install-Module AzureAD
```

## Reconnaissance & Phish Strength Testing
The Azure Device Code phishing technique is dependant on your target using Azure Active Directory. Before launching an Azure Device Code phishing campaign, it is wise to ensure your target uses Azure.
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
In this section we will create a working HTML&CSS Azure Device Code phishing template email, ensure it works in Outlook, and send an Azure Device Code phishing email. We've included a [Device Code phishing Outlook email template in the TokenTactics repo](https://github.com/rvrsh3ll/TokenTactics/blob/main/resources/DeviceCodePhishingEmailTemplate.oft) to get you started!

### Device Code Phishing Email Template Setup
For the phishing campaign we'll need a convincing phishing email to send to targets. This was the main issue we had with using the AADInterals module to send phishing emails. AADInternals sends phishing emails using the Microsoft Graph API. For testing this works great, but for Red Team engagements we wanted to go the extra mile and get some convincing HTML&CSS phishing emails going. 

Initially we were using this [DeviceCodePhish.ps1 PowerShell script created by Mr. Un1k0d3r & Rvrsh3ll](https://gist.github.com/rvrsh3ll/b8bfc113acf5726746929bef2e620f8d), but we kept adding more & more functionality, so we dubbed it TokenTactics!

To get some ideas, we began digging through Microsoft One-Time Password (OTP) emails. We created a phishing template in HTML&CSS, and we've included it in the TokenTactics GitHub repository for you!
+ [Device Code Phishing Outlook Email Template](https://github.com/rvrsh3ll/TokenTactics/blob/main/resources/DeviceCodePhishingEmailTemplate.oft)
+ [Device Code Phishing Email Template in HTML](https://github.com/rvrsh3ll/TokenTactics/blob/main/resources/example_phish.html)

On the RTO Windows VM, open the TokenTactics folder and double-click the DeviceCodePhishingEmailTemplate.oft file.  

![](/assets/images/devcode/phishTemplateExp.png) 
+ This file is an Outlook Item Template (OTF) file, so it will open in the desktop Outlook application.

![](/assets/images/devcode/devcodePhishEmail1.png)
+ For the Azure Device Code Phishing Campaign we will be replacing the `<REPLACE-WITH-DEVCODE-FROM-TOKENTACTICS>` text with the device codes that are generated from the TokenTactics powershell module.
+ Feel free to modify this template. You may need to, as this email template may have been signatured and is "burned".

#### Phishing with TokenTactics

+ You can now begin generating a code to phish with, there are two basic commands depending on the organization you're attempting to hack:
  - Get-AzureToken -Client MSGraph <This command will generate a basic code that you'll use against most standard organizations>
  - Get-AzureToken -Client DODMSGraph <This command will generate a code that you'll use again Department of Depense / Military Organizations>
+ After picking one of the above commands, run it and you should be able to generate a code with it. This is what you'll use with the email template above.

![](/assets/images/devcode/generating-token.png)

## Hooking a Phish

#### AzureAD Module - Dumping Users, Apps, Conditial Access Policies ++

#### RefreshTo-Outlook

#### Dumping Emails with TokenTactics

#### Opening Outlook Web App in a Browser with TokenTactics

## References 
+ [rvrsh3ll/TokenTactics Tool](https://github.com/rvrsh3ll/TokenTactics)  
+ [o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)  
+ [o365blog.com - AAD Internals](https://o365blog.com/aadinternals/)
