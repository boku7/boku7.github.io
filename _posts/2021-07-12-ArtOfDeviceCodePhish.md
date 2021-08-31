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
Connect-ExchangeOnline -UserPrincipalName admin@msftauth.onmicrosoft.com
# Login to prompt
New-DkimSigningConfig -DomainName msftauth.onmicrosoft.com -Enabled $true
```

## Phishing Operator Setup
In this section we will setup Windows 10 Virtual Machines (VMs) for Red Team Operators, install the desktop Outlook Client on the Operators VMs using the Office 365 trials, enable powershell scripts, install the [AADInternals](https://o365blog.com/aadinternals/) powershell module, install the [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) powershell module, and install the [AzureAD](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0) powershell module. 

### Windows 10 Virtual Machine Setup 
We will need a powershell environment to run the AADInternals, TokenTactics, and AzureAD powershell modules. Sometimes I use [macOS powershell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-macos?view=powershell-7.1) which runs TokenTactics fine. Although I have ran into issues running other modules, as some require DLLs. 

For sending the phishing emails, a windows environment is optional. For HTML/CSS emails, we recommend sending from the Windows Outlook desktop client if the target is a Windows shop that uses Outlook internally. Sending HTML/CSS emails from macOS clients to targets with Windows email clients has had mixed results.

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

### Install and import AADInternals into powershell
```powershell
# Install the module
Install-Module AADInternals
# Import the module
Import-Module AADInternals
```
  - https://o365blog.com/aadinternals/#installation



## Azure AD Recon
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

#### Creating a Phishing Email Template
+ You'll want to create a template that makes sense. Obviously, you should adapt if the Azure code template changes but for the time being, you should be able to use a basic template. 
+ An [Azure Device Code phishing template is included in TokenTactics Github repository](https://github.com/rvrsh3ll/TokenTactics/blob/main/resources/example_phish.html)

![](/assets/images/azure-phish-temp.png)

+ You'll notice that the template already has a device code populated. After you generate a code with TokenTactics, you can edit the HTML code that you'll be using for the template and replace the placeholder code "571012" with the code that you have generated. In addition you'll see that the phishing template's title is "Device Code" - feel free to modify this within the template to "Action Required" depending on the nature of your phishing campaign.

#### Phishing with TokenTactics
+ Download TokenTactics on a Windows Machine: [rvrsh3ll/TokenTactics Tool](https://github.com/rvrsh3ll/TokenTactics)
+ You'll have to change the Powershell Execution Policy, otherwise you'll be prevented from invoking the script in Windows.
  - Navigate to Windows Settings, click on "Update & Security"
  - On the left side towards the bottom, you'll see a "For developers" tab
  - After clicking that, you should see a PowerShell header towards the bottom, click on the "Apply" button:
  
![](/assets/images/devcode/powershell-global-bypass.png)

+ You're not done though, local user permissions will still be restricted, to fix this, do the following:
  - Run Powershell as Administrator
  - Copy and paste this command in Powershell: Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
  - Navigate to the TokenTactics Directory and run this command to prevent warnings: Unblock-File 'C:\Users\yourusername\Desktop\TokenTactics-main\TokenTactics-main\modules\\*.ps1'
  - You can now import the module and begin.
  - Run this command: Import-Module .\TokenTactics.psd1
  - You may see this warning, ignore it:

![](/assets/images/devcode/import-mod-warning.png)

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
