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
Blog Contributors: [Bobby Cooke(Boku/@0xBoku)](https://twitter.com/0xBoku), [Stephan Borosh(rvrsh3ll/@424f424f)](https://twitter.com/424f424f), [Octavio Paguaga(@oakTree__)](https://twitter.com/oakTree__), [John Jackson(@johnjhacking)](https://twitter.com/johnjhacking)  

Azure Methodology & Tool Credits: [Charles Hamilton (@Mr.Un1k0d3r)](https://twitter.com/MrUn1k0d3r), [Dr. Nestori Syynimaa(@DrAzureAD)](https://twitter.com/DrAzureAD), [Nikhil Mittal(@nikhil_mitt)](https://twitter.com/nikhil_mitt)

[TokenTactics](https://github.com/rvrsh3ll/TokenTactics) Creators: [Bobby Cooke(Boku/@0xBoku)](https://twitter.com/0xBoku), [Stephan Borosh(rvrsh3ll/@424f424f)](https://twitter.com/424f424f)     

## Overview
In this blog we'll walkthrough the Azure Device Code Phishing attack, from creating a malicous Azure phishing infrastructure, to achieving Azure Account Take-Over (ATO). 

We'll be setting up Azure accounts, Azure Active Directories (AAD), Exchange Online (EXO), spinning up hypervisors, creating Virtual Machines (VMs), creating phishing accounts for Red Team Operators (RTOs), honing our HTML phishing emails, launching an Azure Device Code Phishing campaign, bypassing Multi-Factor Authentication (MFA), bypassing Conditional Access Polcies (CSPs), swapping tokens, dumping Azure AD, dumping exchange mailboxes, and accessing the targets Outlook Web Application (OWA) via our browser. 

Most of this with will be done with free trials, and we'll do our best to stay within the strict scope that Red Teams must abide too.

## Overcoming Red Team Scope Limitations with the Cloud
While real Advanced Persistent Threats (APTs) have no scope in their attacks, Red Team Operators do. These rules make the Initial Access phase much easier for real threat actors, while security providers continue to raise the difficulty bar for RTOs performing threat emulation services.  

### Some attack techniques APTs use which are typically out of scope for RTOs:
- Compromising out-of-scope organizations email systems & email accounts to launch a phishing campaign.
  - The threat actors "Nobelium" compromised a marketing email account for launching their phishing campaign.
    - [New sophisticated email-based attack from NOBELIUM - Microsoft Threat Intelligence Center (MSTIC)](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/)
    - ".. CISA and FBI are engaged in addressing a sophisticated spearphishing campaign. A cyber threat actor leveraged a compromised end-user account from Constant Contact, a legitimate email marketing software company, to send phishing emails to more than 7,000 accounts across approximately 350 government organizations, IGOs, and NGOs. The threat actor sent spoofed emails that appeared to originate from a U.S. Government organization.. " 
      -  [US-Cert.CISA.Gov](https://us-cert.cisa.gov/ncas/alerts/aa21-148a)
- Compromising out-of-scope organizations web servers to host malware.
- Leveraging Zero Day vulnerabilities on out-of-scope organizations web sites, to reflect or redirect phishing victims to malware downloads.
  - A threat actor exploited a Zero Day Cross-Site Scripting (XSS) attack to distribute malware in their phishing campaign.
    - [Phishing campaign uses UPS.com XSS vuln to distribute malware](https://www.bleepingcomputer.com/news/security/phishing-campaign-uses-upscom-xss-vuln-to-distribute-malware/)
  - A threat actor is abusing Zero Day URL Redirect vulnerabilities to bypass email Safe-Link protections to distribute malicious hyperlinks in their phishing emails.
    - [Microsoft Security Intelligence - Active Phishing Campaign Abusing URL Redirects of Vulnerable Organizations Websites](https://twitter.com/MsftSecIntel/status/1432479171813445635)
    - ![](/assets/images/devcode/msftRedir.png)
- Compromising personal computers, online accounts, smartphones, and personal home networks of employees, of the in scope organization.
- Supply-Chain Attacks
  - Threat actors compromised many down-stream companies by exploiting the SolarWinds application supply-chain.
    - [SANS - What You Need to Know About the SolarWinds Supply-Chain Attack](https://www.sans.org/blog/what-you-need-to-know-about-the-solarwinds-supply-chain-attack/)

### Initial Access Methods for Red Teams
While the above paths to Initial Access are out of scope for Red Team Operators performing threat emulation services, we as RTOs still have some viable options remaining. 

As legacy methods continue to increase in difficulty, new Initial Access opportunities are being discovered with the mass adoption of Cloud services. Not only can we as RTOs leverage the Cloud for offensive operations, but the Cloud also opens up an entirely new attack-surface. 

In this walkthrough we will be using our Cloud to attack and breach other Clouds. Welcome to Cloud Wars!

### Traditional Initial Access Methods

Traditional RTO Initial Access methods for Business Email Compromise (BEC) are epicly documented in the [Red Team Infrastructure Wiki]( https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki) created by [Stephan Borosh(rvrsh3ll/@424f424f)](https://twitter.com/424f424f) and [Jeff Dimmock(@bluscreenofjeff)](https://twitter.com/bluscreenofjeff).

If we rule out the out-of-scope ATP methods listed above, we will likely need to gain access to the company by:
+ Physical / Wireless Attacks
+ Exploiting Unpatched Systems that are Exposed to the Internet
+ Compromising a Web Server via a 0-day with a vulnerability like Remote Code Execution (RCE) or Server-Side Request Forgery (SSRF)
+ Credential-Based Attacks such as Password Brute-Forcing, Password-Spraying, or Discovering Active Credentials from a Recent Breach
+ Accessing the Targets VPN via Credential-Based Attacks or some form of Social Engineering
+ Phishing Emails

While there are many vulnerable systems on the internet, it is likely that the Blue Teams of companies performing Red Team exercises have locked down most of the in-scope methods above. It is common that Physical/Wireless attacks are out-of-scope, that the permiter is hardened, and login interfacing including the VPN require MFA or Assemetric Keys. If the Web surface is also hardened, we can turn to finding and attacking Cloud resources. Pentester Academy has great courses on attacking AWS & Azure Active Directory.




The Azure cloud services can be used by offensive operators to host phishing infrastructure that sometimes bypasses organizations spam filters & email protection services.   

When an Azure user registers a tenant in Azure Active Directory, they are provided with an `.onmicrosoft.com` domain. This `.onmicrosoft.com` subdomain can confuse targeted users who are unfamiliar with how Azure services work.

First read Dr Nestori Syynimaa's blog post. The aim of this post is not to republish his great work, but to build on it; providing a detailed "How to Guide" for red teams aiming to succeed in a successful Device Code Phish. 
+ [o365blog.com - Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)

## Azure Phishing Infrastructure Setup
In this section we will setup an Azure Account Subscription, which will host our malicious Azure Active Directory (AAD) phishing domain 'msftsec.onmicrosoft.com'. We will create an 'Admin' Global Administrator user to acquire 30-day Office 365 trial licenses, setup Exchange Online, enable DKIM, and create phishing accounts for Red Team Operators.

### Azure Account Subscription Setup
+ Create an Azure account at [azure.microsoft.com](https://azure.microsoft.com/en-us/free/).
  +  You will be required to verify with a valid email, phone number, and credit card.
+ Login to your newly created Azure subscription at [portal.azure.com](https://portal.azure.com/).

#### Create an Azure Active Directory Tenant
+ Go to the Azure Active Directory (AAD) service from within your Azure portal.  

![](/assets/images/devcode/gotoAAD.png)

+ Create a new Azure Active Directory Tenant. 
  + Azure AD > Overview > Manage Tenant > +Create   

![](/assets/images/devcode/createTenant.png)

+ Switch to the newly created Azure AD Tenant. 
  + Azure AD > Overview > Manage Tenant > Select Tenant > Switch

+ Create an admin user within your tenants Azure AD.
  + AAD > Users > New User
  + Assign Global Administrator role to the admin user.  

  ![](/assets/images/devcode/newAdminUser.png)
  
+ To disable 2FA prompting go to the Properties blade, click Manage Security defaults, then toggle Enable Security defaults to No. 

### Office 365 Setup
Assign Red Team Operators a license bundle which includes Exchange Online & the Office applications. Sending phishing emails from a Windows VM via the Outlook desktop application has been the most reliable. Sending phishing emails from a browser via Outlook Web App (OWA), non-Windows operating systems, and non-Outlook email clients has been unreliable. Your experience may differ, and you are encouraged to experiment to find the best system that works for you.

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
+ Open PowerShell, then install & import the ExchangeOnlineManagement module.

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
In this section we will setup Windows 10 Virtual Machines (VMs) for Red Team Operators, install the desktop Outlook Client on the Operators VMs using the Office 365 trials, enable PowerShell scripts, install the [AADInternals](https://o365blog.com/aadinternals/) PowerShell module, install the [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) PowerShell module, and install the [AzureAD](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0) PowerShell module. 

### Windows 10 VM Setup 
We will need a PowerShell environment to run the AADInternals, TokenTactics, and AzureAD PowerShell modules. Sometimes I use [macOS PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-macos?view=powershell-7.1) which runs TokenTactics fine, but we may run into issues with PowerShell modules that have DLL dependencies.

For sending the phishing emails, a windows environment is optional. For HTML&CSS emails, we recommend sending from the Windows Outlook desktop client if the target is a Windows shop that uses Outlook internally. Sending HTML&CSS emails from macOS clients to targets with Windows email clients has had mixed results.

VMWare & VirtualBox are great options for type-2 hypervisors:
+ VMWare offers free 30 day trials for [VMWare Fusion](https://www.vmware.com/products/fusion/fusion-evaluation.html) for macOS & [VMWare Workstation Pro](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html) for Linux or Windows.
+ [VirtualBox](https://www.virtualbox.org/wiki/Downloads) works too.

![image](https://user-images.githubusercontent.com/19784872/131539380-7c990653-2bf0-45b9-830a-2a493f471d8a.png)

- [Windows 10 ISO Download](https://www.microsoft.com/en-us/software-download/windows10ISO)
    - Download the ISO from macOS or Linux.
- [Windows 10 Developer VM Download](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)

### Outlook Application Setup for RTO

+ On the RTO VMs, we will install Office by going to [office.com](https://www.office.com), logging in with the RTO account, and clicking the 'Install Office' button located at the top-right of the splash page.
  + To install Outlook, we will need to install the entire Office suite.
+ Once the download completes we will follow the on screen instructions to complete the installation phase.
+ We will now open Outlook and login with the RTO's credentials.
  + In this blog, our example RTO account is `DevOps@msftsec.onmicrosoft.com`.

### Changing the VMs PowerShell Execution Policy
+ You'll have to change the PowerShell Execution Policy, otherwise you'll be prevented from invoking the script in Windows.
  - Navigate to Windows Settings, click on 'Update & Security'
  - On the left side towards the bottom, you'll see a 'For developers' tab
  - After clicking that, you should see a PowerShell header towards the bottom, click on the 'Apply' button.
  
![](/assets/images/devcode/powershell-global-bypass.png)

+ You're not done though, local user permissions will still be restricted, to fix this, do the following:
  - Run PowerShell as Administrator
  - Copy and paste this command in PowerShell: 
 
 ```powershell
 Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
 ```

### [AADInternals PowerShell Module Installation](https://o365blog.com/aadinternals/#installation)
We will be using the AADInternals PowerShell module to determine if the target uses Azure. AADInternals also has a Device Code phishing functionality, and the TokenTactics module is derived from the epic AADInternals project.
```powershell
# Install the module
Install-Module AADInternals
```
+ Now that the AADInternals module is installed, we can use `import-module` for a PowerShell session to get access to the AADInternals commands.
+ Just like all the PowerShell modules, we will need to import them into every new PowerShell session we want to use them in.

### [TokenTactics PowerShell Module Installation](https://o365blog.com/aadinternals/#installation)

+ Download or clone the [TokenTactics GitHub repository](https://github.com/rvrsh3ll/TokenTactics)

+ Ensure the TokenTactics folder is on the RTOs Window VMs file system.

```powershell
PS C:\Users\boku> cd .\TokenTactics
PS C:\Users\boku\TokenTactics> Import-Module .\TokenTactics.psd1
```

+ You will need to import TokenTactics when you want to use it within a PowerShell session.
+ Ignore the warning about the naming convention. We did not follow proper Microsoft PowerShell naming convention, so it throws a warning.

![](/assets/images/devcode/import-mod-warning.png)


### [AzureAD PowerShell Module Installation](https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0)
We will install the AzureAD PowerShell module for enumerating the targets AzureAD after acquiring a Refresh Token from the Device Code Phish campaign.

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
+ For the Azure Device Code Phishing Campaign we will be replacing the `<REPLACE-WITH-DEVCODE-FROM-TOKENTACTICS>` text with the device codes that are generated from the TokenTactics PowerShell module.
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
