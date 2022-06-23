- [Introduction](#introduction)
	- [What is a persistency technique ?](#what-is-a-persistency-technique)
	- [What is a syscall trace ?](#what-is-a-syscall-trace)
	- [What does this program do ?](#what-does-this-program-do)
- [How does it work ?](#how-does-it-work)


# Introduction

## What is a persistency technique ?
Once an attacker detects a flaw in a system and wants to exploit it with a malware he has to write the program, infect the device and have it executed. One of the main difficulties to achieve such a mission is to enter the device. Different techniques can be used to do this, phishing being the most famous. To avoid doing this "infection phase" multiple times the attacker must ensure that the malware keeps running on the machine after a reboot or a logout/login sequence. He therefor implements specific techniques called "persistency techniques".

## What is a syscall trace ?
When a software, or in this case a malware,  is run on a device, it follows the instructions coded by the attacker and perform different tasks. Some of those actions require a high level of authorization and the program needs to ask the kernel of the operating system, we call such requests "system calls". It is possible to monitor them and keep a "trace" of it during the execution of the malware.

## What does this program do ?
This program aims to detect persistency techniques from syscall traces of a malware that ran on a windows OS.

# How does it work ?

The syscall traces are saved in pickle files, I use a code from D.B. to load and parse them. Some of the most common persistency techniques are gathered in the MITRE ATT&CK® base.<br/>
I search in each trace if one of those technique is implemented.<br/>

# Techniques

`HKLM` stands for `HKEY_LOCAL_MACHINE` and `HKCU` for `HKEY_CURRENT_USER`.<br/>
I crossed out the techniques I can't detect yet.

## Account Manipulation
	
### ~~Additional Email Delegate Permissions~~
### ~~Device Registration~~

## BITS Jobs
	
## Boot or Logon Autostart Execution
	
### Registry Run Keys / Startup Folder

#### BootExecute

The very first program executed when rebooting a windows machine is the autocheck autochk * sequence located in the registry `HKLM\System\CurrentControlSet\Control\SessionManager`. It check the integrity of the file-system, if a program is added to this value it will be executed a boot time.

#### Run Services

The system needs to know where the drivers are located and this is store in the registries above :<br/>
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Services\Once`<br/>
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Services`

#### Run

This is probably the most commom persistency technique because those are the list of file with AutoStart Extension Points(ASEP) meaning that they will be launch automatically. If their exploit fails to obtain NT AUTHORITY\SYSTEM or administrator-level rights they can always create a key under the "user" run keys and persist their access.<br/>
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`<br/>
`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`<br/>
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`<br/>
`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

#### Shell Folder

The following Registry keys can be used to set startup folder items for persistence:
`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserShell Folders`<br/>
`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders`<br/>
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders`<br/>
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders`

### Authentication Package

An attacker could use the autostart mechanism provided by LSA authentication packages (in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\`). The binary will then be executed by the system when the authentication packages are loaded.

### Time Providers

Time providers are registered in `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\`, an attacker could place a malicious DLL here because service control manager loads and starts time providers listed at system startup.

### Winlogon Helper DLL

#### WinLogon Userinit

This is the part where logons are logoffs are handled, normally it points to userinit.exe but if this key can be altered, then that exe will also launch by Winlogon.<br/>
`HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon`

#### WinLogon Notify

This process handles the Secure Attention Sequence (SAS) and the WinLogon Notify value is used to notify event handles when SAS happens and loads a process, if the attacker can choose the process list, it can launch his malware.<br/>
`HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon\Notify`

### ~~Security Support Provider~~
### ~~LSASS Driver~~
### ~~Shortcut Modification~~
### ~~Port Monitors~~
### ~~Print Processors~~
### ~~Active Setup~~

## Boot or Logon Initialization Scripts
	
### ~~Logon Script~~
### ~~Network Logon Script~~

## Browser Extensions
	
## Compromise Client Software Binary
	
## Create Account
	
### ~~Local Account~~
### ~~Domain Account~~

## Create or Modify System Process
	
### ~~Windows Service~~

## Event Triggered Execution
	
### ~~Change Default File Association~~
### ~~Screensaver~~
### ~~Windows Management Instrumentation Event Subscription~~
### ~~Netsh Helper DLL~~
### ~~Accessibility Features~~
### ~~AppCert DLLs~~
### AppInit DLLs

As most executables load User32.dll and `HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Windows\AppInit_DLLs` show the DLLs loaded by the User32.dll so it is a good idea to keep an eye on this.

### ~~Application Shimming~~
### ~~Image File Execution Options Injection~~
### ~~PowerShell Profile~~
### ~~Component Object Model Hijacking~~

## External Remote Services
	
## Hijack Execution Flow
	
### ~~DLL Search Order Hijacking~~
### ~~DLL Side-Loading~~
### ~~Executable Installer File Permissions Weakness~~
### ~~Path Interception by PATH Environment Variable~~
### ~~Path Interception by Search Order Hijacking~~
### ~~Path Interception by Unquoted Path~~
### ~~Services File Permissions Weakness~~
### ~~Services Registry Permissions Weakness~~
### ~~COR_PROFILER~~
### ~~KernelCallbackTable~~

## Modify Authentication Process
	
### ~~Domain Controller Authentication~~
### ~~Password Filter DLL~~
### ~~Reversible Encryption~~

## Office Application Startup
	
### ~~Office Template Macros~~
### ~~Office Test~~
### ~~Outlook Forms~~
### ~~Outlook Home Page~~
### ~~Outlook Rules~~
### ~~Add-ins~~

## Pre-OS Boot
	
### ~~System Firmware~~
### ~~Component Firmware~~
### ~~Bootkit~~

## Scheduled Task/Job
	
### ~~At~~
### ~~Scheduled Task~~

## Server Software Component
	
### ~~SQL Stored Procedures~~
### ~~Transport Agent~~
### ~~Web Shell~~
### ~~IIS Components~~
### ~~Terminal Services DLL~~

## Traffic Signaling
	
### ~~Port Knocking~~

## Valid Accounts
	
### ~~Default Accounts~~
### ~~Domain Accounts~~
### ~~Local Accounts~~




# Bibliography

*Article*<br/>
[Malware Persistence Mechanisms from Zane Gittinsa and Michael Soltysa](https://www.sciencedirect.com/science/article/pii/S1877050920318342)

*Web site*<br/>
[ATT&CK persistence tactics](https://attack.mitre.org/matrices/enterprise/windows/)<br/>
[Andrea Fortuna's blog](https://andreafortuna.org/2017/07/06/malware-persistence-techniques/)<br/>
[BlackBerry ThreatVector Blog](https://blogs.blackberry.com/en/2013/09/windows-registry-persistence-part-2-the-run-keys-and-search-order)

