# Introduction

### What is a persistency technique ?
Once an attacker detects a flaw in a system and wants to exploit it with a malware he has to write the program, infect the device and have it executed. One of the main difficulties to achieve such a mission is to enter the device. Different techniques can be used to do this, phishing being the most famous. To avoid doing this "infection phase" multiple times the attacker must ensure that the malware keeps running on the machine after a reboot or a logout/login sequence. He therefor implements specific techniques called "persistency techniques".

### What is a syscall trace ?
When a software, or in this case a malware,  is run on a device, it follows the instructions coded by the attacker and perform different tasks. Some of those actions require a high level of authorization and the program needs to ask the kernel of the operating system, we call such requests "system calls". It is possible to monitor them and keep a "trace" of it during the execution of the malware.

### What does this program do?
This program aims to detect persistency techniques from syscall traces of a malware that ran on a windows OS.

# How does it work ?

The syscall traces are saved in pickle files, I use a code from D.B. to load and parse them. Some of the most common persistency techniques are gathered in the MITRE ATT&CK® base.<br/>
I search in each trace if one of those technique is implemented.<br/>

# Techniques

`HKLM` stands for `HKEY_LOCAL_MACHINE` and `HKCU` for `HKEY_CURRENT_USER`.

## Account Manipulation
	
### ~~Additional Email Delegate Permissions~~
### <del>Device Registration</del>

## BITS Jobs
	
## Boot or Logon Autostart Execution
	
### Registry Run Keys / Startup Folder
### Authentication Package
### Time Providers
### Winlogon Helper DLL
### Security Support Provider
### LSASS Driver
### Shortcut Modification
### Port Monitors
### Print Processors
### Active Setup

## Boot or Logon Initialization Scripts
	
### Logon Script
### Network Logon Script

## Browser Extensions
	
## Compromise Client Software Binary
	
## Create Account
	
### Local Account
### Domain Account

## Create or Modify System Process
	
### Windows Service

## Event Triggered Execution
	
### Change Default File Association
### Screensaver
### Windows Management Instrumentation Event Subscription
### Netsh Helper DLL
### Accessibility Features
### AppCert DLLs
### AppInit DLLs
### Application Shimming
### Image File Execution Options Injection
### PowerShell Profile
### Component Object Model Hijacking

## External Remote Services
	
## Hijack Execution Flow
	
### DLL Search Order Hijacking
### DLL Side-Loading
### Executable Installer File Permissions Weakness
### Path Interception by PATH Environment Variable
### Path Interception by Search Order Hijacking
### Path Interception by Unquoted Path
### Services File Permissions Weakness
### Services Registry Permissions Weakness
### COR_PROFILER
### KernelCallbackTable

## Modify Authentication Process
	
### Domain Controller Authentication
### Password Filter DLL
### Reversible Encryption

## Office Application Startup
	
### Office Template Macros
### Office Test
### Outlook Forms
### Outlook Home Page
### Outlook Rules
### Add-ins

## Pre-OS Boot
	
### System Firmware
### Component Firmware
### Bootkit

## Scheduled Task/Job
	
### At
### Scheduled Task

## Server Software Component
	
### SQL Stored Procedures
### Transport Agent
### Web Shell
### IIS Components
### Terminal Services DLL

## Traffic Signaling
	
### Port Knocking

## Valid Accounts
	
### Default Accounts
### Domain Accounts
### Local Accounts




# Bibliography

*Article*<br/>
[Malware Persistence Mechanisms from Zane Gittinsa and Michael Soltysa](https://www.sciencedirect.com/science/article/pii/S1877050920318342)

*Web site*<br/>
[ATT&CK persistence tactics](https://attack.mitre.org/matrices/enterprise/windows/)<br/>
[Andrea Fortuna's blog](https://andreafortuna.org/2017/07/06/malware-persistence-techniques/)<br/>
[BlackBerry ThreatVector Blog](https://blogs.blackberry.com/en/2013/09/windows-registry-persistence-part-2-the-run-keys-and-search-order)

