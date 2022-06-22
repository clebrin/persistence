# Introduction

### What is a persistency techniques ?
Once a flaw is detected in a system and that an attacker wants to exploit it with a malware, he must create the program, infect a device with it and make it execute. On of the main difficulties to achieve such a mission is to enter the device, it can be made throught different technics such as phishing, downloading a malicious file, insering a usb key etc... In order to keep the malware working on the machine after a reboot or a logout/login and avoid doing the "infection phase" again the attacker needs to implement technics that wake the malware up on at a certain point: the persistency techniques.

### What is a syscall trace ?
When a software or, here, a malware is executed on a device, it follows the instructions coded by the attacker and make different actions on the machine. For a some actions the program need to request a service from the kernel of the operating system, we call such actions "system calls". It is possible to monitor them and keep a "trace" of it during the execution of the malware.

### What does this program ?
This program aims to detect persistency techniques from syscall traces of a malware that ran on a windows OS.

# How it works ?

The syscall traces are saved in pickle files, I use a code from D.B. to load and parse them. Some of the most common persistency techniques are gathered in the MITRE ATT&CK® base and other blogs describe the link between the techniques and the specific registry keys in windows.<br/>
I search in each trace if one of those keys have been modified.<br/>
Above is a list of techniques I detect and there link with the registry keys.

# Techniques

*`HKLM` stands for `HKEY_LOCAL_MACHINE` and `HKCU` for `HKEY_CURRENT_USER`. I present the vulnerabilities in order of occurence in the boot sequence.*

## BootExecute

The very first program executed when rebooting a windows machine is the `autocheck autochk *` sequence located in the registry `HKLM\System\CurrentControlSet\Control\Session Manager`. It check the integrity of the file-system, if a program is added to this value it will be executed a boot time.

## Services

When the startup sequence starts, the system look for the needed drivers and this list is located in `HKLM\System\CurrentControlSet\Services`. This is the famous progress bar under the "Starting Windows..." but if one places his malicious software in the list, it will be executed at that time !

## Run Services

It then need to know where those needed drivers are located and this is store in the registries above : <br/>
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Services\Once`<br/>
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Services`

## WinLogon

This is the part where logons are logoffs are handled. This process handles the Secure Attention Sequence (SAS)

# Bibliography

[ATT&CK persistence tactics](https://attack.mitre.org/matrices/enterprise/windows/)<br/>
[Andrea Fortuna's blog](https://andreafortuna.org/2017/07/06/malware-persistence-techniques/)<br/>
[BlackBerry ThreatVector Blog](https://blogs.blackberry.com/en/2013/09/windows-registry-persistence-part-2-the-run-keys-and-search-order)

