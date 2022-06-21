# Introduction

Once a flaw is detected in a system and that an attacker wants to exploit it with a malware, he must create the program, infect a device with it and make it execute. On of the main difficulties to achieve such a mission is to enter the device, it can be made throught different technics such as phishing, downloading, insering a usb key etc... In order to keep the malware working on the machine after a reboot or a logout/login and avoid doing the "infection" again the attacker need to implement "persistence technics".

When a software or, here, a malware is executed on a device, it follows the instructions coded and make different actions on the machine. For a some actions the program need to request a service from the kernel of the operating system, we call such actions "system calls". It is possible to monitor them and keep a "trace" of it during the execution of the malware.

This program aims to detect persistence technics from syscall traces of a malware that ran on a windows OS.

*I used those three websites :*<br/>
[ATT&CK persistence tactics](https://attack.mitre.org/matrices/enterprise/windows/)<br/>
[Andrea Fortuna's blog](https://andreafortuna.org/2017/07/06/malware-persistence-techniques/)<br/>
[BlackBerry ThreatVector Blog](https://blogs.blackberry.com/en/2013/09/windows-registry-persistence-part-2-the-run-keys-and-search-order)

# How it work



# Techniques

## BootExecute

## Services

## Run Services