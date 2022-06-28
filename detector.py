#! python3

import os
import operator
import pickle
import sys
from pathlib import PureWindowsPath
from os.path import isdir, abspath, join, basename, exists, isfile
from typing import List, Dict, Optional, Set
from collections import defaultdict

from classes import DynAnal


def extract_features(report: DynAnal) -> list:
    out = list()
    for event in report.orderedEvents:
        t = event['Type']
        if t.startswith('BE'):
            category = event['Cat']
            symbol = event['Sym']
            arg = None
            if t.endswith('wA'):
                arg = event['Arg']
                if arg is not None:
                    if arg.startswith('\\??'):
                        arg = arg[4:]
                    elif arg.startswith('\\Dev'):
                        arg = arg.replace('\\Device\\HarddiskVolume2', 'C:')
                    arg = arg.lower()
                    arg = arg.replace('guannapenna', 'slasti')  # replace old user
                    if category in ['FILESYSTEM', 'PROCESS']:
                        try:
                            pwp = PureWindowsPath(arg)
                            arg = str(pwp).replace(pwp.stem, '')  # remove filename  but keep extension
                        except:
                            pass
                    elif category == 'NETWORK':
                        if ':' in arg:
                            arg = arg.split(':')[1]
                    elif category == 'MUTEX':
                        arg = ''  # mutex argument is useless
                    elif category == 'REGISTRY':
                        pass
                    elif category == 'SERVICE':
                        if 'name=' in arg:
                            arg = arg.split('=')[1]
                        else:
                            arg = ''
                    else:
                        #print(f'{category}|{symbol}|{arg}')
                        pass
                    arg = arg.replace(' ', '')
            if arg is None or arg == '':
                feat = f'{symbol}'
            else:
                feat = f'{symbol}|{arg}'
            out.append(feat)
        elif t == 'EVA':
            category = event['Cat']
            title = event['Title']
            #print(category, title)  # <- evasive features, in case needed
    return out


def is_empty(file_path: str) -> bool:
    try:
        return os.path.getsize(file_path) <= 0
    except OSError:
        return False


# *************************
# * My detection function *
# *************************

def detection(api_name, arg):

    # api for key value modification/creation
    set_value = ["ntsetvaluekey", "zwsetvaluekey"]
    create_value = ["ntcreatevaluekey", "zwcreatevaluekey"]

    # str(None) to avoid exceptions
    if arg is None:
        arg = ""

    # lower the string to avoid case conflit
    api_name = api_name.lower()
    arg = arg.lower()

    # detect the level of priviledge of the potential attack/key modification
    level = ""
    if arg.startswith("\\registry\\machine"):
        level += "System-level "
    elif arg.startswith("\\registry\\user") : 
        level += "User-level "


    # ******************************************
    # * List of techniques from MITRE database *
    # ******************************************


    ######## Account Manipulation 
    #### Additional Email Delegate Permissions
    #### Device Registration

    ######## BITS Jobs

    ######## Boot or Logon Autostart Execution
    #### Registry Run Keys / Startup Folder
    ## BootExecute
    if api_name in set_value and (arg.endswith("\\controlset001\\control\\sessionmanager\\bootexecute") or arg.endswith("\\controlset002\\control\\sessionmanager\\bootexecute") or arg.endswith("\\controlset003\\control\\sessionmanager\\bootexecute")):
        return "BootExecute"
    ## Run Services
    elif api_name in set_value and (arg.endswith("microsoft\\windows\\currentversion\\runservices") or arg.endswith("microsoft\\windows\\currentversion\\runservicesonce")):
        return "Run Services"
    ## Run
    elif api_name in set_value and (arg.endswith("\\microsoft\\windows\\currentversion\\runonce") or arg.endswith("\\microsoft\\windows\\currentversion\\run")):
        return level + "Run"
    ## Shell Folder
    elif api_name in set_value and (arg.endswith("microsoft\\windows\\currentversion\\explorer\\usershellfolders") or arg.endswith("microsoft\\windows\\currentversion\\explorer\\shellfolders") ):
        return level + "Shell Folder"
    #### Authentication Package
    elif api_name in set_value and ("\\controlset001\\control\\lsa" in arg or "\\controlset002\\control\\lsa" in arg or "\\controlset003\\control\\lsa" in arg):
        return "Authentication Package"
    #### Time Providers
    #### Winlogon Helper DLL
    ## WinLogon Userinit
    elif api_name in set_value and arg.endswith("microsoft\\windowsnt\\currentversion\\winlogon\\userinit"):
        return "WinLogon Userinit"
    ## WinLogon Notify
    elif api_name in set_value and arg.endswith("microsoft\\windowsnt\\currentversion\\winlogon\\notify\\wlogon"):
        return "WinLogon Notify"
    #### Security Support Provider
    #### LSASS Driver
    #### Shortcut Modification
    #### Port Monitors
    #### Print Processors
    #### Active Setup

    ######## Boot or Logon Initialization Scripts
    #### Logon Script
    #### Network Logon Script

    ######## Browser Extensions

    ######## Compromise Client Software Binary

    ######## Create Account
    #### Local Account
    #### Domain Account

    ######## Create or Modify System Process
    #### Windows Service
    elif api_name in set_value and ("\\controlset001\\services" in arg or "\\controlset002\\services" in arg or "\\controlset003\\services" in arg):
        return "Services"

    ######## Event Triggered Execution
    #### Change Default File Association
    #### Screensaver
    #### Windows Management Instrumentation Event Subscription
    #### Netsh Helper DLL
    #### Accessibility Features
    #### AppCert DLLs
    #### AppInit DLLs
    elif api_name in set_value and arg.endswith("\\microsoft\\windowsnt\\currentversion\\windows"):
        return "AppInit"
    #### Application Shimming
    #### Image File Execution Options Injection
    #### PowerShell Profile
    #### Component Object Model Hijacking

    ######## External Remote Services

    ######## Hijack Execution Flow
    #### DLL Search Order Hijacking
    #### DLL Side-Loading
    #### Executable Installer File Permissions Weakness
    #### Path Interception by PATH Environment Variable
    #### Path Interception by Search Order Hijacking
    #### Path Interception by Unquoted Path
    #### Services File Permissions Weakness
    #### Services Registry Permissions Weakness
    #### COR_PROFILER
    #### KernelCallbackTable

    ######## Modify Authentication Process
    #### Domain Controller Authentication
    #### Password Filter DLL
    #### Reversible Encryption

    ######## Office Application Startup
    #### Office Template Macros
    elif api_name in set_value and arg.endswith("outlook\\customforms\\compose"):
        return "Office Template Macros"
    #### Office Test
    elif api_name in create_value and arg.endswith("software\\microsoft\\officetest\\special\\perf"):
        return " Office Test"
    #### Outlook Forms
    #### Outlook Home Page
    #### Outlook Rules
    #### Add-ins

    ######## Pre-OS Boot
    #### System Firmware
    #### Component Firmware
    #### Bootkit

    ######## Scheduled Task/Job
    #### At
    #### Scheduled Task

    ######## Server Software Component
    #### SQL Stored Procedures
    #### Transport Agent
    #### Web Shell
    #### IIS Components
    #### Terminal Services DLL

    ######## Traffic Signaling
    #### Port Knocking

    ######## Valid Accounts
    #### Default Accounts
    #### Domain Accounts
    #### Local Accounts

    # if no attack found
    return ""






if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {basename(__file__)} PICKLES_FOLDER')
    pickles_folder = sys.argv[1]
    assert isdir(pickles_folder)

    files = os.listdir(pickles_folder)
    print(f'Found #{len(files)} files')
    i = 0
    for filename in files:
        if filename.endswith('.pickle'):
            i += 1
            sha256 = filename[:-7]
            assert len(sha256) == 64
            fpath = join(pickles_folder, filename)
            assert not is_empty(fpath)
            with open(fpath, "rb") as fp:

                # list to store techniques on one file
                techniques = []

                da: DynAnal = pickle.load(fp)
                features_list: List = extract_features(da)
                for feat in features_list:
                    api_name = None
                    arg = None
                    if '|' in feat:
                        spt = feat.split('|')
                        api_name = spt[0]
                        arg = spt[1]
                    else:
                        api_name = feat
                    

                    # **************
                    # * My analyse *
                    # **************

                    tech = detection(api_name, arg)
                    if tech:
                        techniques.append(tech)

                # remove duplicates attacks
                techniques = list(set(techniques))

                # if at least one attack is detected
                if len(techniques) > 0:
                    print("Persistence technique detected in file {} :".format(filename))
                    for technique in techniques[:-1]:
                        print("{}".format(technique), end=" || ")
                    print("{}".format(techniques[-1]))
                    print("-------------------------------------------------------------\n")
