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

    set_value = ["ntsetvaluekey", "zwsetvaluekey"]

    #print(api_name, arg, sep='\t')

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


    # program executed during boot, normaly autocheck autochk *
    if api_name in set_value and (arg.endswith("\\controlset001\\control\\sessionmanager\\bootexecute") or arg.endswith("\\controlset002\\control\\sessionmanager\\bootexecute") or arg.endswith("\\controlset003\\control\\sessionmanager\\bootexecute")):
        return "BootExecute"

    # list of driver to be loaded
    if api_name in set_value and ("\\controlset001\\services" in arg or "\\controlset002\\services" in arg or "\\controlset003\\services" in arg):
        return "Services"

    # location of drivers
    elif api_name in set_value and (arg.endswith("microsoft\\windows\\currentversion\\runservices") or arg.endswith("microsoft\\windows\\currentversion\\runservicesonce")):
        return "Run Services"

    # logon
    elif api_name in set_value and arg.endswith("microsoft\\windowsnt\\currentversion\\winlogon\\userinit"):
        return "WinLogon Userinit"
    elif api_name in set_value and arg.endswith("microsoft\\windowsnt\\currentversion\\winlogon\\notify\\wlogon"):
        return "WinLogon Notify"


    # Run key attack
    if api_name in set_value and (arg.endswith("\\microsoft\\windows\\currentversion\\runonce") or arg.endswith("\\microsoft\\windows\\currentversion\\run")):
        return level + "Run"

    

    
    # Run key attack
    elif api_name in set_value and arg.endswith("\\microsoft\\windows\\currentversion\\policies\\explorer\\run"):
        return level + "Run Explorer"

    elif api_name in set_value and arg.endswith("\\microsoft\\windowsnt\\currentversion\\windows"):
        return level + "AppInit"

    

    elif api_name in set_value and arg.endswith("microsoft\\windows\\currentversion\\explorer\\usershellfolders"):
        return level + "Startup Keys User"

    elif api_name in set_value and arg.endswith("microsoft\\windows\\currentversion\\explorer\\shellfolders"):
        return level + "Startup Keys Machine"

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

                attacks = []

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

                    attack = detection(api_name, arg)
                    if attack:
                        attacks.append(attack)

                # remove duplicates attacks
                attacks = list(set(attacks))

                # if at least one attack is detected
                if len(attacks) > 0:
                    print("Persistence technique detected in file {} :".format(filename))
                    for attack in attacks[:-1]:
                        print("{}".format(attack), end=" || ")
                    print("{}".format(attacks[-1]))
                    print("-------------------------------------------------------------\n")
