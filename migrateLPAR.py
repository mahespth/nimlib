#!/usr/bin/python -tt

# -*- coding: utf-8 -*-
# vim:expandtab:ts=4:sw=4:ai:number

"""Move LPARs definitions between CECs

    1.  Find lpar 
    2.  get lpar definition for currently booted lpar
    3.  create new definition on target 
    4.  define storage on target
    5.  commands to manually power off the source
    6.  commands to main boot the target
"""

from __future__ import print_function

__author__ = "Steve Maher"
__copyright__ = ""
__credits__ = ["Steve Maher"]
__license__ = ""
__version__ = "1.0.1"
__maintainer__ = "Steve Maher"
__email__ = "steve@m4her.com"
__status__ = "Production"

import os
import sys
import subprocess
import yaml
import argparse


def runcmd(raiseresult,command):
    """ Run shell commands and handle result """

    try:
        log("Running: "+command)
        os.system(command)
        return True

    except:
        if raiseresult == True:
            raise
        else:
            return False

def log(message):
    """ If debug is set then lets debug """
    if DEBUG:
       print ("debug: %s" % message)

def error_message(message):
    print ("[E] %s" % message, file=sys.stderr)
    return


def yaml_loader(filepath):
    """Loads the yaml data"""
    with open(filepath, 'r') as stream:
      try:
          data = yaml.load(stream)
          stream.close()
      except yaml.YAMLError as exc:
          print("[E] Error in your yaml file: %s" % filepath)
          print(exc)

    return data

def merged(x, y):
    """ Merge the two objects. We want to ensure defaults are used """
    z=x.copy()
    z.update(y)
    return z


def nim_object_exists(object,type):
    """ find an object, alternative if the object """

    log("nim_object_exists: %s" % object)

    if len(type):
        try:
            output = subprocess.check_output(["/usr/sbin/lsnim", "-t", type]).splitlines()

        except:
            return False

        for line in output:
            if object == line.split(" ")[0]:
                return True

    else:
        try:
            output = subprocess.check_output(["/usr/sbin/lsnim", object]).splitlines()

        except:
            return None

    return False


def locate_hmc(nimname):
    """ find hmc for node
        example output:
                [hostname:root:/home/root:] lsnim -Za mgmt_profile somehost
                #name:mgmt_profile:
                somehost:hmcname 29 cecname-and-serial:
    """

    log("locate_hmc: %s" % nimname)

    try:
        output = subprocess.check_output(["/usr/sbin/lsnim","-Za","mgmt_profile", nimname]).splitlines()

        if len(output) == 0:
            return None,None

    except:
        return None,None

    for line in output:
        log("subprocess-line %s" % line)

        if "#" not in line:
            return line.split(":")[1].split(" ")[0],line.split(":")[1].split(" ")[2]

    return

def process_lssyscfg_output(input):
    index = 0
    last_index=0
    output = []
    output_dict = { }

    while index < len(input):
        #log("index = %s" % index )

        index = input.find(",",index)
        
        if index == -1:
            index=len(input)

        if "\"" in input[last_index]:
            #log("found first quote")
            last_index+=1

            # if string.find('""', then end is string.find('"""') else end is string.find('"')
            while True:
                index = input.find("\"",(index+1))

                if "\"" in input[(index+1)]:
                    index+=2
                    if "\"" in input[index]:
                        #log("end of quoted quote section.. phew")
                        line = input[last_index:(index)]
                        break

                else:
                    line = input[last_index:(index)]

                    index+=1
                    break
        else:
            line = input[last_index:(index)]

        eq_location=line.find("=",0)
        output_dict[line[0:eq_location]]=line[(eq_location+1):len(line)]

        log("added %s %s" % ( line[0:eq_location], line[(eq_location+1):len(line)] ) )

        index+=1
        last_index=index

    log("process_lssuscfg_output: Returning data size=%d" % len(output_dict) )

    return output_dict


def require_lpar_settings():
    return {
        "lpar_name": "",
        }

def ignore_lpar_settings():

    return {
        "virtual_serial_adapters": "1",
        "electronic_err_reporting": "1",
        "lhea_lgical_ports": "1",
        "lpar_id": "1",
        "lhea_capabilities": "1",
        "power_ctrl_lpar_ids": "1",
        "auto_start": "1",
        "bsr_arrays": "1",
        "hpt_ratio": "1",
        "boot_mode": "norm",
        "redundant_err_path_reporting": "0",
        "conn_monitoring": "0",
        }

def default_lpar_settings():

    return {
        "max_virtual_slots": "20",
        "name": "normal",
        "shared_proc_pool_id": "0",
        "shared_proc_pool_name": "Oracle_Pool_01",
        "min_procs": "1",
        "desired_procs": "1",
        "max_procs": "1",
        "lpar_env": "aixlinux",
        "sharing_mode": "uncap",
        "mem_mode": "ded",
        "uncap_weight": "128",
        "min_proc_units": "0.1",
        "desired_proc_units": "0.2",
        "max_proc_units": "1.0",
        "min_mem": "1024",
        "desired_mem": "2048",
        "max_mem": "4096",
        "proc_mode": "shared",
        "all_resources": "0",
        "min_num_huge_pages": "0",
        "desired_num_huge_pages": "0",
        "max_num_huge_pages": "0",
        "lpar_io_pool_ids": "none",
        "work_group_id": "none",
        "lpar_proc_compat_mode": "default",
        }

def migratable_lpar_settings():
    # slot-DRC-index/[slot-IO-pool-ID]/ 

    return {
            "virtual_scsi_adapters": "new-vscsi-adapters",
            "virtual_eth_adapters": "new-eth-adapters",
            "io_slots": "new-io-slots",
            #hca_adapters none
            #virtual_fc_adapters none
            }

def new_eth_adapters(input):
    # We need to find the VLANS from this data
    # example: input:
    # 2/0/64//0/0/ETHERNET0//all/none,3/0/804//0/0/ETHERNET0//all/none
    vlans = ""

    for slot in input.split(","):
        fields=slot.split("/")
        vlans+=( "%s_%s," % ( fields[2], fields[6] ) )
        
    vlans=vlans[0:-1]

    return vlans

def new_ios_slots(input):
    # System has physical slots allocated - someone will need to manually match these on the other side !?
    
    return

def new_vscsi_adapters(input):
    # New scsi adapter - we need to find what is presented
    # and move this over ?
    return


def mv_lpar_definition(lpar,target):
    log("mv of %s" % lpar)

    hmc,cec = locate_hmc(lpar)

    if hmc is None:
        error_message("Could not find lpar %s, skipping." % lpar)
        return

    default_profile = hmc_cli( lpar,( "lssyscfg -r lpar -m %s --filter lpar_names=%s -F default_profile" % (cec, lpar ) ) )

    log("default-profile: %s" % default_profile[0])

    profile_config = hmc_cli ( lpar,( "lssyscfg -r prof -m %s --filter lpar_names=%s,profile_names=%s" % (cec, lpar, default_profile[0] ) ) )

    out = process_lssyscfg_output(profile_config[0])
    
    log( "profile-data: %s\n" % profile_config[0] )

    white_flag_attributes=migratable_lpar_settings()
    ignore_lpar_attributes=ignore_lpar_settings()

    # Build a new command 
    ############################################################
    settings=""
    vlans=""

    for item,value in out.items():
        if len(item) == 0 :
            continue

        log( "item: %s == %s" % (item,value) )

        if ignore_lpar_attributes.get(item):
            log( "ignoring item %s" % item )
            continue

        reparse_function = white_flag_attributes.get(item)

        if reparse_function and value != "none":
            log( "Validating with %s" % reparse_function )

            if "new-vscsi-adapters" in reparse_function:
                newjunk = new_vscsi_adapters(value)

            elif "new-eth-adapters" in reparse_function:
                vlans = new_eth_adapters(value)

            elif "new-io-slots" in reparse_function:
                newjunk = new_ios_slots(value)

            else:
                error_message(" Unknown type of attribute, I dont know what to do with it...stopping.")
                exit(1)

        if "\"" in value:
            settings+=("%s=\"%s\"," % ( item, value ) )

        else:
            settings+=("%s=%s," % ( item, value ) )

    if "," in settings[-1]:
        settings=settings[0:-1]

    command="mksyscfg -r lpar -m -i lpar_name=%s," % lpar
    print("%s%s" % ( command, settings ) )
    if vlans:
        print("VLANS: %s" % vlans )




def hmcSSH(hmcname,hmcuser):
    return ( "/usr/bin/ssh -nq -l %s %s" % ( hmcuser, hmcname) )

def hmc_user():
    return "hscroot"

def hmc_cli(lpar,command):
    hmc,cec = locate_hmc(lpar)
    hmcCMD = hmcSSH(hmc,hmc_user())

    log("hmc-command: %s %s" % (hmcCMD, command ) )

    try:
        return subprocess.check_output("%s %s" % ( hmcCMD, command ) ,shell=True).splitlines()

    except:
        raise
        return 

def vlan2vlan(sourceVLAN,destVLAN):
    """ Update the VLAN during the migration """


if __name__ == "__main__":
    try:
        DEBUG = os.environ["DEBUG"]

        if "False" in DEBUG:
            DEBUG=False

    except:
        DEBUG = False

    parser = argparse.ArgumentParser( description = 'Migrate LPAR from disperate systems', add_help = "False", usage = 'migratelpar -t cec -s lpar,lpar')
    parser.add_argument('-t', required = True, metavar = 'CEC-NAME', type = str, help='Target CEC defined as a NIM object')
    parser.add_argument('-s', required = True, metavar = 'LPAR[,LPAR]', type = str, help='LPAR list')
    parser.add_argument('-d', required = False, type = int, help='debug')

    try:
        parser.error = parser.exit
        args = parser.parse_args()

    except SystemExit:
        parser.print_help()
        exit(2)

    if args.d:
        DEBUG = True

    if not nim_object_exists(args.t,"cec"):
        error_message("Could not locate CEC %s, stopping." % args.t)
        exit(1)
        
    for lpar_name in str(args.s).split(","):
        log("arg target: %s" % lpar_name )

        if nim_object_exists(lpar_name,"standalone"):

            mv_lpar_definition( str(lpar_name), str(args.t) )
        else:
            error_message("Could not locate LPAR %s")


