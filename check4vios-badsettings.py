#!/usr/bin/python -tt

# -*- coding: utf-8 -*-
# vim:expandtab:ts=4:sw=4:ai:number

"""
   Check the VIOS disk scsi reservations settings, and fix if required.
"""

from __future__ import print_function

__author__     = "Steve Maher"
__copyright__  = ""
__credits__    = ["Steve Maher"]
__license__    = ""
__version__    = "1.0.1"
__maintainer__ = "Steve Maher"
__email__      = "steve@m4her.com"
__status__     = "Production"

import os
import sys
import subprocess
import yaml
import argparse
import platform

from nimlib import str2bool,error_message,check_output,nim_object_exists,nim_attribute,lsnim_t,nimquery_all_vios,nimquery_vios,nimquery,ssh_check_output,ssh_agent_check,ssh_command,ssh_options,ssh_output,log,getodm,getodmSSH,getvhostmapping,changeAttributeSSH

def getActivePVs(lpar):
    data = {}
    output = ssh_output(lpar, "/usr/sbin/lsvg -o \| /usr/sbin/lsvg -p -i" )

    for line in output:
        log("getActivePVs: line = %s" % line )

        if ":" in line[-1]:
            vgName=line.split(":")[0]

        if "hdisk" in line:
            data[line.split()[0]]=vgName

    return data

def checkVIOSdisks(vios):

    """ AIX is a bit of a pig when it comes to PCM path attributes, 
        it does not store unless changes, so you have to pick up 
        the default settings unlike most ODM entries that are fixed. 
        This code assumes you are using the EMC clarrion driver.
    """

    isOK = ssh_output(vios,"echo OK")

    if isOK == None or isOK == False:
        error_message("Unable to communicate with %s, host not responding." % vios )
        return None

    """Default settings for reserve_policy for all drivers installed"""
    driverDefaults = {}     
    """The driver each dis(ck) uses"""
    discPathDriver = {}     
    """Current reservation policy for a dis(ck) if defined"""
    discResPolicy  = {}     
    """absolute list of dis(ck)s we are interested in and their uuid"""
    discUniqueID   = {}     
    """if the disks is mapped to a lpar this is the device is mapped to"""
    vhostMapping   = {}     
    """list of active disks on the vios that we need to ignore"""
    activePVs      = {}     

    activePVs      = getActivePVs(vios)
    vhostMapping   = getvhostmapping(vios)
    driverDefaults = getodmSSH(vios,"PdAt","attribute=reserve_policy","uniquetype","deflt")
    discPathDriver = getodmSSH(vios,"CuDv","PdDvLn like disk/*","name","PdDvLn")
    discResPolicy  = getodmSSH(vios,"CuAt","name like hdisk* and attribute=reserve_policy","name","value")
    discUniqueID   = getodmSSH(vios,"CuAt","name like hdisk* and attribute=unique_id","name","value")

    for disk in discUniqueID:
        """ Ignore disk if its used in the VIO """

        if activePVs.get(disk):
            continue

        """ Get the policy for the disk, if its not set then
            we take the default for the PCM module """
        policy = discResPolicy.get( disk ) 

        if policy == None:
           PathDriver = discPathDriver.get( disk )
           policy = driverDefaults.get( PathDriver )

        log("checkVIOSdisks: %16s %20s %15s  " % ( vios, disk, policy ) )

        if "no_reserve" not in policy:
            if vhostMapping.get(disk) is not None:
                print( "[E] %-16s %20s %15s disk is mapped to %s " % ( vios, disk, policy, vhostMapping.get(disk) ) )
            else:
                print( "[E] %-16s %20s %15s  " % ( vios, disk, policy ) )

            if FIX:
                if changeAttributeSSH(vios, disk, "reserve_policy", "no_reserve"):
                    print("[I] changed.")
                else:
                    if vhostMapping.get(disk) is not None:
                        print( "[E] %-16s %20s %15s disk in use - failed to update disk attributes." % ( vios, disk, policy ) )
                    else:
                        print( "[E] %-16s %20s %15s failed to update disk attributes." % ( vios, disk, policy ) )
                
                    response = raw_input("[P] continue?")

                    if "n" in response.lower():
                        exit(1)


if __name__ == "__main__":

    myNodeName = platform.node()

    parser = argparse.ArgumentParser( description = 'Check VIOS disk  settings are correct ', add_help = "False", usage = '%(prog)s [options]')
    parser.add_argument('-n', required = False, metavar = 'VIOS-NAME', type = str, help='Target VIOS,VIOS,VIOS....')
    parser.add_argument('-m', required = False, metavar = 'CEC-NAME', type = str, help='Target Management Server')
    parser.add_argument('-a', required = False, type = str2bool, nargs='?', const=True, default=False, help='Find all VIOS')
    parser.add_argument('-f', required = False, type = str2bool, nargs='?', const=True, default=False, help='Attempt to fix.')
    parser.add_argument('-v', required = False, type = str2bool, nargs='?', const=True, default=False, help='Verbose logging')

    try:
        parser.error = parser.exit
        args = parser.parse_args()

    except SystemExit:
        parser.print_help()
        exit(2)

    if not args.m and not args.a and not args.n:
        parser.print_help()
        exit(0)

    VERBOSE = str2bool( os.environ.get("VERBOSE","") ) or args.v
    FIX     = str2bool( os.environ.get("FIX","") ) or args.f

    if ssh_agent_check() == False:
        error_message( "ssh-agent or forwarded-agent is not activated, have you loaded the SSH keys ??" )
        exit(1)

    if args.m or args.a:
        if args.m:
            print("[I] Searching for vios")
            for cec in str(args.m).split(","):
                log("__main__: searching %s" % cec )
                cecs = nimquery_vios(cec)

        if args.a:
            print("[I] Searching for all available vios")
            cecs = nimquery_all_vios()

        for cec in cecs:
            print( "[I] CEC: %s VIOS: %s" % (cec, cecs[cec] ) )

            for lpar in cecs[cec].split():
                checkVIOSdisks(lpar)

    if args.n:
        for lpar_name in str(args.n).split(","):
            log("arg target: %s" % lpar_name )

            checkVIOSdisks( str(lpar_name) )
