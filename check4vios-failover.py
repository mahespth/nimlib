#!/usr/bin/python -tt

# -*- coding: utf-8 -*-
# vim:expandtab:ts=4:sw=4:ai:number

"""Check that the VIOS/LPARS connected are in a fit state so the VIOS can be rebooted.

    1.  Get CEC associated with VIO
    2.  Get other hosts managed on that CEC (nimquey not nimobjects...)
    3.  Check we can get to the nodes and get the path data.
    4.  
    5.  
    6.  
"""

from __future__ import print_function
from nimlib import *

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
import platform
import logging


def get_vscsi_2_vhost(lpar):
    """
       Get the virtual scsi mappings
       :returns:dict[viosname]="devices..."
    """
    log("get_vcsi_2_vhost:")

    data = {}

    output = ssh_output(lpar,"\"echo cvai | kdb\"")

    if output is None or output is False:
        return None

    for line in output:

        logging.debug( "get_vscsi_2_vhost: line: %s" % line )

        if line.startswith("vscsi"):
             map = [line.split()[0],line.split()[-1].split("->")]

             """ viosname -> vscsi"""
             data[map[1][0]]=map[0]     
             """ vscsi -> viosname """
             data[map[0]]=map[1][0]

    return data

def mpio_path_check(lpar):
   
    returnerror=True

    output = ssh_output(lpar,"lspath") 

    if output is None or output is False:

        if ssh_output(lpar,"echo OK") == False:
            error_message("Unable to check paths on %s, host not responding." % lpar )
        else:
            error_message("Unable to check paths on %s, unknown reason.." % lpar )

        return

    vscsi_map = get_vscsi_2_vhost(lpar)

    if len(vscsi_map) < 1 :
        print("[W] %s is a very old patch level - cannot determine the vhosts easily.." % lpar)

    multipath = {}
    samepath = {}

    """
    example output:
       Enabled hdisk2 vscsi0
    """
    for line in output:
        p1 = line.split()

        if not "vscsi" in p1[2]:
            continue

        vios = vscsi_map.get( p1[2],"" )

        if vios:
            """ vios + disk """
            samepath[ vios+"-"+p1[1] ] = samepath.get(vios+"-"+p1[1],0) + 1

        if "Enabled" in p1[0]:
            if p1[1] in multipath:
                multipath[ p1[1] ] += 1
            else:
                multipath[ p1[1] ] = 1

        if "Missing" in p1[0]:
            print("[E] %s %s " % (lpar, line) )

        if "Failed" in p1[0]:
            print("[E] %s %s " % (lpar, line) )

        if "Defined" in p1[0]:
            print("[W] %s %s " % (lpar, line) )


    for item in multipath:
        log("pathcount: %s %s %s" % (lpar, item, multipath[item]) )
        if multipath[item] <2 :
            error_message("%s disk %s has only one path " % (lpar, item) )
            returnerror=False

    # @@SGM - had a node fail with same path - this needs to be re-validated. 21/03/19
    for item in samepath:
        if samepath[item] > 1:
            error_message("******************************************************************")
            error_message("disk: %s has more than one path presented from VIO %s." % ( item.split("-")[1], item.split("-")[0] )  )
            error_message("******************************************************************")

            returnerror=False

    return returnerror

def vfchost_adapter_check(lpar):

    hasError = False

    output = ssh_output(lpar,"\"/usr/bin/apply '/usr/bin/fcstat %1' \$( /usr/sbin/lsdev -t IBM,vfc-client -r name )\"")

    if output is None or output is False:
        logging.debug("vfchost_adapter_check: no vfc-client adapters found")
        return None

    data = {}

    for line in output:
        if "Port Speed (running)" in line:
            if "8" not in line:
                hasError = True
                logging.debug( "vfchost_adapter_check: port speed is not 8GBIT" )
                error_message( "LPAR: %s VFC adapter is not running at 8GBIT" % lpar )

    return hasError


def check4vios_failover2(hw=None):

    if hw is None:
        cecClass = cec()
    else:
        cecClass = cec(hw)

    nimo = nim()
    hosts = nimo.ls("standalone")

    while True:

        (hw, lpar) = cecClass.next()

        if hw is None:
            break

        #if lpar != "crwsmappd01": continue

        if " " in lpar:
            print("[W] CEC: %-32s LPAR: %-32s INVALID HOSTNAME, SKIPPING" % (hw, lpar) )
            continue

        if not hosts.get(lpar):
            print("[W] CEC: %-32s LPAR: %-32s NOT MANAGED BY NIM" % (hw, lpar) )

        if mpio_path_check(lpar):
            print( "[I] MPIO: CEC: %-32s LPAR: %-32s OK" % (hw, lpar) )
        else:
            print( "[E] MPIO: CEC: %-32s LPAR: %-32s FAILED" % (hw, lpar) )

        vfcStatus = vfchost_adapter_check(lpar)

        if vfcStatus is not None:
            if vfcStatus is True:
                print( "[E]  VFC: CEC: %-32s LPAR: %-32s FAILED" % (hw, lpar) )
            else:
                print( "[I]  VFC: CEC: %-32s LPAR: %-32s OK" % (hw, lpar) )


if __name__ == "__main__":
    VERBOSE=False
    myNodeName = platform.node()

    parser = argparse.ArgumentParser( description = 'Check VIOS can be rebooted', add_help = "False", usage = '%(prog)s [options]')
    parser.add_argument('-n', required = False, metavar = 'VIOS-NAME', type = str, help='Target VIOS,VIOS,VIOS....')
    parser.add_argument('-m', required = False, metavar = 'CEC-NAME', type = str, help='Target Management Server')
    parser.add_argument('-a', required = False, metavar = '', type = str2bool, nargs='?', const=True, default=False, help='Find all VIOS')
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

    VERBOSE = str2bool(os.environ.get("VERBOSE","")) or args.v

    if ssh_agent_check() == False:
        error_message( "ssh-agent or forwarded-agent is not activated, have you loaded the SSH keys ??" )
        exit(1)

    if args.a:
        check4vios_failover2()
        exit(0)

    if args.m:
        check4vios_failover2(args.m)

    if args.n:
        nimc = nim()
        nimc.get(args.n)

        try:
            hw = nimc.setting("mgmt_profile1").split()[2]

            print("[I] CEC: %s" % hw )

            check4vios_failover2(hw)
        except:
            raise
            error_message("Could not find CEC for LPAR.")

