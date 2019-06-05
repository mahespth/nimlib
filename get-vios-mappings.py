#!/usr/bin/python -tt

# -*- coding: utf-8 -*-
# vim:expandtab:ts=4:sw=4:ai:number

"""
   Get the vios storage mappings.
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
import pprint

def logdata(d):
    if VERBOSE & True:
        if d == None:
            print("debug: logdata: empty")

        else:
            pp = pprint.PrettyPrinter(indent=4)
            pp.pprint(d)

def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")

""" 
   debug information will be sent to stderr 
"""
def log(message):
    if VERBOSE:
       print ("debug: %s" % message, file=sys.stderr)

def error_message(message):
    print ("[E] %s" % message, file=sys.stderr)
    return

"""    
   Some of the systems are still on python 2.6 so we
   will need work arounds until they are updated
"""
def check_output(args):
    log("check_output: %s" % args)

    if sys.hexversion > 33949424:
       return subprocess.check_output(args).splitlines()
    else:
        from subprocess import PIPE,Popen
        proc = Popen(args, stdout=PIPE)
        return proc.communicate()[0].splitlines()

""" 
   Does a nim object exist?
   returns: boolean
"""
def nim_object_exists(object,type):

    log("nim_object_exists: %s" % object)

    if len(type):
        try:
            output = check_output(["/usr/sbin/lsnim", "-t", type]).splitlines()

        except:
            return False

        for line in output:
            if object == line.split(" ")[0]:
                return True

    else:
        try:
            output = check_output(["/usr/sbin/lsnim", object]).splitlines()
            return True

        except:
            return None

    return False


"""
   Return the contents of NIM attributes
   returns: string
"""
def nim_attribute(name,attribute):
    returndata=""

    log("nim_attribute: %s %s " % (name, attribute) )

    try:
        output = check_output( ["/usr/sbin/lsnim", "-a", attribute, name] )

    except:
        return None
    
    if len(output) == 0:
       return None

    for line in output:
        index = line.find("=",1)

        if index < 1:
            continue

        returndata += line[index+2:132]+" "

    return returndata

"""
   Return all NIM objects of a given type
   returns: array
"""
def lsnim_t(type):

    log("lsnim_type: %s" % type )

    try:
        output = check_output( [ "/usr/sbin/lsnim", "-t", type ] )
        output = ( line.split(" ")[0] for line in output )

    except:
        return None

    return output


def nimquery_all_vios():
    log("nimquery_all_cecs:")
    return nimquery_vios()

""" 
   Return a list of all VIOS on named tin.
   returns: data[hardware_id]="vios names..."
"""
def nimquery_vios(hwname=""):
    
    log("nimquery_cecs:")

    cecs = {}

    if hwname:
        hw=[ hwname ]
    else:
        hw=lsnim_t( "cec" )

    for cec in hw:
        niminfo = nimquery("cec",cec)

        lpar_name=""

        for line in niminfo:
            vars   = ( xx.split("=")[0] for xx in line.split(",") )
            values = ( xx.split("=")[1] for xx in line.split(",") )
            data = dict( zip(vars,values) )

            logdata(data)

            lparMapping[cec+"-"+data["lpar_id"]] = data["name"]
            lparMapping[data["name"]] = cec+"-"+data["lpar_id"]

            if data["lpar_env"] == "vioserver":
                lpar_name += data["name"] + " "
                log("nimquery_all_cecs: found %s on %s" % ( cec, lpar_name) )

        cecs[cec]=lpar_name

    return cecs

def nimquery(type,name):

    log("nim_info: %s" % name )

    try:
        output=check_output( [ "/usr/sbin/nimquery", "-a", type+"="+name ] )

    except:
        return None

    if len(output) == 0:
        return None

    return output

"""    
    Many of the Arq systems are still on python 2.6 and cant yet be patched.
    returns: array
"""
def ssh_check_output(args):
    log("check_output: %s" % args)

    if sys.hexversion > 33949424:
       return subprocess.check_output(args, stderr=subprocess.STDOUT, shell=True).splitlines()
       #return subprocess.check_output(args,stderr=None, shell=True).splitlines()
    else:
        from subprocess import PIPE,Popen
        proc = Popen(args, stdout=PIPE)
        return proc.communicate()[0].splitlines()


""" 
   We need the ssh-agent running for keys to the hosts
   if you dont have it please go sort that out...
   returns: boolean
"""
def ssh_agent_check():
    output = ssh_check_output("/usr/bin/ssh-add -l 2>/dev/null; true" )

    for line in output:
        if "nim" in line:
            return True

    return False
    

"""
   Need this to check for ssh in prefered locations or pickup from env var or flag
"""
def ssh_command():
    return "/usr/bin/ssh"

def ssh_options():
    return ["-n", "-q", "-oConnectTimeout=5", "-oBatchMode=true", "-l", "root" ]

""" 
   execute SSH command
   returns: array|False|None
"""
def ssh_output(host,command):

    log("ssh_output: %s %s " % (host, command) )

    try:
        output = ssh_check_output(" ".join([ ssh_command()," ".join(ssh_options()), host, command ]) )

    except subprocess.CalledProcessError as exc:
        log( "ssh_output: error returned erc=%s" % exc.returncode )
        return False

    return output

""" 
   Return vhost mapping from vios server.
   returns: disk[hdiskxxx]="vhostx vhosty .."
"""
def getvhostmapping(lpar):
    log("gethostmapping: %s" % lpar )

    """ 
       ioscli returns the number of output lines in $?, so ensure we clear that
       otherwise an error condition will be returned which is false.
    """
    output = ssh_output(lpar,"/usr/ios/cli/ioscli lsmap -field svsa backing -fmt : -all; true")
    
    if output == None or output == False:
        return None 

    data = {}

    for line in output:
        log("getvhostmapping: line = %s" % line )
        vhost = line.split(":")[0]

        for disk in line.split(":")[1:]:

            if len( data.get(disk,"") ) > 1:
                data[disk] = ("%s " % ( data.get(disk,"") ) )

            if len(disk) > 1:
                data[disk] = ("%s%s" % ( data.get(disk,""), vhost ) )

    for item in data:
        log("getvhostmapping: %s=\"%s\"" % ( item, data[item] ) )

    return data

""" 
   Get local ODM attributes 
"""
def getodm(odmClass, searchString, key, value): 
    return getodmSSH("local", odmClass, searchString, key, value)

""" 
   Get ODM attribtes from remote or 'local' host 
   returns data[required-key]=value
"""
def getodmSSH(host, odmClass, searchString, key, value):
    log("getodmSSH: host=%s odmClass=%s searchString=%s key=%s value=%s" % (host, odmClass, searchString, key, value ) )
    
    if host == "local":
        output = check_output("odmget -q \"\\\""+stearchString+"\\\"\" "+odmClass)

        if output == None or output == False:
            return None
    else:
        output = ssh_output(host,"odmget -q \"\\\""+searchString+"\\\"\" "+odmClass)

        if output == None or output == False:

            if ssh_output(host,"echo OK") == None:
                error_message("Unable to check storage on %s, host not responding." % host )
            else:
                error_message("Unable to check storage on %s, unknown reason.." % host )

            return None

    data = {}
    dataKey = ""
    dataValue = ""

    for line in output:
        log("getodmSSH: line = %s" % line ) 

        if ("%s =" % key ) in line:
            dataKey=line.split("= ")[1].replace("\"","")

        if ("%s =" % value ) in line:
            data[dataKey]=line.split("= ")[1].replace("\"","")
            log("getodmSSH: %s = %s " % ( dataKey, data.get(dataKey) ) )

    return data

"""
   Update adapter attributes - now 
"""
def changeAttributeSSH(lpar, disk, attribute, value):
        if lpar == "local":
            output = check_output(lpar, ( "/usr/sbin/chdev -l %s -a %s=%s" % ( disk, attribute, value ) ) )

        else:
            output = ssh_output(lpar, ( "/usr/sbin/chdev -l %s -a %s=%s" % ( disk, attribute, value ) ) )

        if output == None:
            return True

        elif output == False:
            return False
            

        else:
            for line in output:
                if "changed" in line:
                    return True

                print( "[W] %s" % output )

            return False

""" 
   Return a list of active PVs and their associated VG
   returns: data[pv]=vg
"""
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

def getvhostmapping_with_vtd(lpar):
    log("gethostmapping_with_vtd: lpar=%s" % lpar )

    """ 
       ioscli returns the number of output lines in $?, so ensure we clear that
       otherwise an error condition will be returned which is false.
    """
    output = ssh_output(lpar,"/usr/ios/cli/ioscli lsmap -field svsa clientid backing vtd -fmt : -all; true")
    
    if output == None or output == False:
        return None 

    data = {}

    for line in output:
        log("getvhostmapping_vtd: line = %s" % line )

        partitionID = int( line.split(":")[1],0 )
        data[line.split(":")[0]] = partitionID

        """ Using :: instead of -1 as if first field is last field and -1
            is used it returns no data, unsure if this is a bug or intentional.  """
        disks = line.split(":")[2::2]
        vtds  = line.split(":")[3::2]

        for index in range(0,len(disks)):
            data[disks[index]]=vtds[index]


    for item in data:
        log("getvhostmapping_vtd: %s=%s" % ( item, data[item] ) )

    return data

def get_EMC_CLARRiiON_inq(lpar):
    log("get_EMC_CLARRiiON_inq: %s " % lpar )

    data = {}

    inqCommand="/usr/lpp/EMC/CLARiiON/bin/inq.aix64_51 -nodots -wwn"

    output = ssh_output( lpar, inqCommand )

    if output == None or output == False:
        return False

    for line in output:
        log("get_EMC_CLARRiiON_inq: %s " % line )

        if "/dev/r" in line:
            piece = line.replace(" ","").split(":")
            #data[piece[3]]=piece[0].replace("/dev/","")
            data[piece[0].replace("/dev/r","")]=piece[3]

    return data

def getVIOSmappings(vios,csvFile=''):

    """
       Get the scsi data, and vtd mapping data and output in the fomat
       viosname,lunid,disk,vtdname,partitionid
    """

    """ We need the cec this vios is running to be able to map the lpar names """
    cec = nim_attribute(vios,"mgmt_profile").split()[2]

    """ ssh comms all ok?? """
    isOK = ssh_output(vios,"echo OK")

    if isOK == None or isOK == False:
        error_message("Unable to communicate with %s, host not responding." % vios )
        return None

    """ scsi lun ids mapped to the disks """
    scsidata = {}
    vhostMapping   = {}     
    vtdMapping = {}

    vhostMapping = getvhostmapping(vios)
    vtdMapping   = getvhostmapping_with_vtd(vios)
    scsidata     = get_EMC_CLARRiiON_inq(vios)

    logdata( lparMapping )

    for disk in vhostMapping:

        lunid=scsidata.get(disk)
        lparName=lparMapping.get( cec + "-" + str(vtdMapping.get( vhostMapping[disk] ) ) )

        if csvFile:
            csvFile.write( "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n" % (
                vios,
                lunid,
                disk,
                vtdMapping.get(disk),
                vhostMapping[disk],
                lparName,
                ) )
        else:
            print( "%-16s %34s %-9s %16s %-9s %-4s" % (
                vios,
                lunid,
                disk,
                vtdMapping.get(disk),
                vhostMapping[disk],
                lparName,
                ) )


if __name__ == "__main__":

    myNodeName = platform.node()
    lparMapping = {}

    parser = argparse.ArgumentParser( description = 'Get VIOS disk mappings', add_help = "False", usage = '%(prog)s [options]')

    parser.add_argument('-n', required = False, metavar = 'VIOS-NAME',type = str, help='Target VIOS,VIOS,VIOS....')
    parser.add_argument('-m', required = False, metavar = 'CEC-NAME', type = str, help='Target Management Server')
    parser.add_argument('-c', required = False, metavar = 'filename', type = argparse.FileType('w+'), help='Output to CSV')
    parser.add_argument('-a', required = False, type = str2bool, nargs='?', const=True, default=False, help='Find all VIOS')
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

        logdata( lparMapping )

        for cec in cecs:
            print( "[I] CEC: %s VIOS: %s" % (cec, cecs[cec] ) )

            for lpar in cecs[cec].split():
                getVIOSmappings( lpar, args.c )

    if args.n:
        for lpar_name in str(args.n).split(","):
            log("arg target: %s" % lpar_name )

            cec = nim_attribute(lpar_name,"mgmt_profile").split()[2]
            cecs = nimquery_vios(cec)

            logdata( lparMapping )

            getVIOSmappings( str(lpar_name), args.c )
