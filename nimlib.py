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
import copy
import yaml
import json
import pprint
import logging
import argparse
import platform
import traceback
import subprocess

""" We are going to cache some of the class data between frees' """
#import weakref

#import pdb;
#pdb.set_trace()

class aixdevices():
    """
    """

    def __init__(self):
        self.devices = []

    def ls(host,**kwargs):

        cmd=[]
        cmd.append("lsdev","-C","-r","name")

        for key, value in kwargs.iteritems():

            if "subclass" in key:
                cmd.append("-s",value)

            if "type" in key:
                cmd.append("-t",value)

            if "class" in key:
                cmd.append("-c",value)

            if "state":
                cmd.append("-S",value)

        ssho = nimssh()
        output = nimssh.new(host, cmd.join(' '))
        
        for line in output:
            self.devices.append(line)

        return self.devices


class sshagent():
    """
       control the ssh agent.
    """
    def __init__(self):
        self.connected = False
        self.pid =       None
        self.socket =    os.environ.get("SSH_AUTH_SOCK",None)
        self.pid =       os.environ.get("SSH_AGENT_PID",None)
        self.raw = None
        self.located = {}
        self.sshbin = self.locate("ssh")
        self.agentbin = self.locate("ssh-agent")
        self.sshaddbin = self.locate("ssh-add")

    def locate(self,cmd):
        if self.located.get( cmd ):
            return self.located.get( cmd )

        for path in ["/usr/local/bin","/usr/local/sbin","/usr/sbin","/usr/bin"]:

            if os.path.isfile( path+"/"+cmd ):
                self.located[cmd]=path+"/"+cmd
                return self.located.get( cmd )

        return False

    def start(self,**kwargs):
        """
           use Popen to 
        """

        if not self.locate("ssh-agent"):
            return False
        
        cmd=[]
        cmd.append( self.locate("ssh-agent") )

        for key, value in kwargs.iteritems():

            if "life" in key:
                cmd.append("-t",value)

            if "fingerprint":
                cmd.append("-E",value)

        (output,erc) = self._cmd( cmd )

        if erc > 0:
            self.raw = output
            return False

        self.socket=None
        self.socket=pid

        for line in output:
            if "SSH_AUTH_SOCK" in line:
                self.socket = line.split(";")[0].split("=")[1]

            if "SSH_AGENT_PID" in line:
                self.pid = line.split(";")[0].split("=")[1]

        return True


    def keylist(self,hash=None):
        if hash is None:
            (output,erc) = self._cmd( [self.sshaddbin,"-l"] )
        else:
            (output,erc) = self._cmd( [self.sshaddbin,"-l","-E",hash] )

        if erc > 0:
            return None

        self.raw=output

        return output

    def removeall(self):
        (output,erc) = self._cmd( [self.sshbin,"-D"] )

        if erc > 0:
           logging.debug("sshagent.del: failed to delete key %s" % key )
           return False

        return True


    def remove(self,key):
        (output,erc) = self._cmd( [self.sshaddbin,"-d",key] )

        if erc > 0:
           logging.debug("sshagent.del: failed to delete key %s" % key )
           return False

        return True


    def add(self,key,life=None):

        returnCode=True
        keylist = []

        if life is not None:
            if isinstance(life,int):
                pass
            else:
                life=copy.copy(0)
        
        if isinstance(key,str):
            keylist.append(key)
        else:
            keylist = copy.copy(key)

        for key in keylist:
            if life is None:
                (output,erc) = self._cmd( [self.sshaddbin,key] )
            else:
                (output,erc) = self._cmd( [self.sshaddbin,"-t",life,key] )

            if erc > 0:
                returnCode = False
                logging.debug("sshagent.addkey: failed to load key %s" % key )

        self.raw = output

        return returnCode

    def raw(self):
        return self.raw
    
    def haskey(self,key):
        """ 
           is this key (by filename) loaded into the agent
           :returns: boolean
        """
        for line in self.keylist():
            p=line.split(" ")

            if key in p[2]:
                return True

        return False

    def running(self):

        (output,erc) = self._cmd( [self.sshaddbin,"-l"] )

        if erc > 0:
            return False

    def _cmd(self,args):

        erc = 0

        try:
            from subprocess import PIPE,Popen
            proc = Popen(args, stdout=PIPE, stderr=subprocess.STDOUT)
            output =  proc.communicate()[0].splitlines()
            
        except subprocess.CalledProcessError as exc:
            erc = exc.returncode

        return output,erc

class nimssh():
    """
       @@SGM merge with ssh-agent class??
       
    """

    def __init__(self,target="localhost",options=None):

        logging.debug("nimssh: target=%s" % target )

        if options == None:
            self.options = ["-n", "-q", "-oConnectTimeout=5", "-oBatchMode=true"]
        else:
            self.options = copy.copy(options)

        self.ssh="/usr/bin/ssh"
        self.target=copy.copy(target)
        self.status=True

        return

    def new(self,args):
        logging.debug( "nimssh.new: args=%s" % args )

        output = []
        command = (" ".join([ self.ssh," ".join(self.options), self.target, args ]) )

        logging.debug("nimssh: command=%s" % command)

        try:
            if sys.hexversion > 33949424:
               output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True).splitlines()
            else:
               from subprocess import PIPE,Popen
               proc = Popen(args, stdout=PIPE)
               output =  proc.communicate()[0].splitlines()

        except subprocess.CalledProcessError as exc:
            self.status=False
            self.output=None
            self.returncode = exc.returncode

            logging.debug("nimssh: error returned erc=%s" % exc.returncode )

            return False

        self.output = output
        self.returncode = 0

        logging.debug("nimssh: complete, lines buffered length=%d" % len(self.output) )


        lineCount=0

        for line in output:
            lineCount+=1
            logging.debug("nimssh: line:%-4s ^%s$ " % ( lineCount, line ) )

        return True

    def rc(self):
        if self.returncode is None:
            return None
        else:
            return self.returncode
    

    def output(self):
        if self.out is None:
            return None
        else:
            return self.output


""" 
   :get lpar profile information of given profile name
"""

class lpar_profile():

    def __init__(self,cec,name,hmc=None):

        self._name = copy.copy(name)
        self._cec = copy.copy(cec)
        self._status = False
        self._default = None
        self._cache = {} 
        self._ignoreSettings = None

        logging.debug("lpar_profile: name=%s,cec=%s" % ( self._name,self._cec ) )

        if hmc is None:
            no = nim()
            no.get(cec)

            hmc = no.setting("hmc")
            no = None

            logging.debug("lpar_profile: hmc=%s" % hmc )

            if hmc is None or not len(hmc):
                logging.debug("lpar_profile: something wrong with HMC")
                self._name = None
                self._cec = None
                self._hmc = None
            else:
                self._hmc=hmc
                self._status = True

        state = self.attr("state")

        if state is None:
            self._name = None
            self._cec = None
            self._hmc = None
            self._status = False

            return 

        return

    def exists(self):
        if self._status:
            if self.attr("default_profile"):
                return True

        return False

    def hmc(self):
        return self._hmc

    def cec(self):
        return self._cec

    def status(self):
        return self._status

    def changed(self,changed=None):
        """
            Has this profile changed ?? ie is the running profile
            different from the one we booted from !! Only way of 
            determining this is to save the profile and compare 
            the changes
        """
        detailedSettings = { "virtual_scsi_adapters":"true", "virtual_fc_adapters":"true", "virtual_eth_adapters":"true" }
        temporaryProfileName=self._name+"_temporary"

        state = self.attr("state")

        if state is None:
            return None

        if "Running" not in state:
            """
               If the lpar is not running then it cannot have its profile changed
            """
            return False

        if self.save(temporaryProfileName) == False:
            return None

        currentProfile = self.attr("curr_profile")

        booted_settings  = self.profile(currentProfile)
        running_settings = self.profile(temporaryProfileName)

        """ We have finished with this so remove it, as we have the settings in a dict """
        self.remove(temporaryProfileName)

        self.ignoresettings()

        for item in self._ignoreSettings:
            if booted_settings.get(item):
                del booted_settings[item]

            if running_settings.get(item):
                del running_settings[item]

        if booted_settings == running_settings:
            """ We can take an early exit """
            return False

        if changed is None:
            """ Another early exit, as no interest in what has changed """
            return True

        """ use running_settings as the key, as this is the current state """
        for item in running_settings:
            if booted_settings.get(item) != running_settings.get(item):

                if detailedSettings.get(item):

                    settings = list2dict( hmcstrsplit( booted_settings.get(item) ) )
                    list2dict( hmcstrsplit( running_settings.get(item) ), True, settings)

                    changed[item]=[]

                    for part in settings:
                        if settings.get(part) <2:
                            changed[item].append(part)

                    """ If this leg has no data then remove it from the structure """
                    if len( changed[item] ) == 0:
                        del( changed[item] )

                else:
                    changed[item]=running_settings[item]

        """
           Some of the settings are the 'same' but are differently ordered
           hence why having to check in detail for some attributes as while
           they are not == they are equal.
        """
        if len(changed) == 0:
            return False

        """ Return True because the profile has changed ! """
        return True


    def ignoresettings(self,settingName=None,settingsValue=None):
        if self._ignoreSettings is None:
            self._ignoreSettings = { "bsr_arrays":"true", "name":"true", "conn_monitoring":"true", "power_ctrl_lpar_ids":"true", "io_slots":"true" }

        if settingName is not None:
            if settingsValue is None:
                del self._ignoreSettings[settingName]
            else:
                self._ignoreSettings[settingName]=settingsValue

        return True

    def remove(self,name=None,flags=None):
        """
           Remove a profile - but not if its the current or default profile unless forced
        """
        if name is None:
            removeName=self._name+"_temporary"
        else:
            removeName=copy.copy(name)

        if flags is not None:
            pass

        """
           Get default and current profile name
        """
        currentProfile = self.attr("curr_profile")
        defaultProfile = self.attr("default_profile")

        if currentProfile == name or defaultProfile == name:
            logging.debug("cannot delete profile that is current or default")
            return False

        """
           Remove the profile
           this can return errors if the hmcs are not syncing correctly, we should
           think about testing for the "retry" message and running on the alternate
           hmc before telling the user there is a problem.
        """
        hmc_cmd=("rmsyscfg -r prof -m %s -p %s -n %s" % (self._cec, self._name, removeName ) )
        hmcssh = nimssh(self._hmc)

        returnCode = hmcssh.new(hmc_cmd)

        if returnCode == False:
            logging.debug("error occured, unable to remove the profile on hmc:%s cec:%s lpar:%s newname:%s" % ( self._hmc, self._cec, self._name, removeName) )
            return False

        return True

    def profile(self,name=None):
        if name is None:
            self._profile = self.attr("curr_profile")
        else:
            self._profile = copy.copy(name)

        hmc_cmd=( "lssyscfg -r prof -m %s --filter \"lpar_names=\"\"%s\"\",profile_names=\"\"%s\"\"\"" % ( self._cec, self._name,self._profile ) )
        hmcssh = nimssh(self._hmc)

        if hmcssh.new(hmc_cmd):
            input = hmcssh.output[0]
            index = 0
            last_index=0
            output = []
            output_dict = { }

            while index < len(input):
                index = input.find(",",index)
        
                if index == -1:
                    index=len(input)

                if "\"" in input[last_index]:
                    last_index+=1

                    # if string.find('""', then end is string.find('"""') else end is string.find('"')
                    while True:
                        index = input.find("\"",(index+1))

                        if "\"" in input[(index+1)]:
                            index+=2
                            if "\"" in input[index]:
                                #logging.debug("end of quoted quote section.. phew")
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

                logging.debug("added %s %s" % ( line[0:eq_location], line[(eq_location+1):len(line)] ) )

                index+=1
                last_index=index
        else:

            logging.debug("lpar_profile.profile: Returning no data")
            return None


        logging.debug("lpar_profile.profile: Returning data size=%d" % len(output_dict) )

        hmcssh = None

        return output_dict


    def save(self,saveName=None):

        if saveName is None:
            profileName=copy.copy(self._name)
            profileName+="_temporary"
        else:
            profileName=copy.copy(saveName)

        hmc_cmd=("mksyscfg -r prof -m %s -o save -p %s -n %s --force" % (self._cec, self._name, profileName ) )
        hmcssh = nimssh(self._hmc)

        returnCode = hmcssh.new(hmc_cmd)

        if returnCode == False:
            logging.debug("error occured, unable to save the profile on hmc:%s cec:%s lpar:%s newname:%s" % ( self._hmc, self._cec, self._name, profileName) )

        hmcssh = None
        return returnCode

    def attr(self,attr):
        """
            :returns: lpar attribute
        """
        if attr is None:
            return None

        returnAttr=None

        """
           Perfect use case for weak references to cache the data as
           this object is destroyed on invokation however the data 
           is used again and again in a loop.
        """

        hmc_cmd=( "lssyscfg -r lpar -m %s --filter 'lpar_names=\"%s\"' -F %s" % (self._cec, self._name, attr ) )
        logging.debug( "cmd=%s" % hmc_cmd )
        hmcssh = nimssh(self._hmc)

        if hmcssh.new(hmc_cmd) == True:
            returnAttr = hmcssh.output[0]

            logging.debug("lpar_profile: attr=%s" % returnAttr )
        else:
            logging.debug("lpar_profile: attr is None" )
            return None

        hmcssh = None

        return returnAttr

    def current(self):
        """
            :returns: default profile name
        """
        self.default=self.attr("curr_profile")

        return self.default
        

    def default(self):
        """
            :returns: default profile name
        """
        self.default=self.attr("default_profile")

        return self.default
        
    def __del__(self):
        try:
            hmcssh is None
        except:
            pass

        return

class nim():

    def __init__(self):
        if os.path.isfile("/usr/sbin/nim"):
            self.type = "master"
        else:
            self.type = client

        return

    def __del__(self):
        self.type = None
        self.data = None

        return

    def type(self):

        return self.type

    def ls(self,type="",mclass=""):

        logging.debug("nim.ls(%s,%s):" % (type,mclass) )

        self.ls = {}

        try:
            if len(type):
                logging.debug("nim: lsnim -t %s" % type )
                output = subprocess.check_output(["/usr/sbin/lsnim","-t",type], stderr=subprocess.STDOUT ).splitlines()

                for line in output:
                    line=' '.join(line.split())
                    self.ls[line.split(" ")[0]] = line.split(" ")[1]

            elif len(mclass):
                logging.debug("lsnim -c %s " % mclass )
                
                output = subprocess.check_output(["/usr/sbin/lsnim","-c",mclass], stderr=subprocess.STDOUT ).splitlines()

                for line in output:
                    line=' '.join(line.split())
                    self.ls[line.split(" ")[0]] = line.split(" ")[2]
            else:
                return  None

        except:
            logging.debug("exception occured during execution.")
            self._status = False
            return

        if output == None:
            self._status = False
            return

        return self.ls

    def get(self,name):

        self.object = {}
        self.name = None
        output = ()

        try:
            output = subprocess.check_output(["/usr/sbin/lsnim","-l",name], stderr=subprocess.STDOUT ).splitlines()

        except:
            self._status = False
            return

        if output == None:
            self._status = False
            return

        self.name = name

        for line in output:
            if " " in line[0]:
                var = line[0:line.find("=")].replace(" ","")
                val = line[line.find("=")+2:]

                """ 
                   If we have more than one of the same object then we 
                   will create an array of those values making this a
                   nice object that can be yaml/json compatible and well
                   formed.
                """
                if self.object.get(var) or type(self.object.get(var)) is list:
                    if type(self.object[var]) is list:
                        pass
                    else:
                        self.object[var] = None
                        self.object[var] = []

                    tempList=self.object[var]
                    tempList.append(val)
                    self.object[var] = tempList

                else:
                    self.object[var] = val

        return True

    def status(self):
        return self._status

    def setting(self,name):
        return self.object.get(name)

    def items(self):
        return ( self.object.viewkeys() )
    

class nimquery():
    """ 
       :nimquery:
    """

    def __init__(self, type, name):
        self.name   = copy.copy(name)
        self.type   = copy.copy(type)
        self.data   = {}
        self.status = True

        try:
            logging.debug("executing /usr/sbin/nimquery")
            output =  subprocess.check_output(["/usr/sbin/nimquery", "-a", type+"="+name ], stderr=subprocess.STDOUT ).splitlines()

        except:
            self.status = False
            logging.debug("executing /usr/sbin/nimquery failed")
            return False

        if output == None:
            self.status = False
            return False

        for line in output:
            vars   = ( nq.split("=")[0] for nq in line.split(",") )
            values = ( nq.split("=")[1] for nq in line.split(",") )
            data = dict( zip( vars, values ) )

            self.data[data["name"]]=data

        #print(json.dumps(self.data, indent=4, sort_keys=True) )

        return None

    def status(self):
        return self.status

    def names(self):
        return ( self.data.viewkeys() )

    def settings(self,name):
        return self.data.get(name)

    def setting(self,name,setting):
        return self.data[name].get(setting)

    def raw(self):
        return self.data


class cec():
    def __init__(self,cec=None):

        self.cec = []
        self.nextdata = None

        if cec is None:
            self.cec = []

            cecs=nim()
            self.cec = cecs.ls("cec","")

        if isinstance(cec, str):
            for cec in cec.replace(" ",",").replace(";",",").split(","):
                self.cec.append(cec)

    def list(self):
        return self.cec

    def info(self,cec=None):
        """
            Get CEC HW information.
        """

    def lpars(self,cec=None):
        """
           Return lpars attached to cec and their state
        """
        self.lpars = {} 


        for cec in self.cec:
            self.lpars[cec]=[]

            cecdata = nimquery("cec",cec)

            for node in cecdata.names():
                self.lpars[cec].append(node)

        self.nextdata = copy.copy(self.lpars)

        return self.lpars

    def next(self):
        if self.nextdata is None:
            self.nextdata = self.lpars()

        for cec in self.lpars:
            for lpar in self.lpars[cec]:
                if len(lpar):
                    self.lpars[cec].remove(lpar)
                    return str(cec),str(lpar)

        return None,None

def cecls():

    cecs=nim()

    for cec in cecs.ls("cec",""):
        logging.debug("cec=%s" % cec)

        cecdata = nimquery("cec",cec)

        for node in cecdata.names():
            ltype = cecdata.setting(node,"lpar_env")
            state = cecdata.setting(node,"state")

            profile1 = lpar_profile(cec,node)
            status=profile1.status()

            logging.debug("lpar_profile.status = %s" % status )

            if not profile1.status():
                print("[E] hw:%-20s lpar:%-32s Running, but could not determine HMC" % ( cec,node) )
                continue

            hmc=profile1.hmc()

            default=profile1.default()
            current=profile1.attr("curr_profile")
            default=profile1.attr("default_profile")

            if current == default:
                star="*"
            else:
                star="!"

            if default is None:
                if "Running" in state:
                    print("[E] unable to find default profile for lpar:%s cec:%s" % (node, cec) )
                    continue
            else:
                print("[I] hmc:%-16s hw:%-32s lpar:%-16s profile:%s%-16s %8s %-10s" % ( hmc, cec, node, star, current, state, ltype) )



def list2dict(list,count=False,appendTo=None):
    """
       Turns a list into a dictionary, thus allowing us easily unique/count items.
       probably a better "python" way of doing this but this is easily understood.
       :input: list
       :returns: dict
    """
    logging.debug("list2dict: len=%s" % len(list))

    if appendTo == None:
        returnDict = {}
    else:
        logging.debug("list2dict: appending to type(%s) size(%s)" % ( type(appendTo), len(appendTo) ) )
        returnDict = appendTo

    for item in list:
        if count:
            returnDict[item]=returnDict.get(item,0)+1
        else:
            returnDict[item]=1

    logging.debug("list2dict: returning dict.size[%s]" % len(returnDict) )

    return returnDict

def hmcstrsplit(input,delim=","):
    """
       :descripton:split the hmc strings that are encapsulated with various quotes
       :returns:list
    """
    returnList=[]
    input = copy.copy(input)

    index=0
    last_index=0

    while index < len(input):
        index = input.find(delim,index)

        if index == -1:
            index=len(input)

        if "\"" in input[last_index]:
            last_index+=1

            while True:
                index = input.find( "\"", ( index+1 ) )

                if "\"" in input[(index+1)]:
                    index+=2
                    line = input[last_index:(index)]
                    break
                else:
                    line = input[last_index:(index)]
                    index+=1
                    break

        else:
            line = input[last_index:(index)]

        returnList.append(line)

        index+=1
        last_index=index

        logging.debug("hmcstrsplit:(%s) %s" % (index, line) )

    return returnList


def json_dump(data):
    if data is None:
        pass
    else:
        print(json.dumps(data, indent=4, sort_keys=True) )

    return True

def merged(x, y):
    """
       Merge the two dict objects. 
       used where we want to merge default ovbjects
    """
    z=x.copy()
    z.update(y)
    return z


def Xprofilecheck(name=None):

    cecs=nim()

    for cec in cecs.ls("cec",""):
        logging.debug("cec=%s" % cec)

        cecdata = nimquery("cec",cec)

        for node in cecdata.names():
            lparType = cecdata.setting(node,"lpar_env")

            if "Running" in cecdata.setting(node,"state"):
                profile1 = lpar_profile(cec,node)

                status=profile1.status()

                logging.debug("lpar_profile.status = %s" % status )

                if not profile1.status():
                    print("[E] hw:%-20s lpar:%-32s Running, but could not determine HMC" % ( cec,node) )
                    continue

                hmc=profile1.hmc()

                default=profile1.default()
                current=profile1.attr("curr_profile")
                default=profile1.attr("default_profile")

                if current == default:
                    star="*"
                else:
                    star="!"

                if default is None:
                    print("[E] unable to find default profile for lpar:%s cec:%s" % (node, cec) )
                    continue
                else:
                    print("[I] hmc:%-16s hw:%-32s lpar:%-16s profile:%s%-16s Running" % ( hmc, cec, node, star, default) )


def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")

def log(message):
    logging.debug(message)

def logdata(d):
    try:
        if VERBOSE.mode == True:
            if d == None:
                print("debug: logdata: empty")

            else:
                pp = pprint.PrettyPrinter(indent=4)
                pp.pprint(d)
    except:
        return

def error_message(message):
    print ("[ERROR] %s" % message, file=sys.stderr)
    return

"""    
   Some of the systems are still on python 2.6 so we
   will need work arounds until they are updated
"""
def check_output(args):
    logging.debug("check_output: %s" % args)

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
    """
       Find an object
       :returns: boolean
    """

    logging.debug("nim_object_exists: '%s'" % object)

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
   :returns: string
"""
def nim_attribute(name,attribute):
    returndata=""

    logging.debug("nim_attribute: %s %s " % (name, attribute) )

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

    logging.debug("lsnim_type: %s" % type )

    try:
        output = check_output( [ "/usr/sbin/lsnim", "-t", type ] )
        output = ( line.split(" ")[0] for line in output )

    except:
        return None

    return output


def nimquery_all_vios():
    logging.debug("nimquery_all_cecs:")
    return nimquery_vios()

""" 
   Return a list of all VIOS on named tin.
   :returns: dict[hardware_id]="vios names..."
"""
def nimquery_vios(hwname=""):
    
    logging.debug("nimquery_cecs:")

    global lparMapping 

    #try:
    #    if lparMapping == None:
    #        lparMapping = {}
    #        
    #except:
    #    lparMapping = {} 

    cecs = {}

    if hwname:
        hw=[ hwname ]
    else:
        hw=lsnim_t( "cec" )

    for cec in hw:
        niminfo = nimquery("cec",cec)

        lpar_name=""

        """ 
           extract keypair info for lparMapping
        """
        for line in niminfo:
            vars   = ( xx.split("=")[0] for xx in line.split(",") )
            values = ( xx.split("=")[1] for xx in line.split(",") )
            data = dict( zip(vars,values) )

            logdata(data)
    
            # need this to go in a class...
            #lparMapping[cec+"-"+data["lpar_id"]] = data["name"]
            #lparMapping[data["name"]] = cec+"-"+data["lpar_id"]

            if data["lpar_env"] == "vioserver":
                lpar_name += data["name"] + " "
                logging.debug("nimquery_all_cecs: found %s on %s" % ( cec, lpar_name) )

        cecs[cec]=lpar_name

    return cecs

def Xnimquery(type,name):

    logging.debug("nim_info: %s" % name )

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
    logging.debug("check_output: %s" % args)

    if sys.hexversion > 33949424:
       return subprocess.check_output(args, stderr=subprocess.STDOUT, shell=True).splitlines()
       #return subprocess.check_output(args,stderr=None, shell=True).splitlines()
    else:
        from subprocess import PIPE,Popen
        proc = Popen(args, stdout=PIPE)
        return proc.communicate()[0].splitlines()



""" 
   @@SGM replace with a a class...
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

    logging.debug("ssh_output: %s %s " % (host, command) )

    try:
        output = ssh_check_output(" ".join([ ssh_command()," ".join(ssh_options()), host, command ]) )

    except subprocess.CalledProcessError as exc:
        logging.debug("ssh_output: error returned erc=%s" % exc.returncode )
        return False

    return output

""" 
   Return vhost mapping from vios server.
   returns: disk[hdiskxxx]="vhostx vhosty .."
"""
def getvhostmapping(lpar):
    logging.debug("gethostmapping: %s" % lpar )

    """ 
       ioscli returns the number of output lines in $?, so ensure we clear that
       otherwise an error condition will be returned which is false.
    """
    output = ssh_output(lpar,"/usr/ios/cli/ioscli lsmap -field svsa backing -fmt : -all; true")
    
    if output == None or output == False:
        return None 

    data = {}

    for line in output:
        logging.debug("getvhostmapping: line = %s" % line )
        vhost = line.split(":")[0]

        for disk in line.split(":")[1:]:

            if len( data.get(disk,"") ) > 1:
                data[disk] = ("%s " % ( data.get(disk,"") ) )

            if len(disk) > 1:
                data[disk] = ("%s%s" % ( data.get(disk,""), vhost ) )

    for item in data:
        logging.debug("getvhostmapping: %s=\"%s\"" % ( item, data[item] ) )

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
    logging.debug("getodmSSH: host=%s odmClass=%s searchString=%s key=%s value=%s" % (host, odmClass, searchString, key, value ) )
    
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
        logging.debug("getodmSSH: line = %s" % line ) 

        if ("%s =" % key ) in line:
            dataKey=line.split("= ")[1].replace("\"","")

        if ("%s =" % value ) in line:
            data[dataKey]=line.split("= ")[1].replace("\"","")
            logging.debug("getodmSSH: %s = %s " % ( dataKey, data.get(dataKey) ) )

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
        logging.debug("getActivePVs: line = %s" % line )

        if ":" in line[-1]:
            vgName=line.split(":")[0]

        if "hdisk" in line:
            data[line.split()[0]]=vgName

    return data

def getvhostmapping_with_vtd(lpar):
    logging.debug("gethostmapping_with_vtd: lpar=%s" % lpar )

    """ 
       ioscli returns the number of output lines in $?, so ensure we clear that
       otherwise an error condition will be returned which is false.
    """
    output = ssh_output(lpar,"/usr/ios/cli/ioscli lsmap -field svsa clientid backing vtd -fmt : -all; true")
    
    if output == None or output == False:
        return None 

    data = {}

    for line in output:
        logging.debug("getvhostmapping_vtd: line = %s" % line )

        partitionID = int( line.split(":")[1],0 )
        data[line.split(":")[0]] = partitionID

        """ Using :: instead of -1 as if first field is last field and -1
            is used it returns no data, unsure if this is a bug or intentional.  """
        disks = line.split(":")[2::2]
        vtds  = line.split(":")[3::2]

        for index in range(0,len(disks)):
            data[disks[index]]=vtds[index]


    for item in data:
        logging.debug("getvhostmapping_vtd: %s=%s" % ( item, data[item] ) )

    return data

def get_EMC_CLARRiiON_inq(lpar):
    logging.debug("get_EMC_CLARRiiON_inq: %s " % lpar )

    data = {}

    inqCommand="/usr/lpp/EMC/CLARiiON/bin/inq.aix64_51 -nodots -wwn"

    output = ssh_output( lpar, inqCommand )

    if output == None or output == False:
        return False

    for line in output:
        logging.debug("get_EMC_CLARRiiON_inq: %s " % line )

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

    #global lparMapping 

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

        logging.debug("checkVIOSdisks: %16s %20s %15s  " % ( vios, disk, policy ) )

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

def hmcVersion( hmc ):
    logging.debug( "hmcVersion: %s" % hmc )


def locate_hmc(nimname):
    """ find hmc for node
        example output:
                [hostname:root:/home/root:] lsnim -Za mgmt_profile somehost
                #name:mgmt_profile:
                somehost:hmcname 29 cecname-and-serial:
    """

    logging.debug("locate_hmc: %s" % nimname)

    try:
        output = subprocess.check_output(["/usr/sbin/lsnim","-Za","mgmt_profile", nimname]).splitlines()

        if len(output) == 0:
            return None,None

    except:
        return None,None

    for line in output:
        logging.debug("subprocess-line %s" % line)

        if "#" not in line:
            return line.split(":")[1].split(" ")[0],line.split(":")[1].split(" ")[2]

    return

def process_lssyscfg_output(input):
    index = 0
    last_index=0
    output = []
    output_dict = { }

    while index < len(input):
        #logging.debug("index = %s" % index )

        index = input.find(",",index)
        
        if index == -1:
            index=len(input)

        if "\"" in input[last_index]:
            #logging.debug("found first quote")
            last_index+=1

            # if string.find('""', then end is string.find('"""') else end is string.find('"')
            while True:
                index = input.find("\"",(index+1))

                if "\"" in input[(index+1)]:
                    index+=2
                    if "\"" in input[index]:
                        #logging.debug("end of quoted quote section.. phew")
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

        logging.debug("added %s %s" % ( line[0:eq_location], line[(eq_location+1):len(line)] ) )

        index+=1
        last_index=index

    logging.debug("process_lssuscfg_output: Returning data size=%d" % len(output_dict) )

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
    logging.debug("mv of %s" % lpar)

    hmc,cec = locate_hmc(lpar)

    if hmc is None:
        error_message("Could not find lpar %s, skipping." % lpar)
        return

    default_profile = hmc_cli( lpar,( "lssyscfg -r lpar -m %s --filter lpar_names=%s -F default_profile" % (cec, lpar ) ) )

    logging.debug("default-profile: %s" % default_profile[0])

    profile_config = hmc_cli ( lpar,( "lssyscfg -r prof -m %s --filter lpar_names=%s,profile_names=%s" % (cec, lpar, default_profile[0] ) ) )

    out = process_lssyscfg_output(profile_config[0])
    
    logging.debug( "profile-data: %s\n" % profile_config[0] )

    white_flag_attributes=migratable_lpar_settings()
    ignore_lpar_attributes=ignore_lpar_settings()

    # Build a new command 
    ############################################################
    settings=""
    vlans=""

    for item,value in out.items():
        if len(item) == 0 :
            continue

        logging.debug( "item: %s == %s" % (item,value) )

        if ignore_lpar_attributes.get(item):
            logging.debug( "ignoring item %s" % item )
            continue

        reparse_function = white_flag_attributes.get(item)

        if reparse_function and value != "none":
            logging.debug( "Validating with %s" % reparse_function )

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

    logging.debug("hmc-command: %s %s" % (hmcCMD, command ) )

    try:
        return subprocess.check_output("%s %s" % ( hmcCMD, command ) ,shell=True).splitlines()

    except:
        raise
        return 

def vlan2vlan(sourceVLAN,destVLAN):
    """ Update the VLAN during the migration """
      
def attrs2csv(key):
    """ turn attributes into csv output, reads a file name or stdin """
       
    from collections import defaultdict
   
    keys = {}
    keys_temp = {}
    key_order = []
    data = defaultdict(dict)
    indexkey = copy.copy(key)

    for line in fileinput.input():
        out = process_lssyscfg_output( line.rstrip() )
        for item,value in out.items():
            if len(item) == 0 :
                continue

            if item == key:
                keyvalue=value
            else:
                if keys.get(item) is None:
                    keys[item]=True
                    key_order.append(item)
        
                keys_temp[item]=value
        
        data[ keyvalue ]=copy.copy(keys_temp)
        keys_temp.clear()

    print( '"%s",' % indexkey, end='' )

    for index in range( len(key_order) ):
      if key_order[index] != indexkey:
          print( '"%s",' % key_order[index], end='' )

    print('')

    #print(json.dumps(data, indent=4, sort_keys=True) )

    for k in data:
        print('"%s",' % k, end='' )
        
        for index in range( len(key_order) ):
            if key_order[index] != indexkey:
                print('"%s",' % (data[k].get(key_order[index],'null') ), end='' )

        print()


def hmc_capabilities(cec):

    hmc,cec = locate_hmc(cec)
    hmcCMD = hmcSSH( hmc, hmc_user() )
    
    command=( "lssyscfg -r sys -m %s -F capbilities" % cec )
    
    output = ssh_output(hmc,command)

    if output == None or output == False:
        return None

    logdata(output)

def sendMail(mail_from,mail_to,body):

    server=smtplib.SMTP("localhost")

    if server is None:
        return False

    try:
        result = server.sendmail(mail_from,mail_to,body)
    except: 
        return False

    return True

def smtpdDebuggingServer(address="localhost:1025"):
    import smtpd

    debug = DebuggingServer(address)


if __name__ is not "__main__":
    """
        The lib is loaded.
    """
    
    #from __future__ import print_function
    
    nimlib = {}
    nimlib["version"]=__version__

    VERBOSE = False
    global lparMapping
    lparMapping = {}

    if os.environ.get("VERBOSE"):
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s' )

    logging.debug("nimlib: loaded")
    logging.debug("nimlib: Version %s" % nimlib["version"])

