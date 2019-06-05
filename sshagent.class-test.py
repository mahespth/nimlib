#!/bin/python -tt

import os
import subprocess

from nimlib import sshagent

class oldsshagent():
    """
    """

    def __init__(self):

        self.connected = False
        self.pid =       None
        self.socket =    os.environ.get("SSH_AUTH_SOCK",None)
        self.pid =       os.environ.get("SSH_AGENT_PID",None)
        self.raw = None

    def start(self,**kwargs):
        """
           use Popen to 
        """
        cmd=[]
        cmd.append("/usr/bin/ssh-agent")

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
            (output,erc) = self._cmd( ["/usr/bin/ssh-add","-l"] )
        else:
            (output,erc) = self._cmd( ["/usr/bin/ssh-add","-l","-E",hash] )

        if erc > 0:
            return None

        self.raw=output

        return output

    def removeall(self):
        (output,erc) = self._cmd( ["/usr/bin/ssh-add","-D"] )

        if erc > 0:
           logging.debug("sshagent.del: failed to delete key %s" % key )
           return False

        return True


    def remove(self,key):
        (output,erc) = self._cmd( ["/usr/bin/ssh-add","-d",key] )

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
                (output,erc) = self._cmd( ["/usr/bin/ssh-add",key] )
            else:
                (output,erc) = self._cmd( ["/usr/bin/ssh-add","-t",life,key] )

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

        (output,erc) = self._cmd( ["/usr/bin/ssh-add","-l"] )

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


if __name__ == "__main__":
    agent = sshagent()

    if agent.running():
        print "running"
    else:
        print "not running.."

    if agent.haskey("nim"):
        print("has nim key")

    if agent.haskey("bob"):
        print("does not have bob key")

    if agent.haskey("/vio"):
        print("has nim key")

    if agent.add("/home/root/.ssh/vio"):
        print "added vio"

    if agent.remove("/home/root/.ssh/vio"):
        print "removed vio"

    if agent.add("/home/root/.ssh/vio"):
        print "added vio"

    for output in agent.raw:
        print(": %s " % output )

    for id in agent.keylist("MD5"):
        print("id=%s" % id )


