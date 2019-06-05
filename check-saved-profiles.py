#!/usr/bin/python -tt

"""
    Check the running profiles - ensure that they are the same as the profile the lpar was booted from.
    If its not the same then show a summary of the problems.

    User can use flag to save to the running profile or to a new profile "auto-saved", can be run
    from cron and use the email flag to send report out
"""

import logging
import sys
import smtplib

from nimlib import *

#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s' )

class saveOutput():

    def __init__(self):
        self.prep = []
        self.seenErrors=False
        self.prep.append("Subject: ERRORS detected in LPAR profiles presented to NIM %s (%s)" % ( os.uname()[1], __file__ ) )

    def p(self,o):
        self.prep.append(o)

        if "[E]" in o:
            self.seenErrors=True

        print(o)
        
    def email(self,to):
        if self.seenErrors:
            server=smtplib.SMTP("localhost")

            if server is None:
                return False

            try:
                result = server.sendmail("noreply-linux@local",to,"\n".join(self.prep) )
                print("[I] email sent to %s" % to )
            except:
                print("[E] Failed to send email.")


def _action(hw=None,lpar=None):
    global saveProfile
    global saveNewProfile
    global sendMailTo

    so = saveOutput()

    if lpar is None:
        if hw is None:
            cecClass = cec()
        else:
            cecClass = cec(hw)

        while True:
            """
               Calling next without any cecs will discover all cecs and all nodes
            """
            (hw, lpar) = cecClass.next()

            if hw is None:
                break

            profile = lpar_profile(hw,lpar)

            if profile.status() == False:
                so.p( "[E] Problem getting data for hw:%s lpar:%s" % (hw,lpar) )
                continue

            thechanges = {}

            if profile.changed(thechanges):
                so.p("[E] %-26s %-26s ERROR" % (hw, lpar) )

                for change in thechanges:
                    if type(thechanges[change]) == list:
                        so.p( "[W] HINTS [%s]" % change )

                        for change2 in thechanges[change]:
                            so.p( "[W] HINTS          %s" % change2 )
                    else:
                        so.p( "[W] HINTS [%s] [%s]" % ( change, thechanges[change] ) )

                if saveProfile or saveNewProfile:
                    if saveNewProfile:
                        profileName="auto-save-profile"
                    else:
                        profileName=profile.current()

                    if profile.save( profileName ):
                        so.p("[I] Saved profile to %s" % profileName )

                        #if str(profile.current()) == str(profile.default()):
                        #    so.p("[W] Defaut profile is not current profile")
            else:
                so.p("[I] %-26s %-26s OK" % (hw, lpar) )

    elif lpar is not None and hw is None:

        nimo = nim()

        if nimo.get(lpar):
            if nimo.setting("mgmt_profile1") is None:
                so.p("[E] %s not found." % lpar)
                return False

            hw = nimo.setting("mgmt_profile1").split(" ")[-1]

            cecClass = cec(hw)

            profile = lpar_profile(hw,lpar)
            thechanges = {}

            Result = profile.changed(thechanges)

            if Result is None:
                so.p("[E] %-26s %-26s ERROR COMMUNICATING" % (hw, lpar) )

            if Result is True:
                so.p("[E] %-26s %-26s ERROR" % (hw, lpar) )

                for change in thechanges:
                    if type(thechanges[change]) == list:
                        so.p( "[W] HINTS [%s]" % change )

                        for change2 in thechanges[change]:
                            so.p( "[W] HINTS          %s" % change2 )
                    else:
                        so.p( "[W] HINTS [%s] [%s]" % ( change, thechanges[change] ) )

                if saveProfile or saveNewProfile:
                    if saveNewProfile:
                        profileName="auto-save-profile"
                    else:
                        profileName=profile.current()

                    if profile.save( profileName ):
                        so.p("[I] Saved profile to %s" % profileName )

                        #if str(profile.current()) == str(profile.default()):
                        #    so.p("[W] Defaut profile is not current profile")
            if Result is False:
                so.p("[I] %-26s %-26s OK" % (hw, lpar) )
        else:
                so.p("[E] unable to locate hardware this LPAR runs on.")

    if sendMailTo is None:
        pass
    elif sendMailTo:
        print("sending mail")
        so.email(sendMailTo)

    return True


if __name__ == "__main__":

    saveProfile=False
    saveNewProfile=False
    sendMailTo=None

    parser = argparse.ArgumentParser( description = 'Check to see if running LPAR profiles have not been saved.', add_help = "False", usage = '%(prog)s [options]')
    parser.add_argument('-n', required = False, metavar = 'LPAR-NAME', type = str, help='Target LPAR,LPAR,LPAR....')
    parser.add_argument('-m', required = False, metavar = 'CEC-NAME', type = str, help='Target Management Server')
    parser.add_argument('-e', required = False, metavar = 'EMAIL',    type = str, help='Mail results')

    parser.add_argument('-S', required = False, metavar = '', type = str2bool, nargs='?', const=True, default=False, help='Save New Profile')
    parser.add_argument('-s', required = False, metavar = '', type = str2bool, nargs='?', const=True, default=False, help='Save Running Profile')
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

    if args.v:
        """ Why does this not work here ???? """
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s' )

    #VERBOSE = str2bool(os.environ.get("VERBOSE","")) or args.v

    if args.e:
        sendMailTo=args.e
        print( "[I] errors will be emailed to %s" % sendMailTo )

    if ssh_agent_check() == False:
        error_message( "ssh-agent or forwarded-agent is not activated, have you loaded the SSH keys ??" )
        exit(1)

    if args.s :
        saveProfile=True
        saveNewProfile=False

    if args.S:
        saveProfile=False
        saveNewProfile=True

    if args.a:
        _action()

    elif args.m:
        _action(args.m)

    elif args.n:
        for lpar in args.n.replace(";"," ").replace(","," ").split(" "):
            _action(None,lpar)


