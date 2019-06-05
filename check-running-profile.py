#!/usr/bin/python -tt

from nimlib import *

if __name__ == "__main__":


    parser = argparse.ArgumentParser( description = 'Show configured VLAN ', add_help = "False", usage = '%(prog)s [options]')

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

    VERBOSE.mode = str2bool( os.environ.get("VERBOSE","") ) or args.v

    if ssh_agent_check() == False:
        error_message( "ssh-agent or forwarded-agent is not activated, have you loaded the SSH keys ??" )
        exit(1)

    if args.m or args.a:
        if args.m:
            print("[I] Searching for NODES")

            for cec in str(args.m).split(","):
                log("__main__: searching %s" % cec )
                cecs = nimquery_vios(cec)

        if args.a:
            print("[I] Searching for all available vios")
            cecs = nimquery_all_vios()

        #logdata( lparMapping )

        for cec in cecs:
            print( "[I] CEC: %s" % cec )

            


#  mksyscfg -r prof -m $system -o save -p $lpar -n `lssyscfg -r lpar -m $system --filter lpar_names=$lpar -F curr_profile` --force; done
