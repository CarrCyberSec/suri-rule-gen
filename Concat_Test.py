#!/usr/bin/env python3 

import os
import argparse
import re
import logging


#output file
outfile = 'suri-rule-gen.rules'
# Header Variables
rule_action = "alert"
protocol = "ip"
source_ip = "any"
source_port = "any"
direction = "->"
dest_ip = "any"
dest_port = "any"
#option_variables
message= "!!!Describe The Rule Here!!!"
rev='rev:001'
sid='sid:000001'

#logging configuration 
logging.basicConfig(filename='suri-rule-gen.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^[\!]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\$HOME_NET|^\$EXTERNAL_NET|^\[|any|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}$|^\$EXT_NET")
port_pattern =  re.compile("^\d{1,6}|^\[\d{1,6}|^any|^!d{1,6}|^!\d{1,6}")
#These validation lists work
action_options = ['alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth']
proto_options = ['tcp', 'udp', 'icmp', 'ip', 'http', 'ftp', 'tls', 'smb', 'dns', 'dcerpc', 
                'ssh', 'smtp', 'imap', 'modbus', 'dnp3', 'enip', 'nfs', 'ike', 'krb5', 'ntp'
                'dhcp', 'rfb', 'rdp', 'snmp', 'tftp', 'sip', 'http2']
#Remove, no need for <>
direction_options =  ['->','<>']

parser =argparse.ArgumentParser()
parser.add_argument('--action', action="store", type=str, help="Use to set rule action - Default is alert")
parser.add_argument('--protocol', action="store", type=str, help="Use to set protocol.")
parser.add_argument('--sip', action="store", type=str, nargs='+', help="Use to set source IP for rule. Format examples: | 10.0.0.0 | 10.0.0.0/8 | !10.0.0.0 | [10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--srcport', action="store", type=str, nargs='+', help="Use to set the source port. Format exampels: | 80 | [80,81,82] | [8080:] | !80 | [1:80,![2,4]]")
parser.add_argument('--direction', action='store', type=str, help="Use to se the direction of the rule valid options inclde: ")
parser.add_argument('--dip', action="store", type=str, nargs='+', help="Use to set destination IP for rule. Format examples: | 10.0.0.0 | 10.0.0.0/8 | !10.0.0.0 |[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--destport', action="store", type=str, nargs='+', help="Use to set the destination port. Format exampels: 80 | [80,81,82] | [8080:] | !80 | [1:80,![2,4]]")
parser.add_argument('--message', action="store", type=str, nargs='+', help="Use to set a descriptive message about the rule.")
parser.add_argument('--meta', action="store", type=str, help="")
#parser.add_argument('--ttl', action="store", type=str, help="")
#parser.add_argument('--outfile', action="store", type=str, help="")
parser.add_argument('--rev', action="store", type=str, help="Use to specify Revision Number")
parser.add_argument('--sid', action="store", type=str, help="Use to specify Signature Identification.")
parser.add_argument('--content', action="store", type=str, help="Used to specificy payload content.")
parser.add_argument('--classtype', action="store,")
#turn cli args into arg.<argument>
args = parser.parse_args()

while True: 
    if args.action is not None: 
        if args.action.lower() in action_options:
            rule_action = args.action.lower()
            break
        else: 
            print("invalid selection")
            break
    else:
        print('no action selected')
        break
while True:
    if args.protocol is not None:
        if args.protocol.lower() in proto_options:
            protocol = args.protocol
            break
        else:
            print('invalid protocol selected valid protocol\n' + str(proto_options))
            break
    else:
        print('no protocol selected')
        break
while True: 
    if args.sip is not None: 
        test_source_ip = ' '.join(args.sip)
        if ip_pattern.match(test_source_ip) is not None:
            source_ip = test_source_ip
            break
        else:
            logging.log(logging.ERROR,'Invalid Source IP entered: ' + test_source_ip)
            print('!!!!!Invalid Source IP entered!!!!!')
            break
    else:
        print('no Source IP specified with --sip')
        break
while True: 
    if args.srcport is not None:
        
        test_source_port  = ' '.join(args.srcport)
        if port_pattern.match(test_source_port):
            source_port = test_source_port
            break
        else:
            print("The port was not entered in the correct format.")
            break
    else: 
        print('no Source port was specified with --srcport')
        break
while True: 
    if args.direction is not None: 
        if args.direction in direction_options:
            direction = args.direction
            break
        else: 
            print('invalid direction selected: please use \n \<\> or \-\> when using a bash terminal')
            break
    else: 
        print('no direction specified.')
        break
while True: 
    if args.dip is not None: 
        test_dest_ip = ' '.join(args.dip)
        if port_pattern.match(test_dest_ip):
            dest_ip = test_dest_ip
            break
        else:
            print('The destination IP was not in the correct format.')
            break
    else: 
        print('No Dest IP specified.')
        break
while True: 
    if args.destport is not None: 
        test_dest_port = ' '.join(args.destport)
        if port_pattern.match(test_dest_port):
            dest_port = test_dest_port
            break
        else:
            print('Destionation port entered incorrectly.')
        break
    else:
        print('no dest port specified')
        break
#to accept arg parse with a space, items need to be accepted as a list and then joined with ' ' to look like how they were entered
while True:
    if args.message is not None: 
        message = " ".join(args.message)
        break
    else:
        print("warning: no message specified. Please use --message to specify the rule message")
        break
while True: 
    if args.sid is not None: 
        sid = args.sid
        break
    else: 
        break
while True: 
    if args.rev is not None:
        rev = args.rev
        break
    else:
        break

#CONSTRUCTING THE RULE 
#message prefix should be present in all rules. 
message = ' (msg:"'+message+'"'
list_of_vars_in_header = [rule_action, protocol, source_ip, source_port, direction, dest_ip, dest_port] 
list_of_rule_options = [message, sid, rev]

new_rule_header = ' '.join(list_of_vars_in_header)
new_rule_options = '; '.join(list_of_rule_options) + ')'
new_rule = new_rule_header+new_rule_options

#REMOVE BEFORE SUBMISSION 
#print(new_rule_header)
#print(new_rule_options)
#print(new_rule)

#Check if file exists and create or write to it
if os.path.exists(outfile):
    f = open(outfile, "a")
    f.write(new_rule + '\n')
else:
    f = open(outfile, "x")
    f.writelines("%s\n" % new_rule)