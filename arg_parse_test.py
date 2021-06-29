#!/usr/bin/env python3
#
# A python script to automatically generate Suricata compatible rules
# Written by Brian T. Carr.
# Copyright (2021) Brian T. Carr
# Version 0.0.1 (Beta)

import argparse
import logging
import os.path

logging.basicConfig(filename='suri-rule-gen.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

outfile = "suri-rule-gen.rules"

# Header Variables
action = "alert"
protocol = "ip"
source_ip = "any"
source_port = "any"
direction = "<>"
dest_ip = "any"
dest_port = "any"

#validation lists
action_options = ['alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth']
proto_options = ['tcp', 'udp', 'icmp', 'ip', 'http', 'ftp', 'tls', 'smb', 'dns', 'dcerpc', 
                'ssh', 'smtp', 'imap', 'modbus', 'dnp3', 'enip', 'nfs', 'ike', 'krb5', 'ntp'
                'dhcp', 'rfb', 'rdp', 'snmp', 'tftp', 'sip', 'http2']
direction_options =  ['->','<>']

parser = argparse.ArgumentParser()

#argparse values
parser.add_argument('--action', action="store", type=str, help="Use to set rule action - Default is alert")
parser.add_argument('--protocol', action="store", type=str, help="Use to set rule protocol.")
parser.add_argument('--source', action="store", type=str, help="Use to set source IP for rule. Format examples:\n10.0.0.0\n10.0.0.0/8\n!10.0.0.0\n[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--sourceport', action="store", type=str, help="Use to set the source port. Format exampels:\n80\n[80,81,82]\n[8080:]\n!80\n[1:80,![2,4]]")
parser.add_argument('--direction', action='store', type=str, help="Use to se the direction of the rule valid options inclde: " + str(direction_options))
parser.add_argument('--dest', action="store", type=str, help="Use to set destination IP for rule. Format examples:\n10.0.0.0\n10.0.0.0/8\n!10.0.0.0\n[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--destport', action="store", type=str, help="Use to set the source port. Format exampels:\n80\n[80,81,82]\n[8080:]\n!80\n[1:80,![2,4]]")

args = parser.parse_args()

#Header input validation 
if args.action is not None:
    if args.action.lower().strip() in action_options:
        action = args.action
else:
    print('No action was included: using alert')
if args.protocol is not None:
    if args.protocol.lower().strip() in proto_options:
        protocol = args.protocol
else:
    print('No protocl was included: using ip')
if args.source is not None:
    source_ip = args.source
else:
    print('No Source IP was included: using any')
if args.sourceport is not None:
    source_port = args.sourceport
else:
    print('No Source Port was included: using any')
if args.direction is not None:
    direction = str(args.direction)
else:
    print('No direction was included: using ->')
if args.dest is not None:
    dest_ip = args.dest
else:
    print('No destionation IP included: using any')
if args.destport is not None:
    dest_port = args.destport
else:
    print('No Destionation Port included: using any')

print(args.action)
print(args.protocol)
print(args.source)
print(args.sourceport)
print(args.direction)
print(args.dest)
print(args.destport)


new_sig = [action, protocol, source_ip, source_port, direction, dest_ip, dest_port]
rule_header = ' '.join(new_sig)
rule_options = '(' + ')'
print(' '.join(new_sig))
new_rule = ' '.join(new_sig) 
new_rule = new_rule + rule_options 

#Check if file exists and create or write to it
if os.path.exists(outfile):
    f = open(outfile, "a")
    f.write(new_rule)
else:
    f = open(outfile, "x")
    f.writelines("%s\n" % new_rule)

#add logging
#File handling
#   check if exiss write it if does create if not
#   Regular Expressions for 
#output one siganature per line
#