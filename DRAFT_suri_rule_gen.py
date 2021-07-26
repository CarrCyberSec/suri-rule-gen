#!/usr/bin/env python3
#
# A python script to automatically generate Suricata compatible rules
# Written by Brian T. Carr.
# Copyright (2021) Brian T. Carr
# Version 0.0.1 (Beta)

import argparse
import logging
import os

logging.basicConfig(filename='suri-rule-gen.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

outfile = "suri-rule-gen.rules"

# Header Variables
action = "alert"
protocol = "ip"
source_ip = "any"
source_port = "any"
direction = "->"
dest_ip = "any"
dest_port = "any"

action_options = ['alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth']
proto_options = ['tcp', 'udp', 'icmp', 'ip', 'http', 'ftp', 'tls', 'smb', 'dns', 'dcerpc', 
                'ssh', 'smtp', 'imap', 'modbus', 'dnp3', 'enip', 'nfs', 'ike', 'krb5', 'ntp'
                'dhcp', 'rfb', 'rdp', 'snmp', 'tftp', 'sip', 'http2']
direction_options =  ['->','<>']

parser = argparse.ArgumentParser()

parser.add_argument('--action', action="store", type=str, help="Use to set rule action - Default is alert")
parser.add_argument('--protocol', action="store", type=str, help="Use to set rule protocol.")
parser.add_argument('--source', action="store", type=str, help="Use to set source IP for rule. Format examples:\n10.0.0.0\n10.0.0.0/8\n!10.0.0.0\n[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--sourceport', action="store", type=str, help="Use to set the source port. Format exampels:\n80\n[80,81,82]\n[8080:]\n!80\n[1:80,![2,4]]")
parser.add_argument('--direction', action='store', type=str, help="Use to se the direction of the rule valid options inclde: " + str(direction_options))
parser.add_argument('--dest', action="store", type=str, help="Use to set destination IP for rule. Format examples:\n10.0.0.0\n10.0.0.0/8\n!10.0.0.0\n[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--dest-port', action="store", type=str, help="Use to set the source port. Format exampels:\n80\n[80,81,82]\n[8080:]\n!80\n[1:80,![2,4]]")

args = parser.parse_args
new_rule_header_list = []

while True:
    if args.action is not None:
        if args.action.lower() in action_options:
            action = args.action.lower()
            break
        else:
            print("Invalid Action Option Entered.\n valid options include:\n" + str(action_options))
            break
    else:
        print('No arugment action entered: using alert')
        break
while True:
    if args.protocol is not None:
        protocol = args.protocol.lower()
        break
    else:
        print("Didn't enter a protocol")
        break
while True:
    if args.source is not None:
        source_ip = args.source
        break
    else:
        print("No Source IP entered: using any")
        break
while True:
    if args.sourceport is not None:
        source_port = args.sourceport
        break
    else:
        print('No Source Port entered: using any')
        break
"""while True:
    if args.direction is not None:
        if args.direction in direction_options:
            direction = args.direction
            break
        else:
            print("The direction you selected was not valid.\n valid options include: " + str())
            break
    else:
        print('No direction was entered: using ->')
        break"""
while True:
    if args.dest is not None:
        dest_ip = args.dest
        break
    else:
        print('No destination IP was entered. using: any')
        break
while True: 
    if args.dest_port is not None:
        dest_port = args.dest_port
        break
    else:
        print('No destination port specified: uisng any')
        break

new_rule_header_list = [ action, protocol, source_ip, source_port, direction, dest_ip, dest_port]
#new_rule_header = action + " " + source_ip + " " + source_port + " " +  direction + " " + dest_ip + " " + dest_port
new_rule_header = " ".join(new_rule_header_list)
#new_rule_options = '(' + 'msg:'+ message + ')'
#new_rule = new_rule_header + " " + new_rule_options
print(new_rule_header)

if os.path.exists(outfile):
    f = open(outfile, "a")
    f.write(new_rule_header)
else:
    f = open(outfile, "x")
    f.writelines("%s\n" % new_rule_header)