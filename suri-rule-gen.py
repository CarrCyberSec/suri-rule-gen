#!/usr/bin/env python3
#
# A python script to automatically generate Suricata compatible rules
# Written by Brian T. Carr.
# Copyright (2021) Brian T. Carr
# Version 0.0.1 (Beta)

import argparse
import logging

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
def validate_action():
        if args.action is not None:
            if args.action.lower() in action_options:
                action = args.action.lower()
                return action
            else:
                print("Invalid Action Option Entered.\n valid options include:\n" + str(action_options))
        else:
            print('No arugment action entered: using alert')
def validate_protocol(protocol):
    while True:
        if args.protocol is not None:
            protocol = args.protocol.lower()
            return protocol
        else:
            print("Didn't enter a protocol")
def validate_source_ip():
    if args.source is not None:
        source_ip = args.source
        return source_ip
    else:
        print("No Source IP entered: using any")
def validate_source_port():
    if args.sourceport is not None:
        source_port = args.sourceport
        return source_port
    else:
        print('No Source Port entered: using any')
def validate_direction():
    if args.direction is not None:
        if args.direction in direction_options:
            direction = args.direction
            return direction
        else:
            print("The direction you selected was not valid.\n valid options include: " + str())
    else:
        print('No direction was entered: using ->')
def validate_dest_ip():
    if args.dest is not None:
        dest_ip = args.dest
        return dest_ip
    else:
        print('No destination IP was entered. using: any')
def validate_dest_port():
    if args.dest_port is not None:
        dest_port = args.dest_port
        return dest_port
    else:
        print('No destination port specified: uisng any')


validate_action()
validate_protocol()
validate_source_ip()
validate_source_port()
validate_direction()
validate_dest_ip()
validate_dest_port()

new_rule_header_list = [ action, protocol, source_ip, source_port, direction, dest_ip, dest_port]
#new_rule_header = action + " " + source_ip + " " + source_port + " " +  direction + " " + dest_ip + " " + dest_port
new_rule_header = " ".join(new_rule_header_list)
#new_rule_options = '(' + 'msg:'+ message + ')'
#new_rule = new_rule_header + " " + new_rule_options
print(new_rule_header)

