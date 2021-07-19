import argparse
import os
import re

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

message='New Signature for the newest threat'
new_rule =  action + ' ip any any <> any any'
new_rule_options = '(msg:"'+str(message)+'";sid:000001;rev:001)'


parser = argparse.ArgumentParser
parser.add_argument('--message', action="store", type=str, help="use to set message")
args = parser.parse_args()

while True:
    if args.action is not None:
        if args.action in action_options:
            action = args.action 
            break
        else: 
            print('invalid selection, valid options include:\n' + str(action_options))
            break
    else:
        print('No action selected')

while True:    
    if args.message is not None: 
        message = args.message
        print(args.message)
        break
    else:
        print("Warning:No Message Set")
        break

new_rule = new_rule + new_rule_options
print(new_rule)