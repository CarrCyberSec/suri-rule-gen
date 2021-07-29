#!/usr/bin/env python3
#This file contains the suri_rule_function class which contains 



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
action_options = ['alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth']
proto_options = ['tcp', 'udp', 'icmp', 'ip', 'http', 'ftp', 'tls', 'smb', 'dns', 'dcerpc', 
                'ssh', 'smtp', 'imap', 'modbus', 'dnp3', 'enip', 'nfs', 'ike', 'krb5', 'ntp'
                'dhcp', 'rfb', 'rdp', 'snmp', 'tftp', 'sip', 'http2']
class suri_rule_functions:
    def validate_action(self):
        global rule_action
        global action_options
        while True:
            if self.lower() in action_options:
                rule_action = self.lower()
                break
            else:
                print('did not work')
                break
        return rule_action
    def validate_protocol(self):
        global protocol
        global proto_options
        while True:
            if self.lower() in proto_options:
                protocol = self.lower()
                return protocol
                break
            else:
                print('did not work')
                break
