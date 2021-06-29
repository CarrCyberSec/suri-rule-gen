


import os
import argparse
import re


# Header Variables
action = "alert"
protocol = "ip"
source_ip = "any"
source_port = "any"
direction = "<>"
dest_ip = "any"
dest_port = "any"
#option_variables
message= "Test123"

list_of_vars_in_header = [action, protocol, source_ip, direction, dest_ip, dest_port]

parser =argparse.ArgumentParser()
parser.add_argument('--action', action="store", type=str, help="Use to set rule action - Default is alert")
parser.add_argument('--source', action="store", type=str, help="Use to set source IP for rule. Format examples:\n10.0.0.0\n10.0.0.0/8\n!10.0.0.0\n[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--sourceport', action="store", type=str, help="Use to set the source port. Format exampels:\n80\n[80,81,82]\n[8080:]\n!80\n[1:80,![2,4]]")
#parser.add_argument('--direction', action='store', type=str, help="Use to se the direction of the rule valid options inclde: " + str(dir_options_list))
parser.add_argument('--dest', action="store", type=str, help="Use to set destination IP for rule. Format examples:\n10.0.0.0\n10.0.0.0/8\n!10.0.0.0\n[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--dest-port', action="store", type=str, help="Use to set the source port. Format exampels:\n80\n[80,81,82]\n[8080:]\n!80\n[1:80,![2,4]]")
parser.add_argument('--message', action="store", type=str, help="")
parser.add_argument('--meta', action="store", type=str, help="")
#parser.add_argument('--ttl', action="store", type=str, help="")
#parser.add_argument('--outfile', action="store", type=str, help="")

args = parser.parse_args()


new_rule_header = ' '.join(list_of_vars_in_header)
new_rule_options = '(msg:"'+message+'";)'
new_rule = new_rule_header+new_rule_options

print(new_rule_header)
print(new_rule_options)
print(new_rule)