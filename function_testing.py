#Function testing

from suri_rules import suri_rule_functions


from suri_rules import suri_rule_functions
import argparse
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

logging.basicConfig(filename='suri-rule-gen.log', filemode='a+', format='%(asctime)s-%(levelname)s-%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
rule_action = "alert"
action_options = ['alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth']

parser = argparse.ArgumentParser()
parser.add_argument('--protocol', action="store", type=str, help="Use to set protocol.")
parser.add_argument('-a', '--action', action="store", type=str, help="Use to set rule action - Default is alert")
args = parser.parse_args()
print(args)

suri_rule_functions.validate_action(args.action)
suri_rule_functions.validate_protocol(args.protocol)
print(args.action)
print(args.protocol)
print(rule_action)
print(protocol)