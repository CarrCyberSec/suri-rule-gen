#!/usr/bin/env python3 
#   Automating Steps of Suricata Rule-Writing
#   by
#   Brian T. Carr
#   A Capstone Submitted to the Faculty of
#   Utica College
#   August 2021
#   in Partial Fulfillment of the Requirements for the Degree of
#   Master of Science in Cybersecurity
#
#   email:  brian@briantcarr.com
#   website:    briancarr.org


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


list_of_vars_in_options = [rev,sid]


#logging configuration 
logger = logging.getLogger('suri-rule-gen.py')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('suri-rule-gen.log')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:S')
ch.setFormatter(formatter)
fh.setFormatter(formatter)
# add the handlers to logger
logger.addHandler(ch)
logger.addHandler(fh)


# 'application' code


#Regular Expressions for input validation 
ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^[\!]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\$HOME_NET|^\$EXTERNAL_NET|^\[|any|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}$|^\$EXT_NET")
port_pattern =  re.compile("^\d{1,6}|^\[\d{1,6}|^any|^!d{1,6}|^!\d{1,6}")
# Lists for Input Validation 
action_options = ['alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth']
proto_options = ['tcp', 'udp', 'icmp', 'ip', 'http', 'ftp', 'tls', 'smb', 'dns', 'dcerpc', 
                'ssh', 'smtp', 'imap', 'modbus', 'dnp3', 'enip', 'nfs', 'ike', 'krb5', 'ntp'
                'dhcp', 'rfb', 'rdp', 'snmp', 'tftp', 'sip', 'http2']
direction_options =  ['->','<>']
target_options = ['src_ip', 'dest_ip']
ipopts_options = ['rr', 'eol', 'nop', 'ts', 'sec', 'esec', 'lsrr', 'ssrr', 'satid', 'any']
# CLI arguments 


parser =argparse.ArgumentParser()
parser.add_argument('--action', action="store", type=str, help="Use to set rule action - Default is alert")
parser.add_argument('--protocol', action="store", type=str, help="Use to set protocol.")
parser.add_argument('--sip', action="store", type=str, nargs='+', help="Use to set source IP for rule. Format examples: | 10.0.0.0 | 10.0.0.0/8 | !10.0.0.0 | [10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--srcport', action="store", type=str, nargs='+', help="Use to set the source port. Format exampels: | 80 | [80,81,82] | [8080:] | !80 | [1:80,![2,4]]")
parser.add_argument('--direction', action='store', type=str, help="Use to se the direction of the rule valid options inclde: ")
parser.add_argument('--dip', action="store", type=str, nargs='+', help="Use to set destination IP for rule. Format examples: | 10.0.0.0 | 10.0.0.0/8 | !10.0.0.0 |[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")
parser.add_argument('--destport', action="store", type=str, nargs='+', help="Use to set the destination port. Format exampels: 80 | [80,81,82] | [8080:] | !80 | [1:80,![2,4]]")
parser.add_argument('--message', action="store", type=str, nargs='+', help="Use to set a descriptive message about the rule.")
parser.add_argument('--meta', action="store", nargs='+', type=str, help="Used to set metadata variables. Be careful with formatting. sample format: --meta key value  | --meta key value, key value")
parser.add_argument('--ttl', action="store", type=str, help="Use to set TTL value. Format: number")
parser.add_argument('--outfile', action="store", type=str, help="used to specify a file to use instead of suri-rule-gen.rules. MUST END IN .rules." )
parser.add_argument('--rev', action="store", type=str, help="Use to specify Revision Number.")
parser.add_argument('--sid', action="store", type=str, help="Use to specify Signature Identification.")
parser.add_argument('--content', action="store", type=str, nargs='+', help="Used to specificy payload content.")
parser.add_argument('--classtype', action="store", type=str, help="Use to set classtype.")
parser.add_argument('--gid', action="store", type=str, help="Use to set group ID.")
parser.add_argument('--urlref', action="store", type=str, help="Used to set URL reference. Format: format.com")
parser.add_argument('--cveref', action="store", type=str, help="Use to set CVE reference. Format: CVE-2021-1234")
parser.add_argument('--priority', action="store", type=str, help="Use to set the rule priorty. Format: 1")
parser.add_argument('--ja3', action="store", type=str, help="Use to set JA3 hash value, JA3 strings require md5 hashing.")
parser.add_argument('--ja3s', action="store", type=str, help="Use to set JA3S hash value, JA3S strings require md5 hashing.")
parser.add_argument('--target', action="store", type=str, help="Use to set rule target.")
parser.add_argument('--ipopts', action="store", type=str, help="Use to set IP Option.")
parser.add_argument('--geoip', action="store", type=str, help="used to set Geo IP value.")
parser.add_argument('--fragbits', action="store", type=str, help="Use to set fragbit values")
parser.add_argument('--fragoffset', action="store", type=str, help="Use to set fragoffset values")
parser.add_argument('--tos', action="store", type=str, help="use to set IP header TOS value.")
parser.add_argument('--seq', action="store", type=str, help="Use to set TCP sequence number.")
parser.add_argument('--tlssubject', action="store", type=str, help="use to tls cert subject")
parser.add_argument('--tlsissuer', action="store", type=str, help="Use to set tls issuer value")
parser.add_argument('--tlsserial', action="store", type=str, help='Use to set tls serial number')
parser.add_argument('--tlsfingerprint', action="store", type=str, help="use to set tls cert SHA1 fingerprint")
parser.add_argument('--pcre', action="store", nargs='+', type=str, help="use to set a Perl Compatible Regular Expresion value.")
parser.add_argument('--sshproto', action="store", type=str, help="use to set ssh protocol version")
parser.add_argument('--sshsoftware', action="store", type=str, help="use to set ssh software value")
parser.add_argument('--hassh', action="store", type=str, help="use to set hassh value for client")
parser.add_argument('--hasshstring', action="store", type=str, help="use to set hassh string value for client")
parser.add_argument('--hasshserver', action="store", type=str, help="use to set hassh value for server")
parser.add_argument('--hasshserverstring', action="store", type=str, help="use to set hassh string value for server")
logger.info('**********NEW RULE BEING GENERATED**************')
#turn cli args into arg.<argument>
args = parser.parse_args()


#   Set rule sid and rev value, set first to populate log properly. 
while True: 
    if args.sid is not None: 
        sid = 'sid:'+args.sid
        list_of_vars_in_options[-2]=sid
        break
    else: 
        logger.warning('No sid value set!!! Please ensure that no rules have duplicate sid values.')
        break
while True: 
    if args.rev is not None:
        rev = 'rev:'+args.rev
        list_of_vars_in_options[-1]=rev
        break
    else:
        logger.warning('No rev value set!!! Please ensure that there are no duplicate rev values with a common sid value.')
        break
generated_rule_sid = 'Generated rule sid ' + sid + ' ' + rev + ' - '
#While loops to test the presence of CLI arguements
while True: 
    if args.action is not None: 
        if args.action.lower() in action_options:
            rule_action = args.action.lower()
            logger.info(generated_rule_sid +' Rule action set: ' + rule_action)
            break
        else: 
            print("invalid selection")
            logger.error(generated_rule_sid + ' Invalid action entered: ' + args.action)
            break
    else:
        #print('no action selected')
        logger.info(generated_rule_sid+' No action value entered.')
        break
while True:
    if args.protocol is not None:
        if args.protocol.lower() in proto_options:
            protocol = args.protocol
            logger.info(generated_rule_sid +'Rule protocol set: ' + protocol)
            break
        else:
            print('invalid protocol selected valid protocol\n' + str(proto_options))
            logger.error(generated_rule_sid + ' invalid protocol value entered: ' + args.protcol )
            break
    else:
       # print('no protocol selected')
        logger.info(generated_rule_sid + ' no protocol value entered.') 
        break
while True: 
    if args.sip is not None: 
        test_source_ip = ' '.join(args.sip)
        if ip_pattern.match(test_source_ip) is not None:
            source_ip = test_source_ip
            break
        else:
            logger.error('Invalid Source IP entered: ' + test_source_ip)
            print('!!!!!Invalid Source IP entered!!!!!')
            logger.error(generated_rule_sid+ ' invalid source IP entered: ' )
            break
    else:
        #print('no Source IP specified with --sip')
        break
while True: 
    if args.srcport is not None:
        test_source_port  = ' '.join(args.srcport)
        if port_pattern.match(test_source_port):
            source_port = test_source_port
            logger.info(generated_rule_sid + ' source port value:' + source_port)
            break
        else:
            print("The port was not entered in the correct format.")
            logger.error(generated_rule_sid+ ' invalid source port entered')
            break
    else: 
       # print('no Source port was specified with --srcport')
        logger.info(generated_rule_sid + 'no value source port value entered.')
        break
while True: 
    if args.direction is not None: 
        if args.direction in direction_options:
            direction = args.direction
            logger.info(generated_rule_sid + 'direction set to:' + args.direction)
            break
        else: 
            print('invalid direction selected: please use \n \<\> or \-\> when using a bash terminal')
            logger.error(generated_rule_sid + ' invalid rule direction ' + args.direction )
            break
    else: 
        logger.info(generated_rule_sid + 'no rule driection specified.')
        break
while True: 
    if args.dip is not None: 
        test_dest_ip = ' '.join(args.dip)
        if ip_pattern.match(test_dest_ip):
            dest_ip = test_dest_ip
            logger.info(generated_rule_sid + 'dest ip set to: ' + dest_ip)
            break
        else:
            print('The destination IP was not in the correct format.')
            logging.error(generated_rule_sid + 'destination IP set to invalid value: '  + test_dest_ip)
            break
    else: 
        #print('No Dest IP specified.')
        logging.info(generated_rule_sid+ 'No dest ip specified, using any. ')
        break
while True: 
    if args.destport is not None: 
        test_dest_port = ' '.join(args.destport)
        if port_pattern.match(test_dest_port):
            dest_port = test_dest_port
            logger.info('Generated rule sid:' + sid + 'dest port set to:' + dest_port)
            break
        else:
            logger.error('Generated rule sid:' + sid + 'dest port entered incorrectly: ' + dest_port)
            print('Destionation port entered incorrectly.')
        break
    else:
        #print('no dest port specified')
        logger.info(generated_rule_sid + 'no dest port specified specified.')
        break
#Rule options start here
while True:
    if args.message is not None: 
        message = " ".join(args.message)
        logger.info(generated_rule_sid + 'Message value set: ' + message)
        break
    else:
        logger.warning(generated_rule_sid + ' No message value set!')
        break

while True:
    if args.meta is not None: 
        meta_var_constructor = " ".join(args.meta)
        meta_var = 'metadata: ' + meta_var_constructor 
        logger.info(generated_rule_sid + ' meta var set to: ' + meta_var )
        list_of_vars_in_options.insert(0, meta_var)
        break
    else:
        break
while True: 
    if args.ttl is not None:
        ttl = 'ttl:' + args.ttl 
        list_of_vars_in_options.insert(0, ttl)
        logger.info(generated_rule_sid + ' ttl value set: ' + ttl) 
        break
    else:
        break
while True:
    if args.content is not None:
        content_constructor = ' '.join(args.content)
        content = 'content:' + content_constructor 
        list_of_vars_in_options.insert(0, content)
        logger.info(generated_rule_sid+ ' content set to: ' + content)
        break
    else:
        break
while True:
    if args.classtype is not None:
        classtype = 'classtype:'+args.classtype
        list_of_vars_in_options.insert(0, classtype)
        logger.info(generated_rule_sid + ' classtype set to:' + classtype)
        break
    else:
        break
while True:
    if args.urlref is not None:
        ref = 'reference: url, ' + args.urlref
        list_of_vars_in_options.insert(0, ref)
        logger.info(generated_rule_sid + ' refernce set to: ' + ref)
        break
    else:
        break
while True:
    if args.cveref is not None: 
        ref = 'reference: cve, ' + args.cveref
        list_of_vars_in_options.insert(0, ref)
        logger.info(generated_rule_sid + 'CVE referenced: ' + ref)
        break
    else:
        break
while True: 
    if args.priority is not None: 
        priority = 'priority:'+args.priority
        list_of_vars_in_options.insert(0, priority)
        logger.info(generated_rule_sid + 'priority set to: ' + priority)
        break
    else:
        break
while True: 
    if args.ja3 is not None: 
        ja3 = 'ja3.hash; content:"' + args.ja3 + '"'
        list_of_vars_in_options.insert(0, ja3)
        logger.info(generated_rule_sid + 'ja3 value set to: ' + ja3)
        break
    else:
        break
while True: 
    if args.ja3s is not None:
        ja3s = 'ja3s.hash; content:"' + args.ja3s + '"'
        list_of_vars_in_options.insert(0, ja3s)
        logger.info(generated_rule_sid + 'ja3s value set to: ' + ja3s)
        break
    else:
        break
while True:
    if args.target is not None:
        if args.target == 'src_ip' or 'dest_ip':
            target = 'target:' + args.target.lower()
            list_of_vars_in_options.insert(0, target)
            break
        else:
            logger.error(generated_rule_sid + 'Invalid target value entered:' + args.target)
            break
    else:
        break
while True:
    if args.ipopts is not None:
        if args.ipopts.lower in ipopts_options:
            ipopts = 'ipopts: ' + args.ipopts.lower()
            list_of_vars_in_options.insert(0, ipopts)
            break
        else:
            logger.error(generated_rule_sid + 'Invalid ipopts value entered: ' + args.ipopts)
            break
    break
while True: 
    if args.geoip is not None:
        geoip = args.geoip.lower()
        list_of_vars_in_options.insert(0, geoip)
        break
    else:
        break
while True:
    if args.fragbits is not None:
        fragbits = args.fragbits.lower()
        break
    else:
        break
while True:
    if args.fragoffset is not None:
        fragoffset = args.fragoffset.lower()
        break
    else:
        break
while True:
    if args.tos is not None: 
        tos = args.tos
    else:
        break
while True:
    if args.seq is not None:
        seq = args.seq
    else:
        break
while True:
    if args.pcre is not None: 
        pcre = " ".join(args.pcre)
        break
    else:
        break
#Test if a different outfile should be used
while True:
    if args.outfile is not None:
        outfile =  args.outfile
        logger.info(generated_rule_sid + 'outfile set to: ' + outfile)
        break
    else:
        break


#   Constructing the final rule string 
list_of_vars_in_header = [ rule_action, protocol, source_ip, source_port, direction, dest_ip, dest_port] 
message_constructor = ' (msg:"' + message + '"'
list_of_vars_in_options.insert(0,message_constructor)
new_rule_header = ' '.join(list_of_vars_in_header)
new_rule_options = '; '.join(list_of_vars_in_options) + ';)'
new_rule = new_rule_header+new_rule_options
print(new_rule)

#   Check if outfile exists and create or write to it
if os.path.exists(outfile):
    f = open(outfile, "a")
    f.write(new_rule + '\n')
else:
    f = open(outfile, "x")
    f.writelines("%s\n" % new_rule)