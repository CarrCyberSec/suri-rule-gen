#!/usr/bin/env python3

import argparse
import re

dip = 'any'


ip1 = '1.1.1.1'
ip2 = '[1.1.1.1, 2.2.2.2]'
ip3 = '!10.0.0.1'
ip4 = '$HOME_NET'
ip5 = '[10.10.0.0/24, !10.10.0.1]'
ip6 = '10.0.0.0/8'
ip7 = 'any'


port1 = "90"
port2 = "any"
port3 = "!443"
port5 = "[80:100,!99]"
port6 = "[1:80,![2,4]]"

parser = argparse.ArgumentParser()
parser.add_argument('--dip', action="store", type=str, nargs='+', help="Use to set destination IP for rule. Format examples: | 10.0.0.0 | 10.0.0.0/8 | !10.0.0.0 |[10.0.0.0, 192.168.0.0/24, !172.16.0.0]")

args = parser.parse_args()

pattern  = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^[\!]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\$HOME_NET|^\[|any|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}$|^\$EXT_NET")
pattern_ports = re.compile("^\d{1,6}|^\[\d{1,6}|^any|^!d{1,6}|^!\d{1,6}")
simple_pattern = re.compile("^\d{1,6}")

#result1 = pattern.match(ip1)


#while True:
 #   if args.dip is not None:
  #      fixed_dip = ''.join(args.dip)
   #     print(fixed_dip)
    #    if pattern.match(fixed_dip):
     #       print('holy fuck it worked')
      #      break
       # else:
        #    print('the mattern did not match')
  #     # break
    #else:
     #   break
#if result1 is not None:
  #  print(result1)
###result2 = pattern.match(ip2)
#result3 = pattern.match(ip3)
#result4 = pattern.match(ip4)
#result5 = pattern.match(ip5)
#result6 = pattern.match(ip6)
#result7 = pattern.match(ip7)


#print(result1)
#print(result2)
#print(result3)
#print(result4)
#print(result5)
#print(result6)
#print(result7)

port_test1 = pattern_ports.match(port1)
port_test2 = pattern_ports.match(port2)
port_test3 = pattern_ports.match(port3)
port_test4 = pattern_ports.match(port6)
port_test5 = pattern_ports.match(port5)
port_test6 = simple_pattern.match(port1)
print(port_test1)
print(port_test2)
print(port_test3)
print(port_test4)
print(port_test5)
print(port_test6)