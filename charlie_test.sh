#Test commands for Charlie
# source suri-rule-gen/bin/active 

printf "\n\n\n INITIATING TEST FOR CHARLIE\n\n\n"
python3 suri-rule-gen.py --action drop --destport 445 --srcport 445 --message this is the first test --ttl 64 --sid 0001 --rev 002
python3 suri-rule-gen.py --dip 10.0.0.0/8 --message this is the second test --sid 0002
python3 suri-rule-gen.py --dip 127.0.0.0 --message this is the third test --ja3 651682e68c00b76e5279aac3918b887f --sid 0003 --rev 003
python3 suri-rule-gen.py --sip 192.168.0.0/24 --destport 53 --message This is the fourth  rule test --destport 80 --ja3s 1fafbc9531a0ce4cd026ace5121b4982 --sid 0004
python3 suri-rule-gen.py --sip 172.16.0.0/16 --destport 433 --message this is the fifth rule test  --ipopts nop --urlref briancarr.org --sid 0005
python3 suri-rule-gen.py --message this is the sixth rule test --ttl 255 --sid 0006
python3 suri-rule-gen.py --message this is the seventh rule test --classtype trojan-activity --sid 0007 --rev 123
python3 suri-rule-gen.py --message test of sshproto --sshproto didthiswork --sid 0008 --rev 001

echo "*****printing rule file*****"
echo "*"
echo "*"
echo "*" 
cat suri-rule-gen.rules  
echo "*"
echo "*"
echo "*****printing log file*****"
tail -20 suri-rule-gen.log