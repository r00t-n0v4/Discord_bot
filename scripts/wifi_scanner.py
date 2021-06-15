#Python wifi scanner
#find devices on wifi
#add to Bagley when possible

import scapy.all as scapy
import re

#IPV4 address pattern
ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
#get the address range to ARP
while True:
	ip_add_range_pattern_entered = input("\nPleaser enter the ip address and range that you want to scan (ex. 192.168.0.1/24): ")
	if ip_add_range_pattern.search(ip_add_range_pattern_entered):
		print(f"{ip_add_range_pattern_entered} is a valid ip range")
		break
		
#try ARPing the ip address range
arp_result = scapy.arping(ip_add_range_pattern_entered)