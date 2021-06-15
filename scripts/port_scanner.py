#r00t-n0v4
#12/26/2020

from socket import * 
import os


print ('-' *60)
print ('░██████╗░█████╗░░█████╗░███╗░░██╗███╗░░██╗███████╗██████╗░')
print ('██╔════╝██╔══██╗██╔══██╗████╗░██║████╗░██║██╔════╝██╔══██╗')
print ('╚█████╗░██║░░╚═╝███████║██╔██╗██║██╔██╗██║█████╗░░██████╔╝')
print ('░╚═══██╗██║░░██╗██╔══██║██║╚████║██║╚████║██╔══╝░░██╔══██╗')
print ('██████╔╝╚█████╔╝██║░░██║██║░╚███║██║░╚███║███████╗██║░░██║')
print ('╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝')
print ('-' *60)
print ('Ports & Meaning')
print ('-' *60)
print ('[+] 20	File Transfer Protocol (FTP) Data Transfer')
print ('[+] 21	File Transfer Protocol (FTP) Command Control')
print ('[+] 22	Secure Shell (SSH) Secure Login')
print ('[+] 23	Telnet remote login service, unencrypted text messages')
print ('[+] 25	Simple Mail Transfer Protocol (SMTP) E-mail routing')
print ('[+] 53	Domain Name System (DNS) service')
print ('[+] 67, 68	Dynamic Host Configuration Protocol (DHCP)')
print ('[+] 80	Hypertext Transfer Protocol (HTTP) used in the World Wide Web')
print ('[+] 110	Post Office Protocol (POP3)')
print ('[+] 119	Network News Transfer Protocol (NNTP)')
print ('[+] 123	Network Time Protocol (NTP)')
print ('[+] 143	Internet Message Access Protocol (IMAP) Management of digital mail')
print ('[+] 161	Simple Network Management Protocol (SNMP)')
print ('[+] 194	Internet Relay Chat (IRC)')
print ('[+] 443	HTTP Secure (HTTPS) HTTP over TLS/SSL')
print ('-' *60)

if __name__ == '__main__':
	target = input('Target: ')
	targetIP = gethostbyname(target)

	#scan reserved ports
	for i in range(20, 1025):
		s = socket(AF_INET, SOCK_STREAM)

		result = s.connect_ex((targetIP, i))
		write_result = str(result)
		if(result == 0) :
			print ('[+]Port %d: Open' % (i,))
			with open(target+'.txt', 'w') as wf:
				wf.write(write_result)
		s.close()