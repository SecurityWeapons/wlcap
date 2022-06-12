import time
import sys
from scapy.all import *
helpfile = """

--thread | First wlcap argument  | That selecting the sniffing thread from wlcap
--crypto | Second wlcap argument | Type Scapy for a scapy output type None for wlcap output type True for the cryptography packets
--filter | Third wlcap argument  | You must dont type it when you dont want to have a filter when you would to have type a filter

"""

try:
	if sys.argv[1] == '--thread':
		thread = int(sys.argv[2])
		if sys.argv[3] == '--crypto':
			crypto = sys.argv[4]
		else:
			print(helpfile)
			sys.exit()
		try:
			if sys.argv[5] == '--filter':
				filting = int(sys.argv[6])
			else:
				filting = None
		except:
			filting = None
	else:
		print(helpfile)
		sys.exit()
except:
	print(helpfile)
	sys.exit()
if crypto == 'None':
	if filting == None:
		while True:
			sniff(count=thread, store=True, prn=lambda x: x.sprintf("[+] [wlcap] Address: {IP:%IP.src% Sending Packets to >>> %IP.dst%  -  DST: %Ether.dst% SRC: %Ether.src%}"))
	else:
		while True:
			sniff(count=thread, filter=filting, store=True, prn=lambda x: x.sprintf("[+] [wlcap] Address: {IP:%IP.src% Sending Packets to >>> %IP.dst%  -  DST: %Ether.dst% SRC: %Ether.src%}"))
elif crypto == 'Scapy':
	if filting == None:
		while True:
			sniff(count=thread, store=True, prn=lambda x: x.summary())
	else:
		while True:
			sniff(count=thread, filter=filting, store=True, prn=lambda x: x.summary())
elif crypto == 'True':
	if filting == None:
		while True:
			sniff(count=thread, store=True, prn=lambda x: hexdump(x))
	else:
		while True:
			sniff(count=thread, filter=filting, store=True, prn=lambda x: hexdump(x))