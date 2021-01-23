
import sys

try:

	import os

	from scapy.all import *

	import threading

except Exception as e:

	print(">> [!] Error Encountered: " + str(e))

	sys.exit()


os.system("clear")


#MAC_Address_Set = set()

logger = open("logs.txt", "w")

station_MAC_Addresses = set()

station_MAC_Addresses2 = set()




def sniffer(pkt):

	if(pkt.haslayer(Dot11) and pkt.haslayer(Dot11Auth)):

		if(pkt['Dot11'].addr2 in station_MAC_Addresses):

			pass

		else:

			output = (">> [+] This MAC Address: " + str(pkt['Dot11'].addr2) + " Tried A Password On A Device Having This MAC Address: " + str(pkt['Dot11'].addr1))

			print(output)

			station_MAC_Addresses.add(str(pkt['Dot11'].addr2))

			logger.write(str(output) + "\n")

			pass

	if(pkt.haslayer(Dot11) and pkt.haslayer(Dot11AssoReq)):

		if(pkt['Dot11'].addr2 in station_MAC_Addresses2):

			pass

		else:

			nextOutput = (">> [+] This MAC Address: " + str(pkt['Dot11'].addr2) + " Successfully Connected To A Device Having This MAC Address: " + str(pkt['Dot11'].addr1))

			print(nextOutput)

			station_MAC_Addresses2.add(str(pkt['Dot11'].addr2))

			logger.write(str(nextOutput) + "\n")

			pass


def initiator():

	try:

		print(">> [!] Note: You Need To Have A Wireless Card That Supports Monitor Mode")

		interface = input(">> [?] Enter Interface Name: ")

		def startInterfaceActivity():

        		os.system("xterm -e sudo airodump-ng " + str(interface))

		print(">> [+] Monitoring Started")

		t = threading.Thread(target=startInterfaceActivity)

		t.setDaemon(True)

		t.start()

		sniff(prn=sniffer, iface=interface)

	except Exception as e:

		print(">> [!] Error Encountered: " + str(e))

		sys.exit()


initiator()
