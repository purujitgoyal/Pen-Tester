from ARP import ARP,parse_ip,parse_mac
from struct import pack
from uuid import getnode as get_mac
# from impacket import ImpactDecoder
import struct
import fcntl
import socket
import time


ETHERNET_PROTOCOL_TYPE_ARP = pack('!H', 0x0806)
ARP_PROTOCOL = pack('!HHBB', 0x0001, 0x0800, 0x06, 0x04)



def request(ipsrc, ipdst, hwsrc, hwdest,interface,list):
	# print get_mac()
	# print hwsrc, hwdest
	# decoder = ImpactDecoder.IPDecoder()
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
	sock.bind((interface, socket.SOCK_RAW))
	arpreq = ARP(0x0001, get_mac(), hwsrc, hwdest, ipsrc, ipdst).arp_packet
	# print arpreq
	sock.send(''.join(arpreq))
	# time.sleep(1)
	reply = sock.recv(1000000000)
	list.append(reply)
	# string_reply = decoder.decode(reply)
	# print ipdst
	# print string_reply




def getSubnet(interface):
	iface = interface
	subnet = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack('256s', iface))[20:24])
	return subnet

def maskChecker(subnet):
	subnetSplit = subnet.split('.')
	maskList = []
	for i in range(0, 4):
		if int(subnetSplit[i]) == 0:
			maskList.append(i)
	return maskList

def getOwnIP(interface):
	iface = interface
	ip = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8915, struct.pack('256s',iface[:15]))[20:24])
	return ip

def scan(interface,list):
	subnet = getSubnet(interface)
	# print subnet
	maskList = maskChecker(subnet)
	# print maskList
	my_ip = getOwnIP(interface)
	# print my_ip
	if len(maskList)>1:
		print "Too many ips to be scanned"
	else:
		# print "here"
		my_ip_parsed = parse_ip(my_ip)
		# print my_ip_parsed
		# ipsrc_parsed = parse_ip(ipsrc)
		# # print ipsrc_parsed
		# hwsrc_parsed = parse_mac(hwsrc)
		# # print hwsrc_parsed
		for i in range(0,256):
			my_ip_parsed[maskList[0]]=i
			ipdst = ".".join(map(str, my_ip_parsed))
			# print ipdst
			# print my_ip_parsed
			request(my_ip,ipdst,get_mac(),0,interface,list)


def parse(list):

	final_list=[]
	for reply in list:

		dest_addr = reply[:6]
		src_addr = reply[6:12]
		prot = reply[12:14]

		dest_addr = [c for c in dest_addr]
		src_addr = [c for c in src_addr]
		# print ':'.join([str(ord(c)) for c in dest_addr])
		# print ':'.join([str(ord(c)) for c in src_addr])
		# # print prot

		if prot =='\x08\x06':
			opcode = reply[20:22]
			sender = reply[22:28]
			sender_ip = reply[28:32]

			if opcode=='\x00\x01':
				sender = [c for c in sender]
				mac = ':'.join([hex(ord(c)).replace('0x','') for c in sender])
				ip = '.'.join([str(ord(c)) for c in sender_ip])
				final_list.append("   IP: "+str(ip)+"  MAC: "+str(mac_converter(mac)))
	return final_list	
def mac_converter(mac):
	mac=mac.replace(":","")
	final=int(mac,16)
	return final

def main1(interface):

	listresp=[]
	scan(interface,listresp)
	fin_list=list(set(parse(listresp)))
	for i in fin_list:
		print i	

# def main():

# 	listresp=[]                 
# 	scan('enp3s0','172.25.12.1',132879549407295,listresp)
# 	fin_list=list(set(parse(listresp)))
# 	for i in fin_list:
# 		print i	
													   

# scan('enp3s0','172.25.12.1',132879549407295,listresp)6240045636604989704
if __name__=="__main__":

	main1()
	# main()


