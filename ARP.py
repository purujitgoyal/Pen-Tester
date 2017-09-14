from struct import pack


ETHERNET_PROTOCOL_TYPE_ARP = pack('!H', 0x0806)
ARP_PROTOCOL = pack('!HHBB', 0x0001, 0x0800, 0x06, 0x04)


def parse_ip(ip):
	return [int(c) for c in ip.split('.')]

def parse_mac(mac):
	m = []
	while mac>0:
		m = [int(mac%256)]+m
		mac/=256
	m = [0]*(6-len(m)) + m
	return m

class ARP:
	def __init__(self, opcode, mymac , hwsrc, hwdest, ipsrc, ipdest):
		ipsrc = parse_ip(ipsrc)
		ipdest = parse_ip(ipdest)
		hwsrc = parse_mac(hwsrc)
		hwdest = parse_mac(hwdest)
		mymac = parse_mac(mymac)
		# print ipsrc, hwsrc, ipdest, hwdest

		self.arp_packet = [
			# Ethernet Header

			pack('!6B', *hwdest),
			pack('!6B', *mymac),
			ETHERNET_PROTOCOL_TYPE_ARP,

			# ARP Header
			ARP_PROTOCOL,
			pack('!H', opcode),
			pack('!6B', *hwsrc),
			pack('!4B', *ipsrc),
			pack('!6B', *hwdest),
			pack('!4B', *ipdest)

		]