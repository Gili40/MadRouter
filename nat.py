from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

LEG1_IN = "enp0s8"
LEG2_OUT = "enp0s9"

LEG1_IN_MAC = "08:00:27:f6:6d:7d"
LEG2_OUT_MAC = "08:00:27:70:76:f7"
ALICE_MAC = "08:00:27:71:77:f8"
BOB_MAC = "08:00:27:71:77:f9"

LEG1_IN_IP = "192.168.1.1"
LEG2_OUT_IP = "192.168.2.1"
ALICE_IP = "192.168.1.2"
BOB_IP = "192.168.2.2"

# NAT mapping table.
nat_table = {}
# Starting point of port range.
port_num = 1024


def manage_packet_fields(pack: packet):
	"""
	Extracts basic fields from the packet for NAT processing.
	:param pack: The packet to extract fields from.
	:return: Fields extracted - protocol, src_port, dst_port, src_ip, dst_ip.
	"""
	protocol = "TCP" if pack.haslayer(TCP) else "UDP"
	src_port = pack[protocol].sport
	dst_port = pack[protocol].dport
	src_ip = pack[IP].src
	dst_ip = pack[IP].dst

	return protocol, src_port, dst_port, src_ip, dst_ip

def handle_outgoing_packets(pack: packet) -> None:
	"""
	Handles outgoing packets.
	:param pack: The packet to handle.
	"""
	global port_num
	global nat_table

	protocol, src_port, dst_port, src_ip, dst_ip = manage_packet_fields(pack)
	combine = (src_ip, src_port)

	pack[Ether].src = LEG2_OUT_MAC
	pack[Ether].dst = BOB_MAC
	pack[IP].src = LEG2_OUT_IP

	if combine in nat_table:
		pack[protocol].sport = nat_table[combine][1]
	else:
		pack[protocol].sport = port_num
		nat_table[combine] = (LEG2_OUT_IP, port_num)
		port_num += 1
	sendp(pack, iface=LEG2_OUT)


def handle_incoming_packets(pack: packet) -> None:
	"""
	Handles incoming packets.
	:param pack: The packet to handle.
	"""
	global nat_table

	protocol, src_port, dst_port, src_ip, dst_ip = manage_packet_fields(pack)

	for ((og_src_ip, og_src_port), (translated_ip, translated_port)) in nat_table.items():
		if dst_ip == translated_ip and dst_port == translated_port:
			pack[Ether].src = LEG1_IN_MAC
			# There is supposed to be an ARP table to match the mac addr to the IP. But pretend it is always Alice mac.
			pack[Ether].dst = ALICE_MAC
			pack[IP].src = LEG1_IN_IP
			pack[IP].dst = og_src_ip
			pack[protocol].dport = og_src_port

			sendp(pack, iface=LEG1_IN)


def nat() -> None:
	"""
	NAT loop that listens on both interfaces and forwards packets.
	"""
	while True:
		pack = sniff(iface=[LEG1_IN, LEG2_OUT], filter="ip and (tcp or udp)", count=1)[0]
		if pack.sniffed_on == LEG1_IN:
			handle_outgoing_packets(pack)
		elif pack.sniffed_on == LEG2_OUT:
			handle_incoming_packets(pack)


def main() -> None:
	nat()


if __name__ == "__main__":
	main()
