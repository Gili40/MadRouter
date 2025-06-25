from scapy.all import *

LEG1 = "enp0s8"
LEG2 = "enp0s9"

LEG1_MAC = "08:00:27:f6:6d:7d"
LEG2_MAC = "08:00:27:70:76:f7"
ALICE_MAC = "08:00:27:71:77:f8"
BOB_MAC = "08:00:27:71:77:f9"

LEG1_IP = "192.168.1.1"
LEG2_IP = "192.168.2.1"
ALICE_IP = "192.168.1.2"
BOB_IP = "192.168.2.2"


def handle_alice_packet(packet: scapy.packet) -> None:
	"""
	Handle a packet sent from Alice.
	:param packet: The packet sent from Alice.
	"""
	packet[Ether].src = LEG2_MAC
	packet[Ether].dst = BOB_MAC
	if IP in packet:
		packet[IP].src = LEG2_IP
		packet[IP].ttl -= 1
	sendp(packet, iface=LEG2)

def handle_outside_packet(packet: scapy.packet) -> None:
	"""
	Handle a packet sent from Bob (Or anyone else).
	:param packet: The packet sent from Bob.
	"""
	packet[Ether].src = LEG1_MAC
	packet[Ether].dst = ALICE_MAC
	if IP in packet:
		packet[IP].dst = ALICE_IP
		packet[IP].ttl -= 1
	sendp(packet, iface=LEG1)


def proxy() -> None:
	"""
	Act as proxy server to hide Alice IP addr.
	"""
	while True:
		packet = sniff(iface=[LEG1, LEG2], count=1)[0]
		if packet.sniffed_on == LEG1:
			handle_alice_packet(packet)
		else:
			handle_outside_packet(packet)


def main() -> None:
	proxy()

if __name__ == "__main__":
	main()
