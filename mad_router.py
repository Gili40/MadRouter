from scapy.all import *


def route_packet() -> None:
	"""
	Reroute packets from iface enp0s8 to iface enp0s9.
	"""
    while True:
        packet = sniff(iface="enp0s8", filter="not src host 192.168.56.101", count=1)[0]

        packet[Ether].src = "08:00:27:70:76:f7"
        packet[Ether].dst = "08:00:27:71:77:f8"
        if IP in packet:
            packet[IP].ttl -= 1

        sendp(packet, iface="enp0s9")


def main() -> None:
    route_packet()

if __name__ == "__main__":
    main()
