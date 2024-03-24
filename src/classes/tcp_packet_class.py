from scapy.all import Raw
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class TcpPacket:

    def __init__(self, packet: Packet):
        self.timestamp = packet.time
        self.ip_src = packet[IP].src
        self.port_src = packet[TCP].sport
        self.ip_dst = packet[IP].dst
        self.port_dst = packet[TCP].dport

        try:
            self.payload = packet[Raw].load.hex()
        except IndexError:
            self.payload = None
