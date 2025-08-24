# core/packet_processor.py

from collections import defaultdict
import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, DNS

class PacketProcessor:
    """
    Processes captured network packets to extract relevant statistics.
    """
    def __init__(self):
        self.protocol_counts = defaultdict(int)
        self.src_dst_counts = defaultdict(lambda: defaultdict(int)) # src -> dst -> count
        self.total_packets = 0

    def process_packet(self, packet):
        """
        Analyzes a single Scapy packet and updates internal statistics.
        """
        self.total_packets += 1

        # Process IP layer for source/destination
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.src_dst_counts[src_ip][dst_ip] += 1

            # Process transport layer protocols
            if packet.haslayer(TCP):
                self.protocol_counts["TCP"] += 1
            elif packet.haslayer(UDP):
                self.protocol_counts["UDP"] += 1
                # Check for DNS specifically within UDP
                if packet.haslayer(DNS):
                    self.protocol_counts["DNS"] += 1
            elif packet.haslayer(ICMP):
                self.protocol_counts["ICMP"] += 1
            else:
                self.protocol_counts["Other IP"] += 1
        else:
            self.protocol_counts["Non-IP"] += 1

    def get_protocol_counts(self):
        """
        Returns a dictionary of protocol counts.
        """
        return dict(self.protocol_counts)

    def get_top_sources_and_destinations(self, top_n=5):
        """
        Returns the top N source-destination IP pairs.
        """
        if not self.src_dst_counts:
            return []

        # Convert to a list of (src, dst, count) tuples for easier sorting
        connections = []
        for src, dests in self.src_dst_counts.items():
            for dst, count in dests.items():
                connections.append((src, dst, count))

        # Sort by count in descending order
        connections.sort(key=lambda x: x[2], reverse=True)

        return connections[:top_n]

    def reset_stats(self):
        """
        Resets all internal statistics.
        """
        self.protocol_counts = defaultdict(int)
        self.src_dst_counts = defaultdict(lambda: defaultdict(int))
        self.total_packets = 0

