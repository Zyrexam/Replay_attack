from scapy.all import *

# Load the captured packets
packets = rdpcap("icmp_google.pcap")

# Replay the packets
for packet in packets:
    if IP in packet and ICMP in packet:  # Ensure it's an ICMP packet
        send(IP(dst=packet[IP].dst)/ICMP(type=packet[ICMP].type, id=packet[ICMP].id, seq=packet[ICMP].seq))
        print(f"Replayed ICMP packet to {packet[IP].dst}")