from scapy.all import *
from collections import defaultdict

# Load the captured packets
packets = rdpcap("icmp_google.pcap")

# Track sequence numbers
sequence_numbers = defaultdict(int)

# Function to detect replayed packets
def detect_replay(packets):
    for packet in packets:
        if ICMP in packet:
            seq_num = packet[ICMP].seq
            sequence_numbers[seq_num] += 1
            if sequence_numbers[seq_num] > 1:
                print(f"Replayed packet detected! Sequence number: {seq_num}")

# Run the detection function
detect_replay(packets)
