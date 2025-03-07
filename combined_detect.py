from scapy.all import *
from collections import defaultdict

# Load the captured packets
packets = rdpcap("icmp_google.pcap")  # Replace with your capture file

# Track sequence numbers, timestamps, and payloads
sequence_numbers = defaultdict(int)
timestamps = defaultdict(int)
payloads = defaultdict(int)

# Tolerance for timestamp comparison (in seconds)
TIMESTAMP_TOLERANCE = 0.1

# Function to detect replayed packets
def detect_replay(packets):
    for packet in packets:
        if ICMP in packet and IP in packet:
            # Extract sequence number, timestamp, payload, and IP addresses
            seq_num = packet[ICMP].seq
            timestamp = float(packet.time)  # Convert timestamp to float
            payload = bytes(packet[ICMP].payload)
            src_ip = packet[IP].src  # Source IP address
            dst_ip = packet[IP].dst  # Destination IP address

            # Check for duplicate sequence numbers
            sequence_numbers[seq_num] += 1
            if sequence_numbers[seq_num] > 1:
                print(f"[!] Replayed packet detected!\n"
                      f"    Sequence number: {seq_num}\n"
                      f"    Source: {src_ip} -> Destination: {dst_ip}\n"
                      f"    Timestamp: {timestamp}\n")

            # Check for duplicate timestamps within tolerance
            timestamp_key = round(timestamp / TIMESTAMP_TOLERANCE) * TIMESTAMP_TOLERANCE
            timestamps[timestamp_key] += 1
            if timestamps[timestamp_key] > 1:
                print(f"[!] Replayed packet detected!\n"
                      f"    Timestamp: {timestamp}\n"
                      f"    Source: {src_ip} -> Destination: {dst_ip}\n")

            # Check for duplicate payloads
            payloads[payload] += 1
            if payloads[payload] > 1:
                print(f"[!] Replayed packet detected!\n"
                      f"    Source: {src_ip} -> Destination: {dst_ip}\n"
                      f"    Timestamp: {timestamp}\n"
                      f"    Payload: {payload}\n")

# Run the detection function
detect_replay(packets)