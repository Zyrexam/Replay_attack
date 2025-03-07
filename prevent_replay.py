from scapy.all import *
from collections import defaultdict
import logging
import time

# Load the captured packets
packets = rdpcap("icmp_google.pcap")  # Replace with your capture file

# Track sequence numbers, timestamps, and payloads
sequence_numbers = defaultdict(int)
timestamps = defaultdict(int)
payloads = defaultdict(int)

# Tolerance for timestamp comparison (in seconds)
TIMESTAMP_TOLERANCE = 0.1

# Time window for valid packets (in seconds)
TIME_WINDOW = 5  # Reject packets older than 5 seconds

# Set up logging
logging.basicConfig(filename="replay_attack.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# Function to detect and prevent replay attacks
def detect_and_prevent_replay(packets):
    current_time = time.time()  # Get current time

    for packet in packets:
        if ICMP in packet and IP in packet:
            # Extract sequence number, timestamp, payload, and IP addresses
            seq_num = packet[ICMP].seq
            timestamp = float(packet.time)  # Convert timestamp to float
            payload = bytes(packet[ICMP].payload)
            src_ip = packet[IP].src  # Source IP address
            dst_ip = packet[IP].dst  # Destination IP address

            # Check if the packet is within the valid time window
            if abs(current_time - timestamp) > TIME_WINDOW:
                logging.warning(f"Packet rejected: Timestamp outside valid window\n"
                               f"    Source: {src_ip} -> Destination: {dst_ip}\n"
                               f"    Timestamp: {timestamp}\n")
                continue  # Skip this packet

            # Check for duplicate sequence numbers
            sequence_numbers[seq_num] += 1
            if sequence_numbers[seq_num] > 1:
                logging.warning(f"Replayed packet detected!\n"
                                f"    Sequence number: {seq_num}\n"
                                f"    Source: {src_ip} -> Destination: {dst_ip}\n"
                                f"    Timestamp: {timestamp}\n")

            # Check for duplicate timestamps within tolerance
            timestamp_key = round(timestamp / TIMESTAMP_TOLERANCE) * TIMESTAMP_TOLERANCE
            timestamps[timestamp_key] += 1
            if timestamps[timestamp_key] > 1:
                logging.warning(f"Replayed packet detected!\n"
                                f"    Timestamp: {timestamp}\n"
                                f"    Source: {src_ip} -> Destination: {dst_ip}\n")

            # Check for duplicate payloads
            payloads[payload] += 1
            if payloads[payload] > 1:
                logging.warning(f"Replayed packet detected!\n"
                                f"    Source: {src_ip} -> Destination: {dst_ip}\n"
                                f"    Timestamp: {timestamp}\n"
                                f"    Payload: {payload}\n")

# Run the detection and prevention function
detect_and_prevent_replay(packets)