
from scapy.all import *

def packet_handler(pkt):
    # Print the packet information
    print("=" * 80)
    print("Source: ", pkt[IP].src)
    print("Destination: ", pkt[IP].dst)
    print("Protocol: ", pkt[IP].proto)
    print("Payload: ", pkt[TCP].payload)
    print("=" * 80)

# Start the packet sniffer
sniff(filter="tcp", prn=packet_handler, store=0)