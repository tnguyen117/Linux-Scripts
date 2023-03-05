from scapy.all import *
 
# Define a callback function to handle each packet as it's captured
def handle_packet(packet):
    # Check if the packet is an ICMP echo request
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        # Construct a response packet
        response_packet = IP(src=packet[IP].dst, dst=packet[IP].src)/ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)/packet[Raw].load
        # Send the response packet
        send(response_packet, verbose=False)
 
# Sniff incoming packets and call the handle_packet function for each packet
sniff(filter='icmp', prn=handle_packet)
