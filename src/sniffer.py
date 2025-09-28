# sniffer.py
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Define a callback function to process each packet
def packet_callback(packet):
    """
    This function is called by Scapy for every packet it captures.
    """
    # Check if the packet has an IP layer (ignores ARP, other non-IP traffic)
    if packet.haslayer(IP):
        # Extract the IP source and destination addresses
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        # Extract the IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
        proto = packet[IP].proto

        # Initialize variables for protocol and ports
        protocol_name = "Other"
        src_port = None
        dst_port = None

        # Determine the protocol name and extract ports if applicable
        if packet.haslayer(TCP):
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"
        else:
            # For any other IP protocol (e.g., IGMP, OSPF)
            protocol_name = f"Proto-{proto}"

        # Print the packet summary in a readable format
        print(f"[+] {ip_src}:{src_port} -> {ip_dst}:{dst_port} [{protocol_name}]")

# Main execution block
if __name__ == "__main__":
    print("Starting packet sniffer. Press Ctrl+C to stop...")
    # Start sniffing. 'prn' specifies the callback function.
    # 'store=0' tells Scapy not to keep packets in memory (prevents high RAM usage).
    # 'iface=None' tells Scapy to sniff on the default interface. You might need to change this later.
    sniff(prn=packet_callback, store=0, iface=None)
