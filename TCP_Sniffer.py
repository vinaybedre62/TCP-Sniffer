# tcp_sniffer.py
# This script sniffs TCP packets from the local network using Scapy.

from scapy.all import sniff, TCP, IP

# Initialize counter
packet_count = 0

def process_packet(packet):
    """
    Callback function to process each sniffed packet.
    Filters and displays TCP packets in the specified format.
    """
    global packet_count
    if packet.haslayer(TCP) and packet.haslayer(IP):
        packet_count += 1  # Increment counter
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        print(f"[{packet_count}] TCP Packet: {src_ip}:{src_port} => {dst_ip}:{dst_port}")

def main():
    """
    Main function to start sniffing packets.
    """
    print("[+] Starting TCP packet sniffer... Press Ctrl + C to stop.")
    print("[+] TCP Packet: {source_ip}:{source_port} => {destination_ip}:{destination_port}")
    
    try:
        # Sniff packets indefinitely, filtering for TCP
        sniff(filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[+] Stopping packet sniffer.")

if __name__ == "__main__":
    main()



