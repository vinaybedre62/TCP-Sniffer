# TCP Packet Sniffer

This is a simple Python based TCP packet sniffer that captures and displays TCP traffic from the local network using the [Scapy](https://scapy.net/) library.

# Features

- Captures live TCP packets.
- Displays source IP and port.
- Displays destination IP and port.
- Sequential numbering of each captured packet.

---

## Requirements

- Python 3.11.9 x
- [Scapy](https://pypi.org/project/scapy/)
- Should be connected to active internet to run this program successfully.
- write a script in notepad and save it as Ex: tcp_sniffer.py to detect .py format as python file.

#Run program in python
1.Open python,click on file than locate & open tcp_sniffer.py
2.Scripts opens up then click on run & select run module or press F5 in keyboard.

#Install Scapy using pip for windows command prompt:
Open windows command prompt than:
1.pip install scapy
2.Type "dir" and find tcp_sniffer.py file in directory
3.Type tcp_sniffer.py to run program in windows command prompt.
4.Script runs after this indefinitely until ctrl + c is pressed manually to stop the script.

# TCP_Sniffer.py
# This script sniffs TCP packets from the local network using Scapy.

from scapy.all import sniff, TCP, IP #import libraries


packet_count = 0  # Initialize counter to zero to start from is a optional implemented feature.

def process_packet(packet):
    """
    Callback function to process each sniffed packet.
    Filters and displays TCP packets in the specified format.
    """
    global packet_count
    if packet.haslayer(TCP) and packet.haslayer(IP):
        packet_count += 1  # Increment counter by step one.
        ip_layer = packet[IP] #internet protocol is 
        tcp_layer = packet[TCP] #Transmission Control Protocol
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        print(f"[{packet_count}] TCP Packet: {src_ip}:{src_port} => {dst_ip}:{dst_port}") #this is the format in which

def main():
    """
    Main function to start sniffing packets.
    """
    print("[+] Starting TCP packet sniffer... Press Ctrl + C to stop.") # stop the script from running when ctrl + c is manually pressed in keyboard.
    print("[+] TCP Packet: {source_ip}:{source_port} => {destination_ip}:{destination_port}")
    
    try:
        # Sniff packets indefinitely, filtering for TCP
        sniff(filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[+] Stopping packet sniffer.")

if __name__ == "__main__":
    main()