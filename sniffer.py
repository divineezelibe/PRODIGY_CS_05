import subprocess
import sys
import os

# Step 1: Install dependencies (if not already installed)
def install_dependencies():
    try:
        import scapy
        import psutil
    except ImportError:
        # Install missing modules
        print("Installing required dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy", "psutil"])
        print("Dependencies installed successfully.")

# Step 2: List all network interfaces with friendly names
def list_network_interfaces():
    from scapy.all import get_if_list
    import psutil

    interfaces = get_if_list()
    interface_info = psutil.net_if_addrs()  # Get detailed info about interfaces

    print("\nAvailable Network Interfaces:")
    interface_mapping = {}
    for index, iface in enumerate(interfaces):
        if iface in interface_info:
            friendly_name = iface
        else:
            friendly_name = f"Unknown ({iface})"

        # Associate friendly name with raw interface name
        interface_mapping[iface] = friendly_name
        print(f"{index + 1}: {friendly_name} ({iface})")

    return interface_mapping

# Step 3: Packet sniffer code
def start_sniffing(interface):
    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP, UDP

    # Function to process captured packets
    def packet_callback(packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            # Display packet details
            print(f"\n[+] Packet captured:")
            print(f"    Source IP: {ip_src}")
            print(f"    Destination IP: {ip_dst}")
            print(f"    Protocol: {protocol}")

            # Check if it's a TCP or UDP packet
            if TCP in packet:
                print(f"    TCP Packet: Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
            elif UDP in packet:
                print(f"    UDP Packet: Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")

            # Display payload data if available
            if packet.haslayer('Raw'):
                print(f"    Payload: {packet['Raw'].load}")
        else:
            print("[-] Non-IP packet detected")

    # Start sniffing
    print(f"[*] Starting packet sniffer on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)

# Main function to install dependencies, list interfaces, and run the packet sniffer
def main():
    install_dependencies()  # Install dependencies if needed
    
    # Step 1: List network interfaces
    interface_mapping = list_network_interfaces()

    # Step 2: Ask the user to select the interface
    selected_interface_index = int(input("\nSelect the interface number to sniff: ")) - 1
    interfaces = list(interface_mapping.keys())

    if 0 <= selected_interface_index < len(interfaces):
        selected_interface = interfaces[selected_interface_index]
        friendly_name = interface_mapping[selected_interface]
        print(f"[*] Selected interface: {friendly_name} ({selected_interface})")
        start_sniffing(selected_interface)
    else:
        print("Invalid interface selection. Exiting...")

if __name__ == "__main__":
    main()
