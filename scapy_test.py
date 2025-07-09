import sys
try:
    from scapy.all import *
    print("Scapy imported successfully for packet dissection.")
except ImportError:
    print("Scapy not found. Please install it: pip install scapy")
    sys.exit()
except Exception as e:
    print(f"Error importing Scapy: {e}")
    sys.exit()

def dissect_packet(packet):
    print("\n" + "="*50)
    print(f"[*] New Packet Captured (Length: {len(packet)} bytes)")
    print("="*50)

    # --- Layer 2: Ethernet Header ---
    if packet.haslayer(Ether):
        ether_layer = packet[Ether]
        print("--- Ethernet Layer ---")
        print(f"  Source MAC: {ether_layer.src}")
        print(f"  Destination MAC: {ether_layer.dst}")
        print(f"  EtherType: {hex(ether_layer.type)}") # 0x800 for IP, 0x806 for ARP

    # --- Layer 3: IP Header (IPv4) ---
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("\n--- IP Layer ---")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        # Note: ip_layer.proto.name might not always exist for all protocol numbers,
        # so the 'hasattr' check is good.
        print(f"  Protocol: {ip_layer.proto} ({ip_layer.proto.name if hasattr(ip_layer.proto, 'name') else 'Unknown'})")
        print(f"  TTL: {ip_layer.ttl}")
        print(f"  Header Length: {ip_layer.ihl * 4} bytes") # IHL is in 4-byte words

        # --- Layer 4: TCP/UDP/ICMP Header (based on IP Protocol) ---
        # These 'if/elif/else' blocks should be indented one level *after* the 'if packet.haslayer(IP):'
        # and aligned with each other.
        if ip_layer.proto == 6 and packet.haslayer(TCP): # TCP (Protocol 6)
            tcp_layer = packet[TCP]
            print("\n--- TCP Layer ---")
            print(f"  Source Port: {tcp_layer.sport}")
            print(f"  Destination Port: {tcp_layer.dport}")
            print(f"  Sequence Number: {tcp_layer.seq}")
            print(f"  Acknowledgment Number: {tcp_layer.ack}")
            print(f"  Flags: {tcp_layer.flags}")
            print(f"  Header Length: {tcp_layer.dataofs * 4} bytes") # Dataofs is 4-byte words

            # TCP Payload (Application Data)
            if tcp_layer.payload:
                try:
                    # Attempt to decode as UTF-8, useful for HTTP
                    payload_str = bytes(tcp_layer.payload).decode('utf-8', errors='ignore').strip()
                    if payload_str:
                        print(f"  Payload (Text): {payload_str[:100]}...") # Print first 100 chars
                    else:
                        print(f"  Payload (Hex): {bytes(tcp_layer.payload).hex()[:100]}...")
                except Exception:
                    print(f"  Payload (Hex): {bytes(tcp_layer.payload).hex()[:100]}...")
            else:
                print("  No TCP Payload")


        elif ip_layer.proto == 17 and packet.haslayer(UDP): # UDP (Protocol 17)
            udp_layer = packet[UDP]
            print("\n--- UDP Layer ---")
            print(f"  Source Port: {udp_layer.sport}")
            print(f"  Destination Port: {udp_layer.dport}")
            print(f"  Length: {udp_layer.len}")

            # UDP Payload
            if udp_layer.payload:
                try:
                    payload_str = bytes(udp_layer.payload).decode('utf-8', errors='ignore').strip()
                    if payload_str:
                        print(f"  Payload (Text): {payload_str[:100]}...")
                    else:
                        print(f"  Payload (Hex): {bytes(udp_layer.payload).hex()[:100]}...")
                except Exception:
                    print(f"  Payload (Hex): {bytes(udp_layer.payload).hex()[:100]}...")
            else:
                print("  No UDP Payload")

        elif ip_layer.proto == 1 and packet.haslayer(ICMP): # ICMP (Protocol 1)
            icmp_layer = packet[ICMP]
            print("\n--- ICMP Layer ---")
            print(f"  Type: {icmp_layer.type} ({icmp_layer.type.name if hasattr(icmp_layer.type, 'name') else 'Unknown'})")
            print(f"  Code: {icmp_layer.code}")

            if icmp_layer.payload:
                print(f"  Payload (Hex): {bytes(icmp_layer.payload).hex()[:100]}...")
            else:
                print("  No ICMP Payload")

        else: # This 'else' catches any other IP protocol not explicitly handled above
            print("\n--- Other/Unknown IP Protocol ---")
            print(f"  IP Protocol Number: {ip_layer.proto}")
            # packet.show() # Uncomment to see full packet details for unknown types

    # If it's not an IP packet, but something else at Layer 3 (e.g., ARP)
    # This 'elif' should be at the same indentation level as 'if packet.haslayer(IP):'
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        print("\n--- ARP Layer ---")
        print(f"  Operation: {arp_layer.op} ({'request' if arp_layer.op == 1 else 'reply'})")
        print(f"  Sender MAC: {arp_layer.hwsrc}")
        print(f"  Sender IP: {arp_layer.psrc}")
        print(f"  Target MAC: {arp_layer.hwdst}")
        print(f"  Target IP: {arp_layer.pdst}")

    # You can add more 'elif packet.haslayer(ProtocolName):' blocks for other top-level protocols


print("[*] Starting comprehensive Scapy sniffer... (Press Ctrl+C to stop)")
print("[*] Waiting for packets. Generate traffic (ping, browse http://neverssl.com/).")

try:
    # sniff() with a callback to our dissection function
    # iface: You can specify your network interface here if needed (e.g., "Ethernet 1", "Wi-Fi")
    # To find interface names: In a cmd, type 'getmac /v' or open Scapy shell by typing 'scapy' then 'show_interfaces()'
    # If you don't specify iface, Scapy tries to sniff on all available interfaces.
    sniff(prn=dissect_packet, store=0) # store=0 prevents storing packets in memory for infinite sniff

except KeyboardInterrupt:
    print("\n[*] Scapy sniffer stopped by user (Ctrl+C).")
except PermissionError:
    print("\nError: Permission denied. Make sure you're running IDLE as Administrator.")
except Exception as e:
    print(f"\n[*] An error occurred during sniffing: {e}")

print("[*] Scapy sniffer finished.")
