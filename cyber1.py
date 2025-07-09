import socket
import struct
import sys

# ... (rest of your code, format_ip_address function) ...

def main():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        print("Raw socket created successfully.")
    except socket.error as msg:
        print(f'Error creating socket: {msg}.')
        print("Hint: On Windows, you usually need to run your script as an Administrator.")
        print("Also, ensure Npcap (with 'WinPcap API-compatible Mode') is installed.")
        sys.exit()

    print("\n[*] Starting basic sniffer... (Press Ctrl+C to stop)")
    print("[*] Waiting for incoming IP packets...")

    while True:
        # --- ADD THIS LINE FOR DEBUGGING ---
        # print("Waiting for packet...") # This will spam the console, but confirms the loop runs
        try:
            raw_data, addr = s.recvfrom(65535)

            # --- IF YOU REACH HERE, A PACKET WAS RECEIVED ---
            print(f"\n--- Packet Captured ---")
            print(f"  Source Address: {addr[0]}")
            print(f"  Packet Length: {len(raw_data)} bytes")
            print(f"  First 20 bytes (raw): {raw_data[:20].hex()}") # Shows the start of the IP header in hex

            # ... (rest of your dissection code) ...

        except KeyboardInterrupt:
            print("\n[*] Sniffer stopped by user (Ctrl+C).")
            break
        except Exception as e:
            print(f"[*] An unexpected error occurred: {e}")
            break

if __name__ == "__main__":
    main()
