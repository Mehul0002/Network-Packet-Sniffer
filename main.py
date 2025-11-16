import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, conf
import threading
import queue

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("900x500")
        self.packets = []
        self.sniffing = False
        self.queue = queue.Queue()

        # Filters
        self.protocol_var = tk.StringVar(value="ALL")
        self.count_var = tk.IntVar(value=50)

        # GUI Layout
        self.create_widgets()
        self.process_queue()

    def create_widgets(self):
        # Controls Frame
        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=10)

        tk.Label(control_frame, text="Protocol:").grid(row=0, column=0)
        protocol_menu = ttk.Combobox(control_frame, textvariable=self.protocol_var, values=["ALL", "TCP", "UDP", "ICMP"])
        protocol_menu.grid(row=0, column=1)

        tk.Label(control_frame, text="Packet Count:").grid(row=0, column=2)
        tk.Entry(control_frame, textvariable=self.count_var, width=5).grid(row=0, column=3)

        ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing).grid(row=0, column=4, padx=10)
        ttk.Button(control_frame, text="Stop", command=self.stop_sniffing).grid(row=0, column=5)
        ttk.Button(control_frame, text="Save to PCAP", command=self.save_pcap).grid(row=0, column=6)

        # Packet Display
        self.tree = ttk.Treeview(self.root, columns=("No", "Source", "Destination", "Protocol"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        # Packet Details
        self.details_text = tk.Text(self.root, height=10)
        self.details_text.pack(fill=tk.X)

    def start_sniffing(self):
        if self.sniffing:
            messagebox.showinfo("Info", "Already sniffing!")
            return
        self.sniffing = True
        self.packets.clear()
        self.tree.delete(*self.tree.get_children())
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False

    def sniff_packets(self):
        def process_packet(packet):
            if not self.sniffing:
                return False
            proto = "OTHER"
            if packet.haslayer(TCP): proto = "TCP"
            elif packet.haslayer(UDP): proto = "UDP"
            elif packet.haslayer(ICMP): proto = "ICMP"

            if self.protocol_var.get() != "ALL" and proto != self.protocol_var.get():
                return

            self.queue.put((packet, proto))

        try:
            sniff(prn=process_packet, store=False, count=self.count_var.get(), socket=conf.L3socket())
        except Exception as e:
            messagebox.showerror("Sniffing Error", f"Failed to start sniffing: {str(e)}")
            self.sniffing = False

    def process_queue(self):
        try:
            while True:
                packet, proto = self.queue.get_nowait()
                self.packets.append(packet)
                self.tree.insert("", "end", values=(len(self.packets), packet[IP].src, packet[IP].dst, proto))
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def show_details(self, event):
        selected = self.tree.selection()
        if selected:
            index = int(self.tree.item(selected[0])["values"][0]) - 1
            packet = self.packets[index]
            self.details_text.delete("1.0", tk.END)
            self.details_text.insert(tk.END, packet.show(dump=True))

    def save_pcap(self):
        if self.packets:
            wrpcap("captured_packets.pcap", self.packets)
            messagebox.showinfo("Saved", "Packets saved to captured_packets.pcap")
        else:
            messagebox.showwarning("No Packets", "No packets to save.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
