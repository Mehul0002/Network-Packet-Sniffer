# Network Packet Sniffer

A Python-based GUI application for capturing and analyzing network packets using Scapy and Tkinter.

## Features

- Live packet sniffing with Scapy
- GUI interface with Tkinter
- Filter by protocol (TCP, UDP, ICMP)
- Limit packet count
- Display packets in a table
- Show detailed packet information on selection
- Save captured packets to .pcap file
- Threading for responsive GUI

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run as administrator (required for packet sniffing):
   ```bash
   python main.py
   ```

## Usage

- Select protocol filter and packet count
- Click "Start Sniffing" to begin capturing
- Select a packet in the table to view details
- Click "Save to PCAP" to save packets
- Click "Stop" to halt sniffing

## Requirements

- Python 3.x
- Scapy
- Tkinter (usually included with Python)
