# Network Packet Sniffer

## CodeAlpha Cybersecurity Internship - Task 1

---

### 📌 Project Description

A Python-based network packet sniffer that captures and analyzes network traffic in real-time. Built using Scapy, this tool helps understand how data flows through networks and the structure of network protocols.

---

### ⚡ Features

- Captures Ethernet, IP, TCP, UDP, ICMP, and ARP packets
- Displays source/destination IPs and MAC addresses
- Shows protocol information and port numbers
- Detects HTTP traffic
- Saves captured packets to PCAP files
- Color-coded output for easy reading

---

### 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python 3.12 | Programming language |
| Scapy | Packet capture and manipulation |
| PrettyTable | Formatted table output |
| Colorama | Colored console text |
| Npcap | Packet capture driver (Windows) |

---

### 📁 Project Structure
CodeAlpha_NetworkSniffer/
├── network_sniffer.py
├── captured_traffic.pcap
└── README.md

text

---

### 🚀 How to Run

#### 1. Install Dependencies
```bash
pip install scapy scapy-http prettytable colorama
2. Install Npcap (Windows only)
Download from: https://npcap.com/

3. Run the Program
bash
# Windows (as Administrator)
python network_sniffer.py

# Linux/Mac (with sudo)
sudo python3 network_sniffer.py
4. Select Capture Mode
text
1. Basic sniff (10 packets)
2. TCP traffic only (20 packets)
3. HTTP traffic (port 80, 15 packets)
4. UDP traffic (10 packets)
5. Custom filter
6. Continuous sniff (until Ctrl+C)
📊 Sample Output
text
═══════════════════════════════════════════════════════════
[2026-07-01 02:52:50.823] Packet #1
═══════════════════════════════════════════════════════════
+----------+------------------+-------------------+
|  Layer   |      Field       |       Value       |
+----------+------------------+-------------------+
| Ethernet |    Source MAC    | 76:2b:6f:14:69:21 |
| Ethernet | Destination MAC  | ac:7b:a1:5f:14:cd |
|    IP    |    Source IP     |   170.72.250.145  |
|    IP    |  Destination IP  |     10.19.84.8    |
|   TCP    |   Source Port    |        443        |
|   TCP    | Destination Port |       56611       |
+----------+------------------+-------------------+
💡 What I Learned
How network packets are structured

How to capture and analyze network traffic

Protocol identification (TCP, UDP, ICMP, ARP)

HTTP traffic detection

How to use Scapy for packet manipulation

📝 Author
ADESIYAN ADEOLA SAMUEL

CodeAlpha Cybersecurity Intern

📅 Date
July 2026