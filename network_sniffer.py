import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from prettytable import PrettyTable
from colorama import init, Fore, Style
import datetime
import sys
import platform

init(autoreset=True)

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.captured_packets = []
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        
    def get_timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    def print_banner(self):
        print(f"""{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║              NETWORK PACKET SNIFFER                          ║
║              CodeAlpha Cybersecurity Internship              ║
║                                                              ║
║  System: {platform.system()} {platform.release()}                     ║
║  Python: {platform.python_version()}                                  ║
║  Started: {self.get_timestamp()}                    ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

    def packet_callback(self, packet):
        self.packet_count += 1
        self.captured_packets.append(packet)
        timestamp = self.get_timestamp()
        print(f"\n{Fore.YELLOW}{'═'*70}")
        print(f"{Fore.GREEN}[{timestamp}] {Fore.WHITE}Packet #{self.packet_count}")
        print(f"{Fore.YELLOW}{'═'*70}")
        table = PrettyTable()
        table.field_names = ["Layer", "Field", "Value"]
        table.align = "L"
        table.max_width = 50
        if Ether in packet:
            eth = packet[Ether]
            table.add_row(["Ethernet", "Source MAC", eth.src])
            table.add_row(["Ethernet", "Destination MAC", eth.dst])
            table.add_row(["Ethernet", "Type", hex(eth.type)])
        if IP in packet:
            ip = packet[IP]
            self.protocol_stats['IP'] = self.protocol_stats.get('IP', 0) + 1
            table.add_row(["IP", "Source IP", f"{Fore.CYAN}{ip.src}{Style.RESET_ALL}"])
            table.add_row(["IP", "Destination IP", f"{Fore.CYAN}{ip.dst}{Style.RESET_ALL}"])
            table.add_row(["IP", "Protocol", ip.proto])
            table.add_row(["IP", "TTL", ip.ttl])
            table.add_row(["IP", "Length", ip.len])
            if TCP in packet:
                tcp = packet[TCP]
                self.protocol_stats['TCP'] += 1
                table.add_row(["TCP", "Source Port", tcp.sport])
                table.add_row(["TCP", "Destination Port", tcp.dport])
                table.add_row(["TCP", "Flags", tcp.flags])
                table.add_row(["TCP", "Sequence", tcp.seq])
                table.add_row(["TCP", "Acknowledgment", tcp.ack])
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if 'HTTP' in payload_str or 'GET' in payload_str or 'POST' in payload_str:
                            table.add_row([f"{Fore.GREEN}HTTP{Style.RESET_ALL}", "Detected", f"{Fore.GREEN}✓ HTTP Traffic Detected{Style.RESET_ALL}"])
                            lines = payload_str.split('\r\n')
                            for line in lines[:3]:
                                if line and len(line) < 60:
                                    table.add_row(["HTTP", "Header", line[:60]])
                    except:
                        pass
            elif UDP in packet:
                udp = packet[UDP]
                self.protocol_stats['UDP'] += 1
                table.add_row(["UDP", "Source Port", udp.sport])
                table.add_row(["UDP", "Destination Port", udp.dport])
                table.add_row(["UDP", "Length", udp.len])
                if packet.haslayer(scapy.DNS):
                    dns = packet[scapy.DNS]
                    if dns.qr == 0:
                        table.add_row(["DNS", "Query", dns.qd.qname.decode() if dns.qd else "Unknown"])
                    else:
                        table.add_row(["DNS", "Response", "DNS Response"])
            elif ICMP in packet:
                icmp = packet[ICMP]
                self.protocol_stats['ICMP'] += 1
                table.add_row(["ICMP", "Type", icmp.type])
                table.add_row(["ICMP", "Code", icmp.code])
        elif scapy.ARP in packet:
            arp = packet[scapy.ARP]
            self.protocol_stats['ARP'] += 1
            table.add_row(["ARP", "Operation", "Request" if arp.op == 1 else "Reply"])
            table.add_row(["ARP", "Source MAC", arp.hwsrc])
            table.add_row(["ARP", "Source IP", arp.psrc])
            table.add_row(["ARP", "Target MAC", arp.hwdst])
            table.add_row(["ARP", "Target IP", arp.pdst])
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            try:
                payload_text = payload.decode('utf-8', errors='ignore')
                preview = payload_text[:50] + "..." if len(payload_text) > 50 else payload_text
                if preview.strip():
                    table.add_row(["Payload", "Data", f"{Fore.MAGENTA}{preview}{Style.RESET_ALL}"])
            except:
                table.add_row(["Payload", "Data", f"{Fore.MAGENTA}{payload.hex()[:50]}...{Style.RESET_ALL}"])
        print(table)
        print(f"{Fore.YELLOW}{'─'*70}{Style.RESET_ALL}")
    
    def start_sniffing(self, interface=None, count=0, filter_str=None, timeout=None):
        self.print_banner()
        print(f"{Fore.CYAN}┌─ Capturing Packets")
        print(f"│  Interface: {interface or 'Default'}")
        print(f"│  Filter: {filter_str or 'None'}")
        print(f"│  Packet Limit: {count if count > 0 else 'Unlimited'}")
        print(f"│  Timeout: {timeout if timeout else 'None'}")
        print(f"└─ Press Ctrl+C to stop{Style.RESET_ALL}")
        print()
        try:
            scapy.sniff(iface=interface, count=count, prn=self.packet_callback, filter=filter_str, store=False, timeout=timeout)
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[*] Stopping packet capture...{Style.RESET_ALL}")
        except PermissionError:
            print(f"\n\n{Fore.RED}[!] ERROR: You need Administrator privileges!{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        self.print_summary()
    
    def print_summary(self):
        print(f"\n{Fore.CYAN}{'═'*70}")
        print(f"{Fore.GREEN}CAPTURE SUMMARY")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"Total packets captured: {self.packet_count}")
        print(f"Packets saved: {len(self.captured_packets)}")
        print(f"\n{Fore.YELLOW}Protocol Distribution:{Style.RESET_ALL}")
        for proto, count in self.protocol_stats.items():
            if count > 0:
                percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
                print(f"  {proto}: {count} packets ({percentage:.1f}%)")
    
    def save_to_pcap(self, filename="captured_traffic.pcap"):
        if self.captured_packets:
            scapy.wrpcap(filename, self.captured_packets)
            print(f"\n{Fore.GREEN}[+] Packets saved to {filename}{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}Welcome to the Network Sniffer!{Style.RESET_ALL}")
    print("=" * 50)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        print(f"{Fore.RED}⚠️  WARNING: Not running as Administrator!{Style.RESET_ALL}")
    print("Select capture mode:")
    print("1. Basic sniff (10 packets)")
    print("2. TCP traffic only (20 packets)")
    print("3. HTTP traffic (port 80, 15 packets)")
    print("4. UDP traffic (10 packets)")
    print("5. Custom filter")
    print("6. Continuous sniff (until Ctrl+C)")
    choice = input("\nEnter choice (1-6): ")
    sniffer = NetworkSniffer()
    if choice == "1":
        sniffer.start_sniffing(count=10)
    elif choice == "2":
        sniffer.start_sniffing(filter_str="tcp", count=20)
    elif choice == "3":
        sniffer.start_sniffing(filter_str="port 80", count=15)
    elif choice == "4":
        sniffer.start_sniffing(filter_str="udp", count=10)
    elif choice == "5":
        filter_str = input("Enter BPF filter (e.g., 'tcp', 'port 53'): ")
        count = int(input("Enter number of packets: "))
        sniffer.start_sniffing(filter_str=filter_str, count=count)
    elif choice == "6":
        sniffer.start_sniffing()
    else:
        print("Invalid choice")
    if sniffer.captured_packets:
        save = input(f"\n{Fore.YELLOW}Save captured packets to PCAP file? (y/n): {Style.RESET_ALL}")
        if save.lower() == 'y':
            filename = input("Enter filename (default: captured_traffic.pcap): ") or "captured_traffic.pcap"
            sniffer.save_to_pcap(filename)

if __name__ == "__main__":
    main()