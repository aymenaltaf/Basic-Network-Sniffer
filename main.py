from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import init, Fore
from datetime import datetime
import os
import csv
import time

# Initialize colorama
init(autoreset=True)

# Get the folder where main.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Output file paths
LOG_FILE = os.path.join(BASE_DIR, "packet_log.txt")
PCAP_FILE = os.path.join(BASE_DIR, "captured_packets.pcap")
CSV_FILE = os.path.join(BASE_DIR, "packet_report.csv")

# Variables
packet_count = 0
captured_packets = []
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0
total_packet_size = 0
largest_packet = 0
smallest_packet = float('inf')

print(Fore.CYAN + "=" * 70)
print(Fore.CYAN + "        CodeAlpha - Basic Network Sniffer")
print(Fore.CYAN + "=" * 70)

print(Fore.YELLOW + "\nChoose Packet Type\n")
print("1. TCP Packets")
print("2. UDP Packets")
print("3. ICMP Packets")
print("4. All IP Packets")

choice = input("\nEnter your choice (1-4): ")

if choice == "1":
    packet_filter = "tcp"
elif choice == "2":
    packet_filter = "udp"
elif choice == "3":
    packet_filter = "icmp"
elif choice == "4":
    packet_filter = "ip"
else:
    print(Fore.RED + "Invalid choice!")
    exit()

print(Fore.YELLOW + f"\nCapturing 20 {packet_filter.upper()} packets...\n")

# Create/Open Log File
log_file = open(LOG_FILE, "w")
log_file.write("CodeAlpha - Basic Network Sniffer\n")
log_file.write("=" * 70 + "\n")

# Create/Open CSV File
csv_file = open(CSV_FILE, "w", newline="")
csv_writer = csv.writer(csv_file)

# CSV Header
csv_writer.writerow([
    "Packet No", "Time", "Source IP", "Destination IP",
    "Protocol", "Packet Length", "Source Port", "Destination Port"
])

def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP", Fore.GREEN
    elif packet.haslayer(UDP):
        return "UDP", Fore.YELLOW
    elif packet.haslayer(ICMP):
        return "ICMP", Fore.MAGENTA
    else:
        return "OTHER", Fore.WHITE

def process_packet(packet):
    global packet_count, tcp_count, udp_count, icmp_count
    global other_count, total_packet_size
    global largest_packet, smallest_packet

    if packet.haslayer(IP):
        packet_count += 1
        captured_packets.append(packet)
        packet_size = len(packet)

        total_packet_size += packet_size

        # ✅ FIXED INDENTATION
        if packet_size > largest_packet:
            largest_packet = packet_size
        if packet_size < smallest_packet:
            smallest_packet = packet_size

        protocol, color = get_protocol(packet)

        if protocol == "TCP":
            tcp_count += 1
        elif protocol == "UDP":
            udp_count += 1
        elif protocol == "ICMP":
            icmp_count += 1
        else:
            other_count += 1

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source_port = ""
        destination_port = ""

        print(color + f"\nPacket #{packet_count}")
        print(color + "-" * 60)
        print(f"Time              : {current_time}")
        print(f"Source IP         : {packet[IP].src}")
        print(f"Destination IP    : {packet[IP].dst}")
        print(f"Protocol          : {protocol}")
        print(f"Packet Length     : {len(packet)} Bytes")

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            print(f"Source Port       : {source_port}")
            print(f"Destination Port  : {destination_port}")
        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            print(f"Source Port       : {source_port}")
            print(f"Destination Port  : {destination_port}")

        print("-" * 60)

        # Save to log file
        log_file.write(f"Packet #{packet_count}\n")
        log_file.write(f"Time              : {current_time}\n")
        log_file.write(f"Source IP         : {packet[IP].src}\n")
        log_file.write(f"Destination IP    : {packet[IP].dst}\n")
        log_file.write(f"Protocol          : {protocol}\n")
        log_file.write(f"Packet Length     : {len(packet)} Bytes\n")
        if source_port != "":
            log_file.write(f"Source Port       : {source_port}\n")
            log_file.write(f"Destination Port  : {destination_port}\n")
        log_file.write("-" * 60 + "\n")

        # Save to CSV
        csv_writer.writerow([
            packet_count, current_time, packet[IP].src, packet[IP].dst,
            protocol, len(packet), source_port, destination_port
        ])

# Capture start time
start_time = time.time()
capture_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
try:
    sniff(filter=packet_filter, prn=process_packet, store=False, count=20)
    
except KeyboardInterrupt:
    print(Fore.RED + "\nPacket Capture Interrupted!")
finally:
    # Close files
    log_file.close()
    csv_file.close()

    # Save packets
    if captured_packets:
        wrpcap(PCAP_FILE, captured_packets)

    # Capture end time
    end_time = time.time()
    capture_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    duration = end_time - start_time
    packets_per_second = packet_count / duration if duration > 0 else 0
    average_size = total_packet_size / packet_count if packet_count else 0

    print(Fore.CYAN + "=" * 70)
    print(Fore.YELLOW + "FINAL NETWORK SUMMARY")
    print(Fore.CYAN + "=" * 70)

    print(f"Total Packets       : {packet_count}")
    print(f"TCP Packets         : {tcp_count}")
    print(f"UDP Packets         : {udp_count}")
    print(f"ICMP Packets        : {icmp_count}")
    print(f"Other Packets       : {other_count}")
    print()
    print(f"Average Packet Size : {average_size:.2f} Bytes")
    print(f"Largest Packet      : {largest_packet} Bytes")
    print(f"Smallest Packet     : {smallest_packet} Bytes")
    print(Fore.CYAN + "=" * 70)

    # ✅ FIXED INDENTATION for summary/statistics/performance
    print(Fore.CYAN + "\n" + "=" * 70)
    print(Fore.GREEN + "Capture completed successfully!")
    print(Fore.GREEN + f"Total Packets Captured : {packet_count}")
    print(Fore.GREEN + f"Packet details saved to : {LOG_FILE}")
    print(Fore.GREEN + f"Packets saved to        : {PCAP_FILE}")
    print(Fore.GREEN + f"CSV Report saved to     : {CSV_FILE}")

    print(Fore.CYAN + "\n" + "=" * 70)
    print(Fore.YELLOW + "NETWORK STATISTICS")
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + f"TCP Packets   : {tcp_count}")
    print(Fore.YELLOW + f"UDP Packets   : {udp_count}")
    print(Fore.MAGENTA + f"ICMP Packets  : {icmp_count}")
    print(Fore.WHITE + f"Other Packets : {other_count}")

    print(Fore.CYAN + "\n" + "=" * 70)
    print(Fore.YELLOW + "CAPTURE PERFORMANCE")
    print(Fore.CYAN + "=" * 70)
    print(f"Capture Started : {capture_start}")
    print(f"Capture Ended   : {capture_end}")
    print(f"Duration        : {duration:.2f} seconds")
    print(f"Packets/Second  : {packets_per_second:.2f}")
    print(Fore.CYAN + "=" * 70)
