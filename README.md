# 🛰️ Basic Network Sniffer

A Python-based **Network Packet Sniffer** built using **Scapy** that captures, analyzes, and stores live network traffic. The application enables users to monitor packets in real time, filter protocols, generate reports, and save captured traffic for further analysis.


# 📖 Project Description

**Basic Network Sniffer** is a command-line cybersecurity tool developed in Python to capture and analyze live network packets from a selected network interface.

The application displays important packet information such as:

- Source IP Address
- Destination IP Address
- Protocol Type
- Packet Size
- Source Port
- Destination Port
- Capture Timestamp

Captured packets are automatically saved in multiple formats, including **TXT logs**, **CSV reports**, and **PCAP files**, making them suitable for later analysis using tools like **Wireshark**.

This project was developed as part of a **Cybersecurity Internship** to demonstrate practical knowledge of packet sniffing, networking concepts, and Python programming.


# ✨ Features

- ✅ Capture live network packets
- ✅ Support TCP, UDP, ICMP, and All IP packets
- ✅ Protocol-based packet filtering
- ✅ Display packet details in real time
- ✅ Log captured packets to a TXT file
- ✅ Export packet information to CSV
- ✅ Save packets in PCAP format
- ✅ Generate protocol statistics
- ✅ Measure capture performance
- ✅ Display a network traffic summary
- ✅ Colored terminal interface using Colorama
- ✅ Simple and beginner-friendly command-line interface


# 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python 3 | Programming Language |
| Scapy | Packet Capture & Analysis |
| Colorama | Colored Console Output |
| CSV | Report Generation |
| OS | File Handling |
| Datetime | Date & Time Management |
| Time | Performance Measurement |


# 📂 Project Structure

```text
BasicNetworkSniffer/
│
├── main.py
├── README.md
├── requirements.txt
├── packet_log.txt
├── packet_report.csv
├── captured_packets.pcap
└── screenshots/
    ├── menu.png
    ├── capture.png
    └── summary.png
```


# ⚙️ Installation

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/BasicNetworkSniffer.git
```

Or download the ZIP file.


## 2️⃣ Navigate to the Project Folder

```bash
cd BasicNetworkSniffer
```


## 3️⃣ Install Required Packages

```bash
pip install -r requirements.txt
```


# ▶️ Running the Application

Start the application using:

```bash
python main.py
```

> **Note:** Administrator (Windows) or Root (Linux/macOS) privileges may be required to capture live network packets.


# 📋 Application Menu

```text
===============================
      Choose Packet Type
===============================

1. TCP Packets
2. UDP Packets
3. ICMP Packets
4. All IP Packets

Enter your choice:
```


# 📊 Sample Output

```text
==============================================================
            CodeAlpha - Basic Network Sniffer
==============================================================

Packet #1

Time              : 2026-07-25 14:30:45
Source IP         : 192.168.1.5
Destination IP    : 20.189.173.18
Protocol          : TCP
Packet Length     : 66 Bytes
Source Port       : 53241
Destination Port  : 443
```


# 📈 Network Statistics

After packet capture, the program displays protocol statistics.

Example:

```text
=========================
NETWORK STATISTICS
=========================

TCP Packets   : 15
UDP Packets   : 4
ICMP Packets  : 1
Other Packets : 0
```


# ⚡ Capture Performance

The application also measures capture performance.

Example:

```text
=========================
CAPTURE PERFORMANCE
=========================

Capture Started : 2026-07-25 14:31:00
Capture Ended   : 2026-07-25 14:31:07
Duration        : 7.00 Seconds
Packets/Second  : 2.86
```


# 📄 Generated Files

| File | Description |
|------|-------------|
| `packet_log.txt` | Detailed packet log |
| `packet_report.csv` | Packet information in CSV format |
| `captured_packets.pcap` | Packet capture file for Wireshark |


# 📚 Networking Concepts Covered

This project demonstrates practical implementation of:

- Packet Sniffing
- TCP/IP Networking
- TCP Protocol
- UDP Protocol
- ICMP Protocol
- Source & Destination IP Analysis
- Port Monitoring
- Packet Logging
- CSV Report Generation
- PCAP File Creation
- Network Traffic Analysis
- Capture Performance Monitoring
- Basic Cybersecurity Monitoring


# 🎯 Learning Outcomes

By completing this project, you will understand:

- How packet sniffers operate
- How Scapy captures and processes packets
- Differences between TCP, UDP, and ICMP
- How to inspect packet information
- How to generate packet reports
- How to save captured traffic for future analysis
- Fundamentals of network monitoring using Python


# 📦 Requirements

Install the required libraries:

```text
scapy
colorama
```

Install them with:

```bash
pip install -r requirements.txt
```


# 📸 Screenshots

Place screenshots inside the `screenshots/` folder.

### Main Menu

```
screenshots/menu.png
```

### Packet Capture

```
screenshots/capture.png
```

### Final Summary

```
screenshots/summary.png
```


# 🚀 Future Enhancements

Possible improvements include:

- 🎨 Graphical User Interface (GUI)
- 📊 Live Network Dashboard
- 🔍 Advanced Packet Search & Filtering
- 🌐 DNS Hostname Resolution
- 🖥️ MAC Address Detection
- 📄 PDF Report Generation
- 🚨 Suspicious Traffic Detection
- 📈 Real-Time Graphs & Charts
- ⚡ Multi-threaded Packet Capture
- 📧 Email Alerts for Threat Detection


# 👨‍💻 Developed By

**Aymen Altaf**

**Cybersecurity Intern**

**Project:** Basic Network Sniffer By CodeAlpha

**Programming Language:** Python

**Libraries:** Scapy, Colorama

**Year:** 2026


# 📜 License

This project was developed for **educational and internship purposes**.

You are welcome to use, modify, and improve this project for learning and non-commercial use.


# 🙏 Acknowledgements

Special thanks to the **CodeAlpha Cybersecurity Internship Program** for providing the opportunity to develop practical cybersecurity projects and strengthen hands-on networking skills.
