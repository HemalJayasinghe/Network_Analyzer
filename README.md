# Network Traffic Analyzer v1.0

Real-time network packet capture and analysis tool with threat detection.
Monitors network traffic, identifies protocols, and detects suspicious patterns
like port scans and potential attacks.

---

## What It Does

1. Captures live network packets using Scapy
2. Identifies protocols (TCP, UDP, ICMP, DNS, ARP)
3. Tracks IP communications
4. Shows real-time traffic statistics
5. Detects suspicious patterns

---

## Technologies Used

- Python 3.8+
- Scapy (packet capture library)
- Npcap (Windows packet driver)
- Real-time packet processing

---

## How to Install

### Step 1: Install Npcap
Download and install from https://npcap.com/#download
**IMPORTANT: Restart computer after installing!**

### Step 2: Install Python library
```
pip install scapy
```

### Step 3: Run the analyzer
**Must run PowerShell as Administrator!**
```
python network_analyzer.py
```

---

## How to Use

1. Open PowerShell as Administrator
   - Search "PowerShell" in Start
   - Right-click → "Run as Administrator"

2. Navigate to folder
```
   cd path\to\network_Analyser
```

3. Run the program
```
   python network_analyzer.py
```

4. Generate traffic by browsing websites
   - The analyzer will capture for 30 seconds
   - Visit websites to see packets in real-time

5. View results
   - Protocol breakdown
   - Unique IPs seen
   - Total packets captured

---

## Sample Output
```
╔══════════════════════════════════════════════╗
║   NETWORK TRAFFIC ANALYZER v1.0 SIMPLE      ║
╚══════════════════════════════════════════════╝

[*] Starting packet capture for 30 seconds...

[TCP] 192.168.1.5 -> 142.250.185.206
[UDP] 192.168.1.5 -> 8.8.8.8
[ICMP] 192.168.1.5 -> 8.8.8.8

[*] Captured 10 packets...

CAPTURE COMPLETE!
Total packets: 87
Protocol breakdown:
  IP: 87
  TCP: 72
  UDP: 15
Unique IPs seen: 23
```

---

## Features

- **Real-time Monitoring** - See packets as they happen
- **Protocol Detection** - Identifies TCP, UDP, ICMP, DNS, ARP
- **IP Tracking** - Shows source and destination IPs
- **Statistics** - Protocol breakdown and unique IP count
- **Lightweight** - Minimal resource usage

---

## Important Notes

- **Administrator Required** - Must run PowerShell as Administrator
- **Npcap Required** - Windows packet capture driver
- **Legal Use Only** - Only monitor your own network
- **Educational Purpose** - For learning network security concepts

---

## How It Works

### Packet Capture Process
```
Network Interface → Npcap Driver → Scapy → Python Script
                                              ↓
                                    Process & Display
```

### What Gets Captured
- Source IP and Destination IP
- Protocol type (TCP/UDP/ICMP)
- Packet size
- Port numbers
- Real-time statistics

---


---

## Author

Hemal Jayasinghe

---

## License

MIT License - Educational use
