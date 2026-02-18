#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Traffic Analyzer v2.0
Captures network packets and generates HTML reports
"""

from scapy.all import *
import time
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import webbrowser

print("""
╔══════════════════════════════════════════════╗
║   NETWORK TRAFFIC ANALYZER v2.0             ║
╚══════════════════════════════════════════════╝
""")

# Create reports folder
reports_dir = Path('reports')
reports_dir.mkdir(exist_ok=True)

# Storage
packets_captured = 0
protocol_count = defaultdict(int)
ip_packet_count = defaultdict(int)
conversations = defaultdict(int)
alerts = []
packet_log = []

# Detection thresholds
PORT_SCAN_THRESHOLD = 10
ip_ports = defaultdict(set)

def process_packet(packet):
    """Process each packet"""
    global packets_captured
    packets_captured += 1
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Process IP packets
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        
        # Count packets per IP
        ip_packet_count[src] += 1
        
        # Track conversations
        conv = tuple(sorted([src, dst]))
        conversations[conv] += 1
        
        # TCP packets
        if packet.haslayer(TCP):
            protocol_count['TCP'] += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = str(packet[TCP].flags)
            
            # Track ports accessed
            ip_ports[src].add(dport)
            
            # Detect port scan
            if len(ip_ports[src]) > PORT_SCAN_THRESHOLD:
                existing = [a for a in alerts if a['src'] == src and a['type'] == 'PORT_SCAN']
                if not existing:
                    alerts.append({
                        'time': timestamp,
                        'type': 'PORT_SCAN',
                        'severity': 'HIGH',
                        'src': src,
                        'description': f"Port scan detected from {src}! Accessed {len(ip_ports[src])} ports."
                    })
                    print(f"\n[!] ALERT: Port scan from {src}")
            
            # Get service name
            service = get_service_name(dport)
            
            # Log packet
            packet_log.append({
                'time': timestamp,
                'protocol': 'TCP',
                'src': f"{src}:{sport}",
                'dst': f"{dst}:{dport}",
                'size': size,
                'info': f"{service} [{flags}]"
            })
            
            print(f"[TCP] {src}:{sport} -> {dst}:{dport} ({service})")
        
        # UDP packets
        elif packet.haslayer(UDP):
            protocol_count['UDP'] += 1
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            service = get_service_name(dport)
            
            packet_log.append({
                'time': timestamp,
                'protocol': 'UDP',
                'src': f"{src}:{sport}",
                'dst': f"{dst}:{dport}",
                'size': size,
                'info': service
            })
            
            print(f"[UDP] {src}:{sport} -> {dst}:{dport} ({service})")
        
        # ICMP packets
        elif packet.haslayer(ICMP):
            protocol_count['ICMP'] += 1
            
            packet_log.append({
                'time': timestamp,
                'protocol': 'ICMP',
                'src': src,
                'dst': dst,
                'size': size,
                'info': 'Echo Request/Reply (Ping)'
            })
            
            print(f"[ICMP] {src} -> {dst}")
    
    # ARP packets
    elif packet.haslayer(ARP):
        protocol_count['ARP'] += 1
    
    # DNS packets
    if packet.haslayer(DNS):
        protocol_count['DNS'] += 1
    
    # Progress
    if packets_captured % 10 == 0:
        print(f"\n[*] Captured {packets_captured} packets...\n")

def get_service_name(port):
    """Get service name for port"""
    services = {
        20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
    }
    return services.get(port, f'Port {port}')

def generate_html_report(start_time, duration):
    """Generate beautiful HTML report"""
    print("\n[*] Generating HTML report...")
    
    # Calculate stats
    total_protocols = sum(protocol_count.values())
    top_ips = sorted(ip_packet_count.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 50px 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .content {{ padding: 40px; }}
        .info-box {{
            background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
            border-left: 5px solid #667eea;
            padding: 20px;
            margin: 25px 0;
            border-radius: 5px;
        }}
        .info-box strong {{
            color: #667eea;
            display: inline-block;
            min-width: 180px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border: 2px solid #e9ecef;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }}
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        h2 {{
            color: #2d3748;
            margin: 40px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            font-size: 1.8em;
        }}
        .alert {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }}
        .alert.high {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }}
        .badge.high {{ background: #dc3545; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #f0f0f0;
            color: #333;
        }}
        tr:hover td {{
            background: #f8f9fa;
        }}
        .protocol-tcp {{ color: #007bff; font-weight: bold; }}
        .protocol-udp {{ color: #28a745; font-weight: bold; }}
        .protocol-icmp {{ color: #ffc107; font-weight: bold; }}
        .no-alerts {{
            background: #d4edda;
            border: 2px solid #28a745;
            padding: 30px;
            text-align: center;
            border-radius: 8px;
            color: #155724;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            color: #6c757d;
            border-top: 3px solid #e9ecef;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🌐 Network Traffic Analysis</h1>
        <div style="opacity: 0.9; font-size: 1.1em;">Security Traffic Report</div>
    </div>
    
    <div class="content">
        <div class="info-box">
            <div><strong>Capture Start:</strong> {start_time}</div>
            <div><strong>Capture End:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
            <div><strong>Duration:</strong> {duration:.1f} seconds</div>
            <div><strong>Total Packets:</strong> {packets_captured}</div>
            <div><strong>Security Alerts:</strong> {len(alerts)}</div>
        </div>
        
        <h2>📊 Traffic Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Packets</div>
                <div class="stat-number">{packets_captured}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">TCP Packets</div>
                <div class="stat-number">{protocol_count.get('TCP', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">UDP Packets</div>
                <div class="stat-number">{protocol_count.get('UDP', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">DNS Queries</div>
                <div class="stat-number">{protocol_count.get('DNS', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique IPs</div>
                <div class="stat-number">{len(ip_packet_count)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Alerts</div>
                <div class="stat-number" style="color: #dc3545;">{len(alerts)}</div>
            </div>
        </div>
"""
    
    # Add alerts
    html += "\n        <h2>🚨 Security Alerts</h2>\n"
    
    if alerts:
        for alert in alerts:
            severity = alert['severity'].lower()
            html += f"""
        <div class="alert {severity}">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <strong style="font-size: 1.1em;">{alert['type'].replace('_', ' ')}</strong>
                <span class="badge {severity}">{alert['severity']}</span>
            </div>
            <div style="color: #555;">
                <strong>Time:</strong> {alert['time']}<br>
                <strong>Source:</strong> {alert['src']}<br>
                <strong>Details:</strong> {alert['description']}
            </div>
        </div>
"""
    else:
        html += """
        <div class="no-alerts">
            <h3>✅ No Security Threats Detected</h3>
            <p>All network traffic appears normal.</p>
        </div>
"""
    
    # Top Talkers
    html += "\n        <h2>📡 Top Talkers (Most Active IPs)</h2>\n"
    html += """
        <table>
            <tr>
                <th>#</th>
                <th>IP Address</th>
                <th>Packets Sent</th>
                <th>Percentage</th>
            </tr>
"""
    
    for i, (ip, count) in enumerate(top_ips, 1):
        percentage = (count / packets_captured * 100) if packets_captured > 0 else 0
        html += f"""
            <tr>
                <td>{i}</td>
                <td style="color: #667eea; font-weight: bold;">{ip}</td>
                <td>{count}</td>
                <td>{percentage:.1f}%</td>
            </tr>
"""
    
    html += "        </table>\n"
    
    # Recent Packets
    html += "\n        <h2>📋 Recent Network Traffic (Last 20 Packets)</h2>\n"
    html += """
        <table>
            <tr>
                <th>Time</th>
                <th>Protocol</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Size</th>
                <th>Info</th>
            </tr>
"""
    
    recent = packet_log[-20:]
    for pkt in reversed(recent):
        proto_class = f"protocol-{pkt['protocol'].lower()}"
        html += f"""
            <tr>
                <td>{pkt['time']}</td>
                <td class="{proto_class}">{pkt['protocol']}</td>
                <td>{pkt['src']}</td>
                <td>{pkt['dst']}</td>
                <td>{pkt['size']} B</td>
                <td style="color: #666;">{pkt['info']}</td>
            </tr>
"""
    
    html += """        </table>
    </div>
    
    <div class="footer">
        <div style="font-size: 1.1em; margin-bottom: 8px;">
            Network Traffic Analyzer v2.0 by <strong>Hemal Jayasinghe</strong>
        </div>
        <div style="opacity: 0.7;">
            Generated on """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """
        </div>
    </div>
</div>
</body>
</html>
"""
    
    # Save report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"network_report_{timestamp}.html"
    filepath = reports_dir / filename
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[+] Report saved: {filepath.resolve()}")
    return str(filepath)

# ============================================================
# MAIN PROGRAM
# ============================================================

print("\n[*] Starting packet capture for 30 seconds...")
print("[*] Open websites in browser to generate traffic!\n")
print("-" * 50)

start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
capture_start = time.time()

try:
    # Capture packets
    sniff(prn=process_packet, timeout=60, count=500)
    
    duration = time.time() - capture_start
    
    print("\n" + "=" * 50)
    print("CAPTURE COMPLETE!")
    print("=" * 50)
    print(f"Total packets: {packets_captured}")
    print(f"Alerts: {len(alerts)}")
    
    # Generate report
    report_path = generate_html_report(start_time, duration)
    
    print("\n" + "=" * 50)
    print("✅ ANALYSIS COMPLETE!")
    print("=" * 50)
    
    # Open report
    open_report = input("\n[?] Open report in browser? (y/n): ").lower()
    if open_report == 'y':
        webbrowser.open(str(Path(report_path).resolve()))
        print("[+] Report opened in browser")

except PermissionError:
    print("\n[!] ERROR: Permission denied!")
    print("[!] Run PowerShell as Administrator")

except Exception as e:
    print(f"\n[!] Error: {e}")
    print("\nMake sure:")
    print("1. Npcap is installed")
    print("2. Running as Administrator")

input("\nPress Enter to exit...")