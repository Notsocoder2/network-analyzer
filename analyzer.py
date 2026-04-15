from scapy.all import *
import time
import os

# Setup
os.makedirs("logs", exist_ok=True)
filename = f"logs/log_{int(time.time())}.txt"
log_file = open(filename, "a")

# Counters
packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0

# Tracking
ip_count = {}
ip_timestamp = {}
alerted_ips = set()
port_scan = {}
flows = {}

# Config
my_ip = "192.168.1.35"
router_ip = "192.168.1.1"
common_ports = {80, 443}


def process_packet(packet):
    global packet_count, tcp_count, udp_count, icmp_count

    if not packet.haslayer(IP):
        return

    packet_count += 1
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = dst_port = "-"
    protocol = "OTHER"

    if packet.haslayer(TCP):
        protocol = "TCP"
        tcp_count += 1
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        udp_count += 1
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        icmp_count += 1

    # High traffic detection
    ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
    if ip_count[src_ip] > 100 and src_ip not in alerted_ips:
        alert = (
            "\n" + "="*50 + "\n"
            "[ALERT] HIGH TRAFFIC DETECTED\n"
            f"Source IP: {src_ip}\n"
            + "="*50 + "\n"
        )
        print(alert)
        log_file.write(alert)
        alerted_ips.add(src_ip)

    # Port scan detection
    if protocol in ["TCP", "UDP"] and dst_port != "-":
        if src_ip not in port_scan:
            port_scan[src_ip] = set()
        port_scan[src_ip].add(dst_port)
        if len(port_scan[src_ip]) > 20 and src_ip not in alerted_ips:
            alert = (
                "\n" + "="*50 + "\n"
                "[ALERT] PORT SCAN DETECTED\n"
                f"Source IP: {src_ip}\n"
                + "="*50 + "\n"
            )
            print(alert)
            log_file.write(alert)
            alerted_ips.add(src_ip)

    # Check payload for sensitive keywords
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if b"login" in payload or b"password" in payload:
            alert = (
                "\n" + "="*50 + "\n"
                "[ALERT] SENSITIVE DATA DETECTED\n"
                f"Source IP: {src_ip}\n"
                + "="*50 + "\n"
            )
            print(alert)
            log_file.write(alert)

    # Log packet if not common port
    if dst_port not in common_ports:
        log_line = f"[{packet_count}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {protocol}"
        print(log_line)
        log_file.write(log_line + "\n")

    # Print stats every 30 packets
    if packet_count % 30 == 0:
        stats = (
            "\n-------- STATS --------\n"
            f"Total Packets: {packet_count}\n"
            f"TCP: {tcp_count} | UDP: {udp_count} | ICMP: {icmp_count}\n"
            "------------------------\n"
        )
        print(stats)
        log_file.write(stats + "\n")


# Start sniffing
print("Capturing packets... Press Ctrl+C to stop.\n")
try:
    sniff(iface="wlp1s0", filter="ip", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\nStopping capture...")
    log_file.close()