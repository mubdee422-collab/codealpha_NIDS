from collections import defaultdict
import time
from scapy.all import IP, TCP, UDP, sniff

# Thresholds for anomaly detection (Detects packet floods / rapid scanning)
PACKET_THRESHOLD = 20  # Max packets allowed within the time window
TIME_WINDOW = 2.5  # Time window in seconds

# Tracking dictionary to store packet timestamps per source IP
ip_activity = defaultdict(list)


def detect_intrusion(packet):
  if packet.haslayer(IP):
    src_ip = packet.getlayer(IP).src
    dst_ip = packet.getlayer(IP).dst

    current_time = time.time()

    # Clean old timestamps outside the active time window
    ip_activity[src_ip] = [
        t for t in ip_activity[src_ip] if current_time - t < TIME_WINDOW
    ]
    # Record current packet timestamp
    ip_activity[src_ip].append(current_time)

    # Check if the IP has exceeded the threshold (Port Scan / Anomaly)
    if len(ip_activity[src_ip]) > PACKET_THRESHOLD:
      print(f"\n[!] ALERT: Potential Intrusion / Port Scan Detected!")
      print(f"    Source IP     : {src_ip}")
      print(f"    Packet Count  : {len(ip_activity[src_ip])} packets")
      print(f"    Target IP     : {dst_ip}")
      print(f"    Timestamp     : {time.strftime('%Y-%m-%d %H:%M:%S')}")
      print("-" * 50)
      ip_activity[src_ip] = []  # Reset counter to prevent alert spam

    protocol = (
        "TCP"
        if packet.haslayer(TCP)
        else "UDP"
        if packet.haslayer(UDP)
        else "OTHER"
    )
    print(
        f"[*] Monitoring -> Src: {src_ip} | Dst: {dst_ip} | Protocol:"
        f" {protocol}",
        end="\r",
    )


def main():
  print("[*] Starting Custom Python NIDS Engine...")
  print(
      f"[*] Rule: Alert if an IP sends > {PACKET_THRESHOLD} packets in"
      f" {TIME_WINDOW}s."
  )
  print("[*] Press Ctrl+C to stop.\n")
  sniff(prn=detect_intrusion, store=False)


if __name__ == "__main__":
  main()
