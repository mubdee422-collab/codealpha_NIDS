# CodeAlpha_NIDS
# Custom Python Network Intrusion Detection System (NIDS)

Hey everyone! This is Task 4 for my CodeAlpha Cybersecurity Internship. It's a lightweight, rate-based Network Intrusion Detection System built in Python using the `scapy` library.

---

### How It Works
- **Live Traffic Monitoring:** Sniffs packets flowing across the network interface in real-time.
- **Anomaly/Rate-Based Detection:** Tracks packet frequency per source IP within a sliding time window.
- **Alert Generation:** Flags and outputs a security alert when an IP address exceeds predefined packet frequency thresholds (indicative of port scanning or traffic floods).

---

### Prerequisites
1. **Python 3.x**
2. **Scapy library**:
   ```bash
   pip install scapy
