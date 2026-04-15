# Network Packet Analyzer with Basic Intrusion Detection

## Overview
This project is a Python-based network packet analyzer that captures live network traffic and performs basic intrusion detection. It monitors packets in real time, identifies protocols, tracks traffic patterns, and detects suspicious activities such as high traffic rates and potential port scans.

Built using Scapy, the tool provides insights into network behavior and demonstrates foundational concepts used in network security and intrusion detection systems.

---

##  Features
-  Real-time packet capture
-  Protocol detection (TCP, UDP, ICMP)
-  Packet statistics tracking
-  High traffic detection (rate-based)
-  Port scan detection
-  Basic payload inspection (detects keywords like "login", "password")
-  Organized logging system with timestamped files

---

## 🛠️ Tech Stack
- Python
- Scapy

---

## Project Structure
network-analyzer/
├── analyzer.py
├── requirements.txt
├── README.md
├── logs/
│   └── sample_log.txt
└── screenshots/
