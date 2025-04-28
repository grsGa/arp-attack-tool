# Advanced ARP Spoofing Tool 🔍

## 🚨 Disclaimer

**Warning: This tool is for security research and educational purposes only. Unauthorized use may constitute illegal activity, and users are solely responsible for their actions.**

## 🌐 Project Overview

An advanced ARP (Address Resolution Protocol) attack tool designed for network security research and penetration testing. This tool provides multiple ARP attack strategies to help security researchers understand and simulate network man-in-the-middle attacks.

## ✨ Key Features

- Multiple ARP Attack Strategies
- Flexible Target Selection
- Automatic Network Interface Detection
- Real-time Network Activity Monitoring
- Packet Sniffing
- Automatic IP Forwarding Management
- Automatic Network Restoration

## 🛠 Attack Strategies

### 1. Standard ARP Attack
- Forge ARP Responses
- Hijack Target Network Traffic

### 2. Gratuitous ARP Attack
- Send Unsolicited ARP Packets
- Force Network Device ARP Cache Update

### 3. Man-in-the-Middle (MITM) Attack
- Simultaneously Spoof Target and Gateway
- Optional Packet Sniffing
- Intercept and Analyze Network Traffic

## 🔧 Technical Principles

### ARP Protocol Attack Mechanism
1. ARP Cache Poisoning
2. Forged ARP Responses
3. Network Communication Hijacking

### Key Technical Implementations
- Multi-threaded Concurrent Attacks
- Dynamic MAC Address Retrieval
- Real-time Network Monitoring
- Automatic Attack State Refresh

## 📦 Dependencies

- scapy
- psutil
- colorama
- threading
- logging

## 🚀 Usage

```bash
# Creating a Python Virtual Environment
$ python -m venv arp-attack-tool

# Enter the virtual environment folder
$ cd arp-attack-tool

# Create a src folder
$ mkdir src

# Move arp_attack.py to the src folder
$ move arp_attack.py src/

# Activate the virtual environment (Powershell needs to enable the command to allow all scripts to run: Set-ExecutionPolicy -ExecutionPolicy Unrestricted)
$ .\Scripts\activate

# Install necessary libraries
$ pip install -r requirements.txt

# Go to the src folder
$ cd src

# Execute Script
$ python arp_attack.py

# Exit the virtual environment
$ deactivate
```

### Interactive Process
1. Select Network Interface
2. Enter Gateway IP
3. Enter Target IPs
4. Choose Attack Strategy
5. Configure Attack Parameters

## 🛡 Security Protection Recommendations

- Use Static ARP Tables
- Enable ARP Firewall
- Monitor Abnormal Network Traffic
- Regularly Update Network Device Firmware

## 📝 Precautions

- Use Only in Authorized Environments
- Comply with Laws and Professional Ethics
- Protect Personal and Organizational Privacy

## 🔬 Learning Objectives

This tool aims to:
- Understand ARP Protocol Vulnerabilities
- Raise Network Security Awareness
- Learn Network Attack and Defense Techniques

## 🤝 Contributions and Feedback

Issues and Pull Requests are welcome!

---

**Security begins with understanding vulnerabilities, but should never aim to cause destruction.**
