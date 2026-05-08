# Stateful-packet-inspection-Firewall
Stateful Packet Inspection (SPI) Firewall & IPS
🛡️ A Layer 4 Security Gateway for Virtualized Networks
This project implements a custom-built Stateful Packet Inspection (SPI) firewall engine and Intrusion Prevention System (IPS). Developed as a 6th-semester B.Tech Computer Science project, it bridges the gap between high-level Python logic and low-level Linux kernel enforcement.

🚀 Core Features
Layer 4 Stateful Inspection: Monitors the TCP 3-way handshake (SYN, SYN-ACK, ACK) to ensure only requested traffic enters the network.

Dynamic IPS Blocking: Automatically detects persistent threats and injects real-time iptables drop rules at the kernel level.

Hybrid Architecture: Combines Scapy for intelligent packet dissection with iptables for high-performance traffic enforcement.

Producer-Consumer Logging: Utilizes SQLite (WAL Mode) to handle concurrent write/read operations between the firewall engine and the dashboard.

Live Analytics: A Streamlit-based dashboard provides real-time visualization of traffic ratios and active threats.

🏗️ System Architecture
The environment is configured in Oracle VirtualBox with a dual-homed gateway setup:

Firewall Gateway (Kali Linux): * eth0 (WAN): Connected to the Internet.

eth1 (LAN): Connected to the internal private network.

Internal Client (Ubuntu/Debian):

Configured with a static IP and uses the Firewall as its default gateway.

🛠️ Tech Stack
Language: Python 3.x

Networking: Scapy, iptables, IPv4 Forwarding, NAT/Masquerading

Database: SQLite 3 (Write-Ahead Logging)

Visualization: Streamlit

Environment: Linux (Kali & Debian/Ubuntu), VirtualBox

📂 Project Structure
Bash
├── firewall_engine.py      # Core logic: Sniffing, State Machine, & IPS
├── dashboard.py            # Streamlit interface for real-time monitoring
├── firewall_logs.db        # SQLite database (auto-generated)
├── firewall_performance.csv # Periodic audit snapshots (auto-generated)
└── setup_gateway.sh        # Script to configure IP forwarding and NAT
⚙️ Logic & Enforcement
The Finite State Machine (FSM)
The engine tracks the sequence of TCP flags. If an inbound packet does not correspond to an established outbound request in the state_table, it is categorized as unsolicited and dropped.

The IPS Threshold
If a specific Source IP exceeds 15 drops within a 60-second window, the engine executes:

Bash
sudo iptables -I FORWARD -s <ATTACKER_IP> -j DROP
This offloads the security overhead to the Linux kernel, preventing CPU exhaustion in the Python engine during a flood.

🚦 How to Run
Configure the Gateway:
Enable IP forwarding and NAT on your Kali VM:

Bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
Start the Engine:

Bash
sudo python3 firewall_engine.py
Launch the Dashboard:

Bash
streamlit run dashboard.py
