from scapy.all import *
import sqlite3
import csv, os, threading, time
from datetime import datetime, timedelta
from collections import defaultdict

# --- 1. CONFIGURATION ---
LAN_IFACE = "eth1"  # Interface connected to Client VM [cite: 209]
WAN_IFACE = "eth0"  # Interface connected to Internet [cite: 206]
CSV_LOG_FILE = 'firewall_performance.csv'

# In-memory session tracker (State Table) [cite: 238, 239]
state_table = {} 
packet_stats = {'total': 0, 'allowed': 0, 'dropped': 0}

# IPS Tracking [cite: 451, 452, 453]
drop_tracker = defaultdict(list) 
BLACKLIST_THRESHOLD = 15  # Drops before blocking [cite: 452]
WINDOW_SECONDS = 60       # Rolling time window [cite: 453]
blocked_ips = set()

# --- 2. DATABASE LOGGING [cite: 250, 251] ---
def log_to_db(src, dst, sport, dport, status, reason):
    """Writes firewall decisions to the SQLite message bus."""
    try:
        conn = sqlite3.connect('firewall_logs.db')
        c = conn.cursor()
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        c.execute('INSERT INTO logs (timestamp, src, dst, sport, dport, status, reason) VALUES (?,?,?,?,?,?,?)',
                  (ts, src, dst, sport, dport, status, reason))
        conn.commit()
        conn.close()
        
        # Update real-time stats
        packet_stats['total'] += 1
        if status == 'ALLOW':
            packet_stats['allowed'] += 1
        else:
            packet_stats['dropped'] += 1
    except Exception as e:
        print(f"DB Error: {e}")

# --- 3. DYNAMIC IPS BLOCKING [cite: 441, 445, 464] ---
def check_and_block(src_ip):
    """Injects kernel rules if an IP exceeds the drop threshold."""
    now = datetime.now()
    window_start = now - timedelta(seconds=WINDOW_SECONDS)
    
    # Purge old timestamps from the window [cite: 461]
    drop_tracker[src_ip] = [t for t in drop_tracker[src_ip] if t > window_start]
    drop_tracker[src_ip].append(now)
    
    if len(drop_tracker[src_ip]) >= BLACKLIST_THRESHOLD and src_ip not in blocked_ips:
        blocked_ips.add(src_ip)
        # Inject OS-level block [cite: 464]
        os.system(f"sudo iptables -I FORWARD -s {src_ip} -j DROP")
        print(f" [IPS BLOCK] Dynamically blocked {src_ip} after {len(drop_tracker[src_ip])} drops.")

# --- 4. CSV PERFORMANCE LOGGER [cite: 367, 368, 394] ---
def csv_logger_thread():
    """Background thread to log performance snapshots every 10s."""
    if not os.path.exists(CSV_LOG_FILE):
        with open(CSV_LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'total', 'allowed', 'dropped', 'active_sessions']) 
            
    while True:
        time.sleep(10)
        with open(CSV_LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                             packet_stats['total'], packet_stats['allowed'], 
                             packet_stats['dropped'], len(state_table)])

# --- 5. CORE FIREWALL LOGIC (TCP STATE MACHINE) [cite: 216, 217] ---
def firewall_logic(packet):
    """Callback invoked for every captured TCP packet."""
    if not packet.haslayer(TCP): 
        return
        
    ip = packet[IP]
    tcp = packet[TCP]
    
    # Define session key: (src, dst, sport, dport) [cite: 218, 219]
    session = (ip.src, ip.dst, tcp.sport, tcp.dport)
    # Reverse key for matching responses
    rev_session = (ip.dst, ip.src, tcp.dport, tcp.sport)
    flags = tcp.flags

    # A. NEW SESSION: TCP SYN [cite: 220, 221]
    if flags == 'S': 
        state_table[session] = 'SYN_SENT'
        log_to_db(ip.src, ip.dst, tcp.sport, tcp.dport, 'ALLOW', 'NEW_SESSION')
        print(f"[+] NEW SESSION: {ip.src} -> {ip.dst}")

    # B. ESTABLISHED SESSION: Key exists in state table [cite: 224]
    elif session in state_table or rev_session in state_table:
        # Check for termination flags (FIN/RST) [cite: 226, 279]
        if 'F' in str(flags) or 'R' in str(flags):
            if session in state_table: del state_table[session]
            if rev_session in state_table: del state_table[rev_session]
            log_to_db(ip.src, ip.dst, tcp.sport, tcp.dport, 'ALLOW', 'SESSION_CLOSED')
        else:
            # Upgrade state to Established [cite: 283]
            current_key = session if session in state_table else rev_session
            state_table[current_key] = 'ESTABLISHED'
            log_to_db(ip.src, ip.dst, tcp.sport, tcp.dport, 'ALLOW', 'ESTABLISHED')

    # C. INVALID STATE: No SYN and No State [cite: 227, 228]
    else:
        log_to_db(ip.src, ip.dst, tcp.sport, tcp.dport, 'DROP', 'INVALID_STATE')
        check_and_block(ip.src)

# --- STARTUP ---
if __name__ == "__main__":
    # Start the background performance logger [cite: 371]
    threading.Thread(target=csv_logger_thread, daemon=True).start()
    
    print("==================================================")
    print("   STATEFUL PACKET INSPECTION ENGINE STARTED")
    print("   Architecture: Producer-Consumer (SQLite)")
    print("==================================================")
    
    # Sniff TCP traffic on both interfaces [cite: 210, 294]
    # store=0 is critical to prevent memory exhaustion [cite: 196, 294]
    sniff(iface=[LAN_IFACE, WAN_IFACE], filter="tcp", prn=firewall_logic, store=0)
