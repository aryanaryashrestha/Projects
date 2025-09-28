# ids.py - UPDATED WITH INTERFACE ARGUMENT + FIXED SYN DETECTION
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import psycopg2
from psycopg2 import sql
import argparse

# Debug flag - set to True to see detailed output
DEBUG = True

# Parse command line arguments
parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
parser.add_argument('--interface', '-i', default=None, help='Network interface to sniff on (e.g., wlan0, eth0)')
args = parser.parse_args()

port_scan_tracker = defaultdict(lambda: (set(), 0))
SCAN_THRESHOLD = 1
INACTIVITY_RESET = 60

def log_alert_to_db(src_ip, dst_ip, protocol, alert_type, severity, details):
    if DEBUG:
        print(f"[DEBUG] Trying to log alert to DB: {src_ip} -> {dst_ip}")
    
    db_params = {
        "host": "localhost",
        "database": "nids_db",
        "user": "nids_user",
        "password": "Projectfor@life"  # PLEASE CHANGE THIS!
    }

    conn = None
    try:
        if DEBUG:
            print("[DEBUG] Attempting database connection...")

        conn = psycopg2.connect(**db_params)
        cur = conn.cursor()

        if DEBUG:
            print("[DEBUG] Database connection successful. Preparing query...")

        query = sql.SQL("""
            INSERT INTO alerts (src_ip, dst_ip, protocol, alert_type, severity, details)
            VALUES (%s, %s, %s, %s, %s, %s)
        """)

        cur.execute(query, (src_ip, dst_ip, protocol, alert_type, severity, details))
        conn.commit()
        cur.close()
        print(f"[DB SUCCESS] Alert logged: {alert_type} from {src_ip}")
        return True

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"[DB ERROR] Failed to log alert: {error}")
        return False
    finally:
        if conn is not None:
            conn.close()
            if DEBUG:
                print("[DEBUG] Database connection closed.")

def detect_port_scan(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    dst_port = packet[TCP].dport
    current_time = time.time()

    # FIX: Proper SYN detection
    if packet[TCP].flags == 0x02:  # SYN only (not SYN-ACK)
        if DEBUG:
            print(f"[DEBUG] SYN packet detected: {ip_src} -> {ip_dst}:{dst_port}")

        port_set, last_time = port_scan_tracker[ip_src]

        if current_time - last_time > INACTIVITY_RESET:
            if DEBUG and len(port_set) > 0:
                print(f"[DEBUG] Reset tracker for IP: {ip_src}")
            port_set.clear()

        port_set.add(dst_port)
        port_scan_tracker[ip_src] = (port_set, current_time)

        unique_port_count = len(port_set)

        if DEBUG:
            print(f"[DEBUG] IP {ip_src} has scanned {unique_port_count} unique ports so far")

        if unique_port_count >= SCAN_THRESHOLD:
            alert_msg = f"Port Scan detected. Scanned ports: {unique_port_count}. Threshold: {SCAN_THRESHOLD}."
            if DEBUG:
                print(f"[DEBUG] Threshold exceeded! Should alert now: {alert_msg}")

            # Try to log to database
            success = log_alert_to_db(ip_src, ip_dst, "TCP", "Port Scan", "MEDIUM", alert_msg)

            if success:
                port_set.clear()
                if DEBUG:
                    print(f"[DEBUG] Cleared tracker for {ip_src} after successful DB log")
            else:
                print(f"[WARNING] Alert not logged to DB for {ip_src}")

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        detect_port_scan(packet)
    elif DEBUG:
        print(f"[DEBUG] Non-TCP packet: {packet.summary()}")

if __name__ == "__main__":
    print(f"[*] Starting NIDS. Monitoring for port scans (> {SCAN_THRESHOLD} unique connections).")
    print(f"[*] Interface: {args.interface if args.interface else 'default'}")
    print("[*] Press Ctrl+C to stop.\n")
    
    if DEBUG:
        print("[DEBUG] Sniffer starting now...")
    
    try:
        sniff(prn=packet_callback, store=0, iface=args.interface)
    except KeyboardInterrupt:
        print("\n[*] Stopping NIDS.")
    except Exception as e:
        print(f"[ERROR] Sniffer crashed: {e}")
