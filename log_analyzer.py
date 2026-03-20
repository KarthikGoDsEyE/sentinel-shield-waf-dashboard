import re
import socket
from collections import Counter

LOG_FILE = "/var/log/apache2/modsec_audit.log"


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def analyze_logs():
    try:
        with open(LOG_FILE, "r", errors="ignore") as f:
            data = f.read()
    except Exception as e:
        print(f"Cannot read log file: {e}")
        return

    local_ip = get_local_ip()

    # Split full audit log into transactions
    transactions = re.split(r'(?=--[A-Za-z0-9]+-A--)', data)

    sql = 0
    xss = 0
    cmd = 0
    ip_list = []

    for tx in transactions:
        if not tx.strip():
            continue

        detected = None

        # Extract client IP
        ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', tx)
        ip = ip_match.group() if ip_match else None

        # Ignore local/self IP
        if ip == local_ip or ip == "127.0.0.1":
            ip = None

        # Detect attack family once per transaction
        if re.search(r'\b942\d{3}\b', tx):
            detected = "sql"
        elif re.search(r'\b941\d{3}\b', tx):
            detected = "xss"
        elif re.search(r'\b932\d{3}\b', tx):
            detected = "cmd"

        if detected == "sql":
            sql += 1
            if ip:
                ip_list.append(ip)

        elif detected == "xss":
            xss += 1
            if ip:
                ip_list.append(ip)

        elif detected == "cmd":
            cmd += 1
            if ip:
                ip_list.append(ip)

    ip_count = Counter(ip_list)

    reputation = {}
    for ip, count in ip_count.items():
        if count > 20:
            reputation[ip] = "High Risk"
        elif count > 5:
            reputation[ip] = "Medium Risk"
        else:
            reputation[ip] = "Low Risk"

    total = sql + xss + cmd

    print("\n===== SentinelShield WAF Report =====\n")
    print("Attack Summary:")
    print(f"SQL Injection     : {sql}")
    print(f"XSS Attacks       : {xss}")
    print(f"Command Injection : {cmd}")
    print(f"Total Attacks     : {total}")

    print("\nTop Attacker IPs:")
    if ip_count:
        for ip, count in ip_count.most_common(5):
            print(f"{ip}: {count} attacks ({reputation[ip]})")
    else:
        print("No attacker IPs found")


if __name__ == "__main__":
    analyze_logs()
