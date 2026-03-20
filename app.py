from flask import Flask, render_template
import re
import socket
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os

app = Flask(__name__)

LOG_FILE = "/var/log/apache2/modsec_audit.log"


# ✅ GET LOCAL IP
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


# ✅ ANALYZE LOGS (ACCURATE VERSION)
def analyze_logs():
    try:
        with open(LOG_FILE, "r", errors="ignore") as f:
            data = f.read()   # 🔥 FULL LOG (fix reset issue)
    except:
        return 0, 0, 0, {}, {}

    # Split transactions
    transactions = re.split(r'(?=--[A-Za-z0-9]+-A--)', data)

    sql = 0
    xss = 0
    cmd = 0
    ip_list = []

    local_ip = get_local_ip()

    for tx in transactions:
        if not tx.strip():
            continue

        tx_lower = tx.lower()

        # 🌐 Extract IP
        ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', tx)
        ip = ip_match.group() if ip_match else None

        if ip == local_ip or ip == "127.0.0.1":
            continue

        detected = None

        # ✅ SQL Injection (942 rules)
        if re.search(r'\b942\d{3}\b', tx):
            detected = "sql"

        # ✅ XSS (941 rules)
        elif re.search(r'\b941\d{3}\b', tx):
            detected = "xss"

        # ✅ Command Injection (932 rules)
        elif re.search(r'\b932\d{3}\b', tx):
            detected = "cmd"

        # Count only once per transaction
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

    # 🧠 Reputation
    reputation = {}
    for ip, count in ip_count.items():
        if count > 20:
            reputation[ip] = "High Risk 🔴"
        elif count > 5:
            reputation[ip] = "Medium Risk 🟠"
        else:
            reputation[ip] = "Low Risk 🟢"

    return sql, xss, cmd, ip_count, reputation


# ✅ GRAPH
def generate_graph(sql, xss, cmd):

    if not os.path.exists("static"):
        os.makedirs("static")

    labels = ["SQL", "XSS", "CMD"]
    values = [sql, xss, cmd]

    plt.figure()
    plt.bar(labels, values)
    plt.title("Attack Types")
    plt.savefig("static/graph.png")
    plt.close()


# ✅ DASHBOARD
@app.route("/")
def dashboard():

    sql, xss, cmd, ip_count, reputation = analyze_logs()

    generate_graph(sql, xss, cmd)

    total = sql + xss + cmd

    return render_template(
        "index.html",
        total=total,
        sql=sql,
        xss=xss,
        cmd=cmd,
        ip_count=ip_count,
        reputation=reputation
    )


# ✅ RUN
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
