# 🔐 SentinelShield WAF Dashboard

SentinelShield is a Web Application Firewall (WAF) monitoring system that analyzes ModSecurity audit logs to detect and visualize web attacks such as SQL Injection, Cross-Site Scripting (XSS), and Command Injection.

---

## 🚀 Project Overview

This project simulates a real-world web security monitoring system using:

- **DVWA (Damn Vulnerable Web Application)** for generating attacks  
- **ModSecurity (OWASP CRS)** as the Web Application Firewall  
- **Flask Dashboard** for visualization  
- **Python Log Analyzer** for accurate attack detection  

---

## 🎯 Features

- 🔍 Detects:
  - SQL Injection (CRS Rule 942xxx)
  - XSS Attacks (CRS Rule 941xxx)
  - Command Injection / RCE (CRS Rule 932xxx)

- 📊 Dashboard:
  - Attack count display
  - Graph visualization
  - Total attack summary

- 🌐 IP Tracking:
  - Top attacker IPs
  - Risk classification (Low / Medium / High)

- 🧠 Accurate Parsing:
  - Transaction-based log analysis
  - Avoids duplicate counting
  - Uses real ModSecurity rule IDs

---

## 🛠️ Tech Stack

- Python  
- Flask  
- ModSecurity (OWASP CRS)  
- DVWA  
- Matplotlib  

---

## 📁 Project Structure
SentinelShield/
│
├── app.py # Flask dashboard
├── log_analyzer.py # CLI log analyzer
├── templates/
│ └── index.html # Dashboard UI
├── static/
│ └── graph.png # Generated graph
├── README.md



## 📘 Installation Guide

👉 Full setup instructions available here:  
[Installation Guide](INSTALLATION.md)
