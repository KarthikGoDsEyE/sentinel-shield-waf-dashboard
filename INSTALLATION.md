---

## ⚙️ Installation & Setup

Follow these steps to run the project:

---
🔹 Step 1: Clone Repository
git clone https://github.com/KarthikGoDsEyE/sentinel-shield-waf-dashboard.git
cd sentinel-shield-waf-dashboard
🔹 Step 2: Install Dependencies
	pip install flask matplotlib
🔹 Step 3: Configure ModSecurity Log Path

	Ensure the correct log path in your code:

	LOG_FILE = "/var/log/apache2/modsec_audit.log"
🔹 Step 4: Start Required Services
	sudo service apache2 start
	sudo service mysql start
🔹 Step 5: Setup DVWA

	1.Open:http://127.0.0.1/dvwa

	2.Login

	3.Set Security Level → Low

🔹 Step 6: Run Dashboard
	python3 app.py

	Open:http://127.0.0.1:5000
🔹 Step 7: Run Log Analyzer
	python3 log_analyzer.py
🔹 Step 8: Clear Logs Before Testing
	sudo truncate -s 0 /var/log/apache2/modsec_audit.log
🔹 Step 9: Perform Attack Testing
	SQL Injection: ' OR '1'='1
	XSS: <script>alert(1)</script>
	Command Injection: 127.0.0.1; whoami
🔹 Step 10: View Results

	1.Dashboard → http://127.0.0.1:5000

	2.Terminal → Log Analyzer output
