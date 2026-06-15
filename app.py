from flask import Flask, render_template, request
import re
import hashlib

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    # Search History
    searched_password = ""
    searched_url = ""
    searched_software = ""
    searched_ip = ""
    searched_incident = ""

    # Password Module
    strength = ""
    score = 0
    crack_time = ""

    # Phishing Module
    phishing_result = ""
    phishing_score = 0

    # Vulnerability Module
    vulnerability_result = ""
    cve = ""
    severity = ""

    # Digital Forensics Module
    file_name = ""
    file_size = ""
    md5_hash = ""
    sha1_hash = ""
    sha256_hash = ""

    # Threat Intelligence Module
    threat_score = ""
    country = ""
    category = ""
    risk_level = ""

    # Incident Response Module
    incident_severity = ""
    incident_actions = []

    if request.method == "POST":

        # PASSWORD ANALYZER
        if "password" in request.form:

            password = request.form["password"]
            searched_password = password

            if len(password) >= 8:
                score += 1
            if re.search(r"[A-Z]", password):
                score += 1
            if re.search(r"[a-z]", password):
                score += 1
            if re.search(r"[0-9]", password):
                score += 1
            if re.search(r"[!@#$%^&*()_+=]", password):
                score += 1

            if score <= 2:
                strength = "Weak"
                crack_time = "Few Seconds"

            elif score <= 4:
                strength = "Medium"
                crack_time = "Several Days"

            else:
                strength = "Strong"
                crack_time = "Hundreds of Years"

        # PHISHING DETECTOR
        elif "url" in request.form:

            url = request.form["url"]
            searched_url = url

            suspicious_words = [
                "login",
                "verify",
                "secure",
                "update",
                "bank",
                "account",
                "paypal"
            ]

            url_lower = url.lower()

            if len(url) > 50:
                phishing_score += 20

            if not url.startswith("https://"):
                phishing_score += 20

            if re.search(r"\d+\.\d+\.\d+\.\d+", url):
                phishing_score += 30

            for word in suspicious_words:
                if word in url_lower:
                    phishing_score += 10

            if phishing_score >= 50:
                phishing_result = "Potential Phishing Website"
            else:
                phishing_result = "Likely Safe Website"

        # VULNERABILITY SCANNER
        elif "software" in request.form:

            software = request.form["software"]
            searched_software = software

            software = software.lower()

            if "windows" in software:
                cve = "CVE-2025-1001"
                severity = "HIGH"
                vulnerability_result = "Remote Code Execution Vulnerability"

            elif "chrome" in software:
                cve = "CVE-2025-2002"
                severity = "CRITICAL"
                vulnerability_result = "Memory Corruption Vulnerability"

            elif "apache" in software:
                cve = "CVE-2025-3003"
                severity = "MEDIUM"
                vulnerability_result = "Directory Traversal Vulnerability"

            else:
                cve = "No CVE Found"
                severity = "N/A"
                vulnerability_result = "Software not found in demo database"

        # DIGITAL FORENSICS
        elif "evidence_file" in request.files:

            file = request.files["evidence_file"]

            if file.filename != "":

                data = file.read()

                file_name = file.filename
                file_size = len(data)

                md5_hash = hashlib.md5(data).hexdigest()
                sha1_hash = hashlib.sha1(data).hexdigest()
                sha256_hash = hashlib.sha256(data).hexdigest()

        # THREAT INTELLIGENCE
        elif "ip_address" in request.form:

            ip = request.form["ip_address"]
            searched_ip = ip

            if ip.startswith("185."):
                threat_score = "92/100"
                country = "Germany"
                category = "Tor Exit Node"
                risk_level = "High"

            elif ip.startswith("103."):
                threat_score = "78/100"
                country = "India"
                category = "Suspicious Activity"
                risk_level = "Medium"

            elif ip.startswith("192."):
                threat_score = "15/100"
                country = "Private Network"
                category = "Internal Address"
                risk_level = "Low"

            else:
                threat_score = "50/100"
                country = "Unknown"
                category = "Unclassified"
                risk_level = "Medium"

        # INCIDENT RESPONSE
        elif "incident_text" in request.form:

            incident = request.form["incident_text"]
            searched_incident = incident

            incident = incident.lower()

            if "phishing" in incident:

                incident_severity = "HIGH"

                incident_actions = [
                    "Disconnect affected device",
                    "Reset user credentials",
                    "Enable MFA",
                    "Scan system for malware",
                    "Review email logs"
                ]

            elif "malware" in incident:

                incident_severity = "CRITICAL"

                incident_actions = [
                    "Isolate infected endpoint",
                    "Run antivirus scan",
                    "Remove malicious files",
                    "Check lateral movement",
                    "Restore clean backups"
                ]

            elif "ddos" in incident:

                incident_severity = "HIGH"

                incident_actions = [
                    "Enable traffic filtering",
                    "Block malicious IPs",
                    "Scale infrastructure",
                    "Contact ISP",
                    "Monitor traffic"
                ]

            else:

                incident_severity = "MEDIUM"

                incident_actions = [
                    "Collect logs",
                    "Investigate incident",
                    "Document findings",
                    "Monitor systems"
                ]

    return render_template(
        "index.html",
        strength=strength,
        score=score,
        crack_time=crack_time,
        phishing_result=phishing_result,
        phishing_score=phishing_score,
        vulnerability_result=vulnerability_result,
        cve=cve,
        severity=severity,
        file_name=file_name,
        file_size=file_size,
        md5_hash=md5_hash,
        sha1_hash=sha1_hash,
        sha256_hash=sha256_hash,
        threat_score=threat_score,
        country=country,
        category=category,
        risk_level=risk_level,
        incident_severity=incident_severity,
        incident_actions=incident_actions,
        searched_password=searched_password,
        searched_url=searched_url,
        searched_software=searched_software,
        searched_ip=searched_ip,
        searched_incident=searched_incident
    )

if __name__ == "__main__":
    app.run(debug=True)