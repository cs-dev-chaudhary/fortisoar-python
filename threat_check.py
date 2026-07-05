import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    data = response.json()["data"]
    return {
        "score": data["abuseConfidenceScore"],
        "country": data["countryCode"],
        "reports": data["totalReports"]
    }

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    response = requests.get(url, headers=headers)
    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"]
    }

def investigate_ip(ip):
    print(f"\n{'='*45}")
    print(f"Investigating: {ip}")
    print(f"{'='*45}")

    abuse = check_abuseipdb(ip)
    vt = check_virustotal(ip)

    print(f"Country          : {abuse['country']}")
    print(f"AbuseIPDB Score  : {abuse['score']}%")
    print(f"AbuseIPDB Reports: {abuse['reports']}")
    print(f"VT Malicious     : {vt['malicious']}")
    print(f"VT Suspicious    : {vt['suspicious']}")

    if abuse["score"] > 50 or vt["malicious"] > 5:
        verdict = "MALICIOUS"
    else:
        verdict = "CLEAN"

    print(f"Final Verdict    : {verdict}")

open("ip_report.txt", "w").close()

with open("suspicious_ips.txt") as f:
    ips = [line.strip() for line in f.readlines()]

for ip in ips:
    investigate_ip(ip)

