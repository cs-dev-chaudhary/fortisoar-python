import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2"

def check_ip(ip_address):
    url = f"{BASE_URL}/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    score = data["data"]["abuseConfidenceScore"]
    country = data["data"]["countryCode"]
    total_reports = data["data"]["totalReports"]

    print(f"\nIP Address   : {ip_address}")
    print(f"Country      : {country}")
    print(f"Total Reports: {total_reports}")
    print(f"Abuse Score  : {score}%")

    if score > 50:
        verdict = "MALICIOUS"
    else:
        verdict = "CLEAN"

    print(f"Verdict      : {verdict}")

    with open("ip_report.txt", "a") as f:
        f.write(f"{ip_address} | {country} | Score: {score}% | Reports: {total_reports} | {verdict}\n")


open("ip_report.txt", "w").close()

with open("suspicious_ips.txt") as f:
    suspicious_ips = [line.strip() for line in f.readlines()]

for ip in suspicious_ips:
    check_ip(ip)
    print("-" * 40)

