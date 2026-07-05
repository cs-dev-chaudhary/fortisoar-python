import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timezone


load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
WHOIS_KEY = os.getenv("WHOIS_API_KEY")

def check_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()

    if "data" not in data:
        return {"malicious": 0, "suspicious": 0, "error": "Not found in VirusTotal"}

    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "error": None
    }


def check_whois(domain):
    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    params = {
        "apiKey": WHOIS_KEY,
        "domainName": domain,
        "outputFormat": "JSON"
    }
    response = requests.get(url, params=params)
    data = response.json()

    if "WhoisRecord" not in data:
        return {"created": "Unknown", "registrar": "Unknown"}

    record = data["WhoisRecord"]
    created = record.get("createdDate", "Unknown")
    registrar = record.get("registrarName", "Unknown")
    return {
        "created": created,
        "registrar": registrar
    }


def investigate_domain(domain):
    
    print(f"Investigating: {domain}")
    print(f"{'='*45}")

    vt = check_virustotal_domain(domain)
    whois = check_whois(domain)
    if whois["created"] != "Unknown":
        created_date = datetime.fromisoformat(whois["created"].replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - created_date).days
        print(f"Domain Age   : {age_days} days")
        if age_days < 30:
            print("Warning      : NEWLY REGISTERED DOMAIN — high phishing risk")

    
    print(f"Created Date : {whois['created']}")
    print(f"Registrar    : {whois['registrar']}")
    if vt["error"]:
        print(f"VT Result    : {vt['error']}")
    else:
        print(f"VT Malicious : {vt['malicious']}")
        print(f"VT Suspicious: {vt['suspicious']}")

 
    if vt["malicious"] > 0:
        verdict = "MALICIOUS"
    else:
        verdict = "CLEAN"

    print(f"Verdict      : {verdict}")


domains = [
    "google.com",
    "facebook.com",
    "malware.testing.google.test",
    "paypal-secure-update.com"
]

for domain in domains:
    investigate_domain(domain)

