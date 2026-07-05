import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

def check_ip_virustotal(ip_address):
    url = f"{BASE_URL}/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]

    print(f"\nIP Address   : {ip_address}")
    print(f"Malicious    : {malicious}")
    print(f"Suspicious   : {suspicious}")
    print(f"Harmless     : {harmless}")

    if malicious > 0:
        verdict = "MALICIOUS"
    else:
        verdict = "CLEAN"

    print(f"Verdict      : {verdict}")

check_ip_virustotal("185.220.101.45")

