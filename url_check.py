import requests
import os
import base64
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

def check_url(url_to_check):
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    url = f"{BASE_URL}/urls/{url_id}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)
    data = response.json()


    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]

    print(f"\nURL          : {url_to_check}")
    print(f"Malicious    : {malicious}")
    print(f"Suspicious   : {suspicious}")
    print(f"Harmless     : {harmless}")

    if malicious > 0:
        verdict = "MALICIOUS"
    else:
        verdict = "CLEAN"

    print(f"Verdict      : {verdict}")

suspicious_urls = [
    "http://malware.testing.google.test/testing/malware/",
    "https://google.com",
    "https://www.facebook.com"
]

for url in suspicious_urls:
    check_url(url)
    print("-" * 45)

