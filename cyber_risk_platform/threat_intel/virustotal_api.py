import requests
from config import VIRUSTOTAL_API_KEY

def get_virustotal_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()["data"]["attributes"]

        return {
            "ip": ip,
            "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
            "country": data.get("country") or "N/A",
            "isp": data.get("as_owner") or "N/A"
        }

    return {"error": "API failed"}