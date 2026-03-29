import requests

class ThreatIntelAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def check_domain_reputation(self, domain):
        if not self.api_key or self.api_key == "YOUR_VIRUSTOTAL_API_KEY":
            return {"error": "Invalid or missing VirusTotal API key"}

        url = f"{self.base_url}/domains/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return stats
            elif response.status_code == 401:
                return {"error": "Unauthorized. Please check your API key."}
            else:
                return {"error": f"HTTP Error {response.status_code}"}
        except requests.exceptions.RequestException as e:
             return {"error": f"Network error: {e}"}
