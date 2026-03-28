import requests
import socket
API_KEY = "22e37953b4be570b5e1f6ab133ca81c8b44eeba5ba2fa4973e3f5293f36a4bca"
def get_threat_data(target):
    try:
        # Resolve hostname/domain to IP address, since VT `/ip_addresses/` endpoint requires an IP
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target # Fallback if it's already an IP or resolution fails
            
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": API_KEY
        }
        response = requests.get(url, headers=headers)
        # DEBUG
        print("Status Code:", response.status_code)
        print("Response:", response.text)
        if response.status_code == 200:
            data = response.json()
            attributes = data["data"]["attributes"]
            return {
                "ip": ip,
                "abuse_score": attributes["last_analysis_stats"]["malicious"],
                "country": attributes.get("country", "N/A"),
                "isp": attributes.get("as_owner", "N/A")
            }
        else:
            return {"error": f"API failed with status {response.status_code} (Resolved IP: {ip})"}
    except Exception as e:
        return {"error": str(e)}