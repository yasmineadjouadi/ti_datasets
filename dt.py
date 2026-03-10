import requests
import json
import random
import time


URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt"
LIMITS = 10
API_KEY = "042268ef6f012e4b8edb42f681e047bf1d67372aab5f12c8833d1a9496cfe2f0" 
OUTPUT_FILE = "ti_datasets_hash.json"
SLEEP_API = 15  

def call_function_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            if stats["malicious"] > 0:
                ptc = data["data"]["attributes"].get("popular_threat_classification")
                if ptc and "suggested_threat_label" in ptc:
                    return ptc["suggested_threat_label"]
                else:
                    return "malicious"
            else:
                return "clean"
        else:
            return "unknown"
    except:
        return "unknown"


response = requests.get(URL)
if response.status_code != 200:
    print("Failed to download malicious hashes")
    exit()

all_hashes = response.text.splitlines()
hashes = random.sample(all_hashes, LIMITS)

results = []

for h in hashes:
    h = h.strip()
    if not h:
        continue

    malware_type = call_function_virustotal(h)

   
    if malware_type in ["clean", "unknown"]:
        continue

    
    results.append({
        "type": "hash",
        "value": h,
        "Threat": malware_type
    })

    print(h, "→", malware_type)
    time.sleep(SLEEP_API)  


with open(OUTPUT_FILE, "w") as f:
    json.dump(results, f, indent=4)

print(f" {len(results)} malicious hashes saved to '{OUTPUT_FILE}'")