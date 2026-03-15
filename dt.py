import requests
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor
import os

URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt"

LIMITS = 2000

API_KEYS = [
"af8aeba02657ebe85cac81c8f3e1aa64a9a97e2c40db940e35d8675f8028f610",
"5ffb7905f7b959e5b0964c8bcb5f0d72277e7b449ee445b7fa126228858add61"
]

OUTPUT_FILE = "hash_dataset.json"

results = []

existing_data = []
existing_hashes = set()

if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        try:
            existing_data = json.load(f)
            existing_hashes = {item["value"] for item in existing_data}
        except:
            existing_data = []

def function_virustotal(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return None

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        if stats["malicious"] == 0:
            return None

        ptc = data["data"]["attributes"].get("popular_threat_classification")

        if ptc and "suggested_threat_label" in ptc:
            threat = ptc["suggested_threat_label"]
        else:
            threat = "malicious"

        print(hash_value, "→", threat)

        return {
            "type": "hash",
            "value": hash_value,
            "Threat": threat
        }

    except:
        return None


def worker(hash_value):
    if hash_value in existing_hashes:
        return

    for key in API_KEYS:
        result = function_virustotal(hash_value, key)

        if result:
            results.append(result)
            existing_hashes.add(hash_value)
            return

        time.sleep(1)


response = requests.get(URL)

if response.status_code != 200:
    print("Failed to download malicious hashes")
    exit()

all_hashes = response.text.splitlines()

hashes = random.sample(all_hashes, LIMITS)

with ThreadPoolExecutor(max_workers=2) as executor:
    executor.map(worker, hashes)

existing_data.extend(results)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(existing_data, f, indent=4)

print(len(results), "new hashes added")
print(len(existing_data), "total hashes in dataset")
