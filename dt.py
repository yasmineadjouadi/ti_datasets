import requests
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor

URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt"

LIMITS = 2000

API_KEYS = [
"afaa2f23aff1727b8625ab49c95d6c603f1a4d6f33040308e74711c0099b1b0d",
"042268ef6f012e4b8edb42f681e047bf1d67372aab5f12c8833d1a9496cfe2f0"
]

OUTPUT_FILE = "hash_dataset.json"

SLEEP_API = 15

results = []


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

    for key in API_KEYS:

        result = function_virustotal(hash_value, key)

        if result:
            results.append(result)
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


with open(OUTPUT_FILE, "w") as f:
    json.dump(results, f, indent=4)


print(len(results), "malicious hashes saved to", OUTPUT_FILE)
