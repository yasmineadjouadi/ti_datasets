import requests
import json
import random
import time

URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt"

API_KEY = "042268ef6f012e4b8edb42f681e047bf1d67372aab5f12c8833d1a9496cfe2f0"

LIMIT_MALICIOUS = 200
LIMIT_CLEAN = 60
LIMIT_UNKNOWN = 10

OUTPUT_FILE = "ti_datasets_hash.json"


def call_function_virustotal(hash_value):

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    headers = {
        "x-apikey": API_KEY
    }

    try:

        response = requests.get(url, headers=headers)

        if response.status_code == 200:

            data = response.json()

            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

            if malicious > 0:
                return "malicious"
            else:
                return "clean"

        else:
            return "unknown"

    except:
        return "unknown"


def random_hash():

    return ''.join(random.choices("0123456789abcdef", k=64))


response = requests.get(URL)

if response.status_code != 200:
    print("Download failed")
    exit()

all_hashes = response.text.splitlines()

malicious_hashes = random.sample(all_hashes, LIMIT_MALICIOUS)

results = []

# --- MALICIOUS ---
for h in malicious_hashes:

    results.append({
        "type": "hash",
        "value": h,
        "Threat": "malicious"
    })


# --- CLEAN ---
for i in range(LIMIT_CLEAN):

    h = random_hash()

    results.append({
        "type": "hash",
        "value": h,
        "Threat": "clean"
    })


# --- UNKNOWN ---
for i in range(LIMIT_UNKNOWN):

    h = random_hash()

    results.append({
        "type": "hash",
        "value": h,
        "Threat": "unknown"
    })


random.shuffle(results)

with open(OUTPUT_FILE, "w") as f:

    json.dump(results, f, indent=4)


print("Dataset generated :", len(results))