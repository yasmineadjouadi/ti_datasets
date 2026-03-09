import os
import json
import hashlib
import random
import string
import subprocess

# --- CONFIGURATION ---
github_repo = "https://github.com/CYB3RMX/MalwareHashDB.git"
github_folder = "MalwareHashDB"
output_file = "hash_dataset.json"
max_hashes = 500
num_clean_hashes = 5  # nombre de hashes clean à générer automatiquement

# --- HELPER : hash aléatoire ---
def random_hash(length=32):
    return ''.join(random.choices('0123456789abcdef', k=length))

dataset = []

# --- 1️⃣ Cloner GitHub si pas déjà présent ---
if not os.path.exists(github_folder):
    print(f"Clonage du repo {github_repo} ...")
    subprocess.run(["git", "clone", github_repo], check=True)

# --- 2️⃣ Ajouter les hashes malicieux depuis GitHub ---
hashdb_file = os.path.join(github_folder, "HashDB")
if os.path.exists(hashdb_file):
    with open(hashdb_file, "r", errors="ignore") as f:
        for line in f:
            hash_value = line.strip()
            if hash_value:
                dataset.append({"type": "hash", "value": hash_value, "status": "malicious"})
else:
    print(f"⚠️ Fichier HashDB introuvable dans {github_folder} !")

# --- 3️⃣ Ajouter des hashes clean directement ---
for i in range(num_clean_hashes):
    dataset.append({"type": "hash", "value": random_hash(), "status": "clean"})

# --- 4️⃣ Ajouter des hashes unknown aléatoires si nécessaire ---
while len(dataset) < max_hashes:
    dataset.append({"type": "hash", "value": random_hash(), "status": "unknown"})

# --- 5️⃣ Limiter à max_hashes ---
dataset = dataset[:max_hashes]

# --- 6️⃣ Écrire le JSON ---
with open(output_file, "w") as f:
    json.dump(dataset, f, indent=2)

print(f"✅ Dataset généré : {len(dataset)} hashes dans '{output_file}'")