import json

input_file = "hashes.txt"
output_file = "hash_dataset.json"
dataset = []

with open(input_file, "r") as f:
    for line in f:
        parts = line.strip().split(",")
        if len(parts) == 2:
            hash_value, status = parts
            dataset.append({
                "type": "hash",
                "value": hash_value,
                "status": status
            })

with open(output_file, "w") as f:
    json.dump(dataset, f, indent=2)

print(f"{len(dataset)} hashes ajoutés dans {output_file}")