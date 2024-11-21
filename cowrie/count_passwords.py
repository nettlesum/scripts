#!/usr/bin/env python3

# Counts and lists the most frequently used passwords from Cowrie logs, 
# including both successful and failed login attempts.

import json
from collections import Counter

def count_passwords(file_path, top_n=10):
    with open(file_path) as f:
        passwords = [
            json.loads(line).get("password", "")
            for line in f
            if any(e in line for e in ["cowrie.login.failed", "cowrie.login.success"])
        ]
    return Counter(passwords).most_common(top_n)

if __name__ == "__main__":
    for password, count in count_passwords("cowrie.json"):
        print(f"{password}: {count}")