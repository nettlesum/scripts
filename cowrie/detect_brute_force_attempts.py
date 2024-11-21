#!/usr/bin/env python3

# Identifies IP addresses with high-frequency login attempts
# in Cowrie logs flagging potential brute force sources based on a
# configurable threshold and time window

import json
from collections import defaultdict
from datetime import datetime, timedelta

# Configuration
ATTEMPT_THRESHOLD = 10  
TIME_WINDOW = timedelta(minutes=5)  

def parse_logs(file_path):
    login_attempts = defaultdict(list)

    with open(file_path, "r") as file:
        for line in file:
            try:
                log = json.loads(line)
                if log.get("eventid") in ["cowrie.login.failed", "cowrie.login.success"]:
                    ip = log.get("src_ip")
                    timestamp = datetime.fromisoformat(log.get("timestamp").rstrip("Z"))
                    login_attempts[ip].append(timestamp)
            except (json.JSONDecodeError, KeyError):
                continue

    return login_attempts

def identify_brute_force_ips(attempts):
    brute_force_ips = {}

    for ip, timestamps in attempts.items():
        timestamps.sort() 
        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + TIME_WINDOW
            attempts_in_window = sum(1 for t in timestamps if window_start <= t < window_end)

            if attempts_in_window >= ATTEMPT_THRESHOLD:
                brute_force_ips[ip] = attempts_in_window
                break 

    return brute_force_ips

def main():
    log_file = "cowrie.json" 
    print(f"analysing log file: {log_file}")

    login_attempts = parse_logs(log_file)
    brute_force_ips = identify_brute_force_ips(login_attempts)

    if brute_force_ips:
        for ip, count in brute_force_ips.items():
            print(f"IP: {ip}, ATTEMPTS: {count}")
    else:
        print("\nno brute force attempts detected.")

if __name__ == "__main__":
    main()
