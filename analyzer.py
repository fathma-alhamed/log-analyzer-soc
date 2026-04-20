import re
from collections import defaultdict

log_file = "logs/sample.log"

failed_logins = defaultdict(int)
ip_activity = defaultdict(int)

# Regex pattern
pattern = r"(login (failed|success) user=(\w+) ip=([\d\.]+))"

with open(log_file, "r") as file:
    logs = file.readlines()

for line in logs:
    match = re.search(pattern, line)
    if match:
        full_event = match.group(1)
        status = match.group(2)
        user = match.group(3)
        ip = match.group(4)

        ip_activity[ip] += 1

        if status == "failed":
            failed_logins[ip] += 1

print("\n🚨 SECURITY REPORT 🚨\n")

# Detect brute force
print("🔐 Brute Force Attempts:")
for ip, count in failed_logins.items():
    if count >= 3:
        print(f"⚠️ Suspicious IP: {ip} -> {count} failed logins")

# Detect high activity IPs
print("\n📊 IP Activity:")
for ip, count in ip_activity.items():
    if count > 3:
        print(f"⚠️ High activity IP: {ip} -> {count} events")
    else:
        print(f"✔️ Normal IP: {ip} -> {count} events")
