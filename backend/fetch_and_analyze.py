print("🔥 Script started")

import json
import subprocess
import os
import sys

print("✅ Imports successful")

OUTPUT_DIR = "backend/data"
OUTPUT_FILE = f"{OUTPUT_DIR}/security_analysis.json"
ALLOWED_PORTS = [80, 443]

try:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("✅ Data directory ready")
except Exception as e:
    print("❌ Failed to create data directory:", e)
    sys.exit(1)

print("🚀 Running AWS CLI command...")

try:
    result = subprocess.run(
        ["aws", "ec2", "describe-security-groups", "--output", "json"],
        capture_output=True,
        text=True
    )
except Exception as e:
    print("❌ AWS CLI execution failed:", e)
    sys.exit(1)

print("✅ AWS CLI command executed")

if result.stderr:
    print("❌ AWS CLI error:")
    print(result.stderr)
    sys.exit(1)

print("📦 Parsing AWS output...")

try:
    security_groups = json.loads(result.stdout)
except Exception as e:
    print("❌ JSON parsing failed:", e)
    sys.exit(1)

results = []

for sg in security_groups.get("SecurityGroups", []):
    for perm in sg.get("IpPermissions", []):
        for ip in perm.get("IpRanges", []):
            if ip.get("CidrIp") == "0.0.0.0/0":
                port = perm.get("FromPort")

                risk = (
                    "ALLOWED (80/443)"
                    if port in ALLOWED_PORTS
                    else "HIGH RISK"
                )

                results.append({
                    "SecurityGroupName": sg.get("GroupName"),
                    "SecurityGroupId": sg.get("GroupId"),
                    "Protocol": perm.get("IpProtocol"),
                    "PortRange": f"{port}-{perm.get('ToPort')}",
                    "OpenTo": "0.0.0.0/0",
                    "Risk": risk
                })

print(f"📊 Found {len(results)} public rules")

try:
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=4)
    print(f"✅ File written to {OUTPUT_FILE}")
except Exception as e:
    print("❌ Failed to write file:", e)
    sys.exit(1)

print("🎉 Script completed successfully")
