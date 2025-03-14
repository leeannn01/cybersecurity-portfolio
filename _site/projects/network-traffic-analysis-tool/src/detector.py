# ##Read the generated CSV and detect potentional malicious traffic, saving suspecious packets to results/malicious_traffic.csv
'''
Functions included
1. Suspicious Traffic filtering
    a. Suspicious payload detection (suspicious keywords)
    b. Larget packet size (suspect suspicious activity)
2. Traffic Direction analysis
3. Output: malicious_traffic_summary.txt & malicious_traffic.csv
'''

import os
import sys
import pandas as pd
from collections import defaultdict
import time
import ipaddress
import re

SUSPICIOUS_PORTS = {21, 22, 23, 53, 80, 443, 445, 1433, 1521, 3306, 3389}
LARGE_PACKET_SIZE = 1500
SUSPICIOUS_KEYWORDS = ["cmd.exe", "powershell", "wget", "curl", "/bin/sh", "/bin/bash"]
BASE64_PATTERN = re.compile(r'(?i)(?:[A-Za-z0-9+/]{4}){5,}={0,2}')
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False

def contains_suspicious_payload(payload):
    if pd.isna(payload):
        return False
    payload_lower = str(payload).lower()
    if any(keyword in payload_lower for keyword in SUSPICIOUS_KEYWORDS):
        return True
    if BASE64_PATTERN.search(payload_lower):
        return True
    return False

def detect_malicious_traffic(input_csv, output_folder):
    pcap_filename = os.path.splitext(os.path.basename(input_csv))[0].replace("packet_data_", "")
    results_folder = os.path.join(output_folder, "Malicious_Traffic_Detected")
    os.makedirs(results_folder, exist_ok=True)

    with open(input_csv, "r", encoding="utf-8", errors="replace") as file:
        df = pd.read_csv(file, engine="python", on_bad_lines="skip")

    # print(f"Detected Columns: {df.columns.tolist()}")  # Debugging step

    if "payload" not in df.columns:
        print("⚠️ WARNING: 'payload' column not found in CSV. Suspicious payload detection will not work!")
        df["payload"] = ""

    df["length"] = pd.to_numeric(df["length"], errors="coerce").fillna(0).astype(int)
    df["sport"] = df["sport"].astype(str)
    df["dport"] = df["dport"].astype(str)

    # Apply payload detection function with NaN handling
    df["suspicious_payload"] = df["payload"].fillna("").apply(contains_suspicious_payload)

    total_packets = len(df)

    # Ensure the suspicious_payload column does not contain NaN values
    df["suspicious_payload"] = df["suspicious_payload"].fillna(False)

    # Add a new column to explain why each packet is suspicious
    df["suspicious_reason"] = ""

    df.loc[df["length"] > LARGE_PACKET_SIZE, "suspicious_reason"] += "Large packet size; "
    df.loc[df["sport"].isin(map(str, SUSPICIOUS_PORTS)), "suspicious_reason"] += "Suspicious source port; "
    df.loc[df["dport"].isin(map(str, SUSPICIOUS_PORTS)), "suspicious_reason"] += "Suspicious destination port; "
    df.loc[df["suspicious_payload"], "suspicious_reason"] += "Suspicious payload detected; "

    # Add Traffic Direction Analysis
    def classify_traffic_direction(row):
        src = row["source"]
        dst = row["destination"]
        src_internal = is_internal_ip(src)
        dst_internal = is_internal_ip(dst)

        if src_internal and not dst_internal:
            return "outbound"
        elif not src_internal and dst_internal:
            return "inbound"
        elif src_internal and dst_internal:
            return "internal"
        else:
            return "external"

    df["traffic_direction"] = df.apply(classify_traffic_direction, axis=1)

    # Now filter suspicious traffic
    suspicious_traffic = df[df["suspicious_reason"] != ""]

    total_malicious = len(suspicious_traffic)

    output_csv = os.path.join(results_folder, f"malicious_traffic_{pcap_filename}.csv")
    summary_file = os.path.join(results_folder, f"malicious_summary_{pcap_filename}.txt")

    if not suspicious_traffic.empty:
        # Remove source_ip and dest_ip since they duplicate 'source' and 'destination'
        suspicious_traffic = suspicious_traffic.drop(columns=["source_ip", "dest_ip"], errors="ignore")

        suspicious_traffic.to_csv(output_csv, index=False)
        print(f"Malicious traffic detected and saved to {output_csv}")
    else:
        print("No suspicious traffic detected.")

    summary_data = []
    if total_malicious > 0:
        summary_data.append(f"{total_malicious} suspicious packets detected out of {total_packets} packets searched! \n")
        summary_data.append("**Potential threats detected:**\n")

        for port in SUSPICIOUS_PORTS:
            port_count = len(suspicious_traffic[
                (suspicious_traffic["sport"] == str(port)) |
                (suspicious_traffic["dport"] == str(port))
            ])
            if port_count > 0:
                summary_data.append(f"  - **Port {port}:** {port_count} occurrences.")

        large_packet_count = len(suspicious_traffic[suspicious_traffic["length"] > LARGE_PACKET_SIZE])
        if large_packet_count > 0:
            summary_data.append(f"\n- **Large Packets Detected:** {large_packet_count} instances, possible data exfiltration or DoS activity.")

        payload_alert_count = suspicious_traffic["suspicious_payload"].sum()
        if payload_alert_count > 0:
            summary_data.append(f"\n- **Suspicious Payloads Detected:** {payload_alert_count} packets contain potentially malicious content.")

        # Add traffic direction summary
        traffic_counts = suspicious_traffic["traffic_direction"].value_counts()
        for direction, count in traffic_counts.items():
            summary_data.append(f"\n- **{direction.capitalize()} Traffic:** {count} suspicious packets.\n")

        summary_data.append("\n⚠️ **Recommended Actions:**\n")
        summary_data.append("  - Investigate flagged IPs using security tools.")
        summary_data.append("  - Analyze packet captures in Wireshark.")
        summary_data.append("  - Implement firewall rules to mitigate threats.")
        summary_data.append("  - Monitor outbound traffic for potential exfiltration.")

        with open(summary_file, "w") as f:
            f.write("\n".join(summary_data))

        print(f" Detailed summary report saved to {summary_file}")
    else:
        # print(" No suspicious traffic detected.")
        return
        
def main():
    if len(sys.argv) != 3:
        print("Usage: python detector.py <input_csv> <output_folder>")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_folder = sys.argv[2]
    detect_malicious_traffic(input_csv, output_folder)

if __name__ == "__main__":
    main()