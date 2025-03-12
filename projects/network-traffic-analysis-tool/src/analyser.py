# # ## Extract packet data from a .pcap file and save it as a CSV in results/.

'''
Packet analysis:
1. Packet info (time, source, destination, source_vendor, destination_vendor, protocol, length, sport, dport, payload)
    a. Protocol Mapping (using Pyshark)
    b. MAC Vendor Lookup from Wireshark’s manuf file
2. Extract all downloadable file & payload (make use of FILE Signature)
'''

import os
import sys
import binascii
import pandas as pd
import csv
import pyshark
from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, Raw
from collections import defaultdict
from datetime import datetime

# ** Path to Wireshark's OUI Manufacturer File **
MANUF_FILE = "./projects/network-traffic-analysis-tool/docs/manuf"
MAC_MANUFACTURERS = {}

### ** Load MAC Vendors from Wireshark's manuf File **
def load_mac_manufacturers():
    """Loads the Wireshark 'manuf' file into a dictionary for MAC address lookup."""
    if not os.path.exists(MANUF_FILE):
        print(f"\n\033[1;33mWarning:\033[0m Wireshark 'manuf' file not found at {MANUF_FILE}. MAC lookups will be 'Unknown'.")
        return

    with open(MANUF_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("#") or line.strip() == "":
                continue  # Skip comments and empty lines
            parts = line.split("\t")
            if len(parts) >= 2:
                oui_prefix = parts[0].strip().lower()  # Extract OUI (first 3 bytes)
                manufacturer = parts[1].strip()
                MAC_MANUFACTURERS[oui_prefix] = manufacturer

def get_mac_vendor(mac_address):
    """Get vendor name for a MAC address using the Wireshark OUI database."""
    mac_prefix = mac_address[:8].lower()  # Extract first 3 bytes (OUI)
    return MAC_MANUFACTURERS.get(mac_prefix, "Unknown Device")

# Load MAC Vendor Database
load_mac_manufacturers()

# ** File Signatures (Magic Numbers) for Extraction **
FILE_SIGNATURES = {
    b"\xFF\xD8\xFF": ("jpg", b"\xFF\xD9"),
    b"\x89\x50\x4E\x47": ("png", b"\x49\x45\x4E\x44\xAE\x42\x60\x82"),
    b"\x47\x49\x46\x38": ("gif", b"\x00\x3B"),
    b"\x25\x50\x44\x46": ("pdf", b"\x25\x25\x45\x4F\x46"),
    b"\x50\x4B\x03\x04": ("zip", b"\x50\x4B\x05\x06"),
    b"\x49\x44\x33": ("mp3", None),
    b"\x42\x4D": ("bmp", None),
}

# ** Extract Protocol Classification using Pyshark **
def extract_pyshark_protocols(pcap_file):
    """Extracts high-level protocol names from PCAP using Pyshark."""
    cap = pyshark.FileCapture(pcap_file, display_filter="frame")
    protocol_map = {}

    for packet in cap:
        try:
            frame_number = int(packet.number)  # Wireshark's frame number
            protocol_name = packet.highest_layer  # The highest-level protocol
            protocol_map[frame_number] = protocol_name
        except AttributeError:
            continue  # Skip packets without a highest-layer field

    cap.close()
    return protocol_map

# ** Clean and Limit Payload Size **
def clean_payload(raw_payload):
    """Ensures payloads are readable and properly formatted for CSV storage."""
    if raw_payload is None:
        return ""

    try:
        decoded_payload = raw_payload.decode('utf-8', errors='ignore')
        return decoded_payload.strip()[:100]  # Limit to 100 chars to prevent Excel overflow
    except Exception:
        return binascii.hexlify(raw_payload).decode()[:100]  # Return hex if decoding fails

# ** Extract Downloadable Files & TCP Payloads **
def extract_files_and_payloads(packets, output_folder, pcap_filename):
    """Extracts downloadable files and saves full TCP stream payloads."""
    tcp_streams = defaultdict(bytes)
    extracted_files = 0
    payloads_saved = False
    temp_downloads = {}

    print("\n\033[1mExtracting TCP streams and payloads...\033[0m")
 
    # Step 1: Reassemble TCP Streams
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            stream_id = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
            tcp_streams[stream_id] += bytes(packet[Raw].load)
 
    # Step 2: Save Payload Data (if present)
    payload_file = os.path.join(output_folder, f"payload_{pcap_filename}.txt")
    with open(payload_file, "w", encoding="utf-8", errors="ignore") as f_payload:
        for stream_id, data in tcp_streams.items():
            if data:
                src_ip, dst_ip, sport, dport = stream_id
                f_payload.write(f"\n--- TCP Stream {src_ip}:{sport} -> {dst_ip}:{dport} ---\n")
                f_payload.write(data.decode("utf-8", errors="ignore") + "\n")
                payloads_saved = True

    # Step 3: Search for File Signatures in TCP Streams
    for stream_id, data in tcp_streams.items():
        for signature, (extension, eof_marker) in FILE_SIGNATURES.items():
            start_idx = data.find(signature)
            if start_idx != -1:
                extracted_files += 1
                file_id = f"file_{extracted_files}.{extension}"
                temp_downloads[file_id] = data[start_idx:] if eof_marker is None else data[start_idx:data.find(eof_marker) + len(eof_marker)]

    # Only create downloads folder if files were extracted
    if extracted_files > 0:
        downloads_folder = os.path.join(output_folder, f"downloads_{pcap_filename}")
        os.makedirs(downloads_folder, exist_ok=True)

        for file_id, file_content in temp_downloads.items():
            file_path = os.path.join(downloads_folder, file_id)
            with open(file_path, "wb") as f:
                f.write(file_content)
            print(f"Extracted file saved: {file_path}")

    if not payloads_saved:
        os.remove(payload_file)  # Remove if no payloads found

# ** Main PCAP Analysis Function **
def extract_packet_data(pcap_file, output_folder):
    """Extracts packets from PCAP file and processes them into CSV."""
    packets = rdpcap(pcap_file)
    detected_protocols = set()
    pcap_filename = os.path.splitext(os.path.basename(pcap_file))[0]

    os.makedirs(output_folder, exist_ok=True)

    output_csv = os.path.join(output_folder, f"{pcap_filename}.csv")

    extract_files_and_payloads(packets, output_folder, pcap_filename)

    pyshark_protocols = extract_pyshark_protocols(pcap_file)  # Use Pyshark for protocol classification
    total_packets = len(packets)
    data = []

    for index, packet in enumerate(packets):
        frame_number = index + 1  # Frames in Wireshark start from 1
        packet_info = {
            "time": datetime.utcfromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S'),
            "source": None, "destination": None,
            "source_vendor": "Unknown", "destination_vendor": "Unknown",
            "protocol": "Unknown",
            "length": len(packet),
            "sport": None, "dport": None, "payload": "",
        }

        try:
            if packet.haslayer(Ether):
                packet_info["source"] = packet[Ether].src
                packet_info["destination"] = packet[Ether].dst
                packet_info["source_vendor"] = get_mac_vendor(packet[Ether].src)
                packet_info["destination_vendor"] = get_mac_vendor(packet[Ether].dst)

            if packet.haslayer(IP):
                packet_info["source"] = packet[IP].src
                packet_info["destination"] = packet[IP].dst

            if packet.haslayer(TCP):
                packet_info["sport"] = packet[TCP].sport
                packet_info["dport"] = packet[TCP].dport

            elif packet.haslayer(UDP):
                packet_info["sport"] = packet[UDP].sport
                packet_info["dport"] = packet[UDP].dport

            if packet.haslayer(Raw):
                packet_info["payload"] = clean_payload(bytes(packet[Raw].load))

            # Use Pyshark’s protocol classification
            protocol = pyshark_protocols.get(frame_number, "Unknown")
            # If protocol is DATA, further refine classification:
            if protocol == "DATA":
                if packet.haslayer(UDP) or (packet.haslayer(TCP) and int(packet[TCP].sport) > 49152):
                    protocol = "UDP"

            packet_info["protocol"] = protocol
            detected_protocols.add(protocol)

        except Exception as e:
            print(f"\n\033[31mError processing packet: {e}]033[0m")

        data.append(packet_info)

    df = pd.DataFrame(data)
    df.to_csv(output_csv, index=False)

    print(f"\n\033[1mAnalysis complete.\033[0m Data saved to {output_csv}")
    print(f"\033[1mDetected Protocols: \033[0m{', '.join(sorted(detected_protocols))}")
    print(f"\033[1mTotal packets searched: \033[0m{total_packets}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python analyser.py <input_pcap> <output_folder>")
        sys.exit(1)

    extract_packet_data(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()