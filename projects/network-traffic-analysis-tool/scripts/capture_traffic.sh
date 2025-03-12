## Web scrapping:
# - using tcpdump, do packet capture for 60s for each website
# - save pcap in specified folder
# Make sure to allow the script to have execution permission before running (chmod +x ./script.sh)



#!/bin/bash

# Configuration
URL_LIST="./projects/network-traffic-analysis-tool/docs/websites.txt"  # File containing list of websites (one per line)
OUTPUT_DIR="./projects/network-traffic-analysis-tool/data"  # Directory to store pcap files
SCRAPING_DURATION=60  # Capture time per website in seconds (modify as needed)
INTERFACE="en0"  # Change this to the correct network interface (use `ip a` to check)

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Function to scrape website traffic
scrape_website() {
    local website=$1
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local domain=$(echo "$website" | awk -F/ '{print $3}')  # Extract domain from URL
    local pcap_file="${OUTPUT_DIR}/${domain}_${timestamp}.pcap"

    echo "\nStarting packet capture for \033[1m$website...\033[0m"
    sudo tcpdump -i "$INTERFACE" -w "$pcap_file" &
    PID=$!  # Get the process ID of tcpdump

    echo "Fetching $website..."
    curl -s "$website" > /dev/null 2>&1  # or use `wget -qO- "$website"` for alternative

    sleep "$SCRAPING_DURATION"  # Capture for defined time

    echo "\nStopping packet capture..."
    sudo kill "$PID"

    echo "Saved: $pcap_file"
}

# Main loop to iterate through websites.txt
if [[ ! -f "$URL_LIST" ]]; then
    echo "\n\033[1;31mERROR:\033[0m: $URL_LIST not found!"
    exit 1
fi

while IFS= read -r website; do
    [[ -z "$website" || "$website" == \#* ]] && continue  # Skip empty lines and comments
    scrape_website "$website"
done < "$URL_LIST"

echo "\n\033[1;32mAll captures completed.\033[0m PCAP files saved in '$OUTPUT_DIR'."