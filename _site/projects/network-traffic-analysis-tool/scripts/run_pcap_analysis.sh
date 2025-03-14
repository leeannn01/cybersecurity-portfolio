## Automate src code for packet analysis


#!/bin/bash

# Define directories
PCAP_DIR="./projects/network-traffic-analysis-tool/data"
RESULTS_DIR="./projects/network-traffic-analysis-tool/results"
SRC_DIR="./projects/network-traffic-analysis-tool/src"

# Ensure the directories exist
if [[ ! -d "$PCAP_DIR" ]]; then
    echo "\n\033[1;31mError:\033[0m PCAP directory $PCAP_DIR does not exist!"
    exit 1
fi
mkdir -p "$RESULTS_DIR"

# List available PCAP files
echo "\033[1mAvailable PCAP files:\033[0m"
PCAP_FILES=($(ls "$PCAP_DIR"/*.pcap 2>/dev/null))
if [[ ${#PCAP_FILES[@]} -eq 0 ]]; then
    echo "\n\033[33mNo PCAP files found in $PCAP_DIR.\033[0m"
    exit 1
fi

# Display files with indices
for i in "${!PCAP_FILES[@]}"; do
    echo "[$i] ${PCAP_FILES[$i]##*/}"
done

# Ask user to select files
echo -n "Enter the indices of the PCAP files to analyse (comma-separated, e.g., 0,2,3): "
read -r INPUT

# Convert input to an array
IFS=',' read -r -a SELECTED_INDICES <<< "$INPUT"

# Run each selected file through the Python scripts
for INDEX in "${SELECTED_INDICES[@]}"; do
    if [[ "$INDEX" =~ ^[0-9]+$ ]] && [[ "$INDEX" -ge 0 ]] && [[ "$INDEX" -lt ${#PCAP_FILES[@]} ]]; then
        FILE="${PCAP_FILES[$INDEX]}"
        FILENAME=$(basename "$FILE" .pcap)

        echo "\n\033[1mProcessing: ${FILE##*/}\033[0m"

        # Define output file paths (NO SUBFOLDERS)
        PCAP_RESULT_CSV="$RESULTS_DIR/${FILENAME}"
        ANALYSER_CSV="$RESULTS_DIR/${FILENAME}/${FILENAME}.csv"
        DETECTOR_CSV="$RESULTS_DIR/${FILENAME}/Malicious_Traffic_Detected/malicious_traffic_${FILENAME}.csv"
        VISUALS_FOLDER="$PCAP_RESULT_CSV/Visuals"

        # Ensure results directory exists (without creating extra folders)
        mkdir -p "$RESULTS_DIR"

        # Run Analyser
        python3 "$SRC_DIR/analyser.py" "$FILE" "$PCAP_RESULT_CSV"

        # Ensure Analyser output exists before running Detector
        if [[ ! -f "$ANALYSER_CSV" ]]; then
            echo "\n\033[1;31mERROR:\033[0m Analyser failed! $ANALYSER_CSV not found."
            continue
        fi

        # Run Detector
        DETECTOR_OUTPUT=$(python3 "$SRC_DIR/detector.py" "$ANALYSER_CSV" "$PCAP_RESULT_CSV")

        if echo "$DETECTOR_OUTPUT" | grep -q "Malicious traffic detected"; then
            if [[ ! -f "$DETECTOR_CSV" ]]; then
                echo "\n\033[1;31mERROR:\033[0m Suspicious traffic detected, but $DETECTOR_CSV is missing!"
                continue
            fi
        else
            echo "\n\033[1;033mWARNING:\033[0m No malicious traffic detected. Skipping visualisation."
            continue
        fi
        
        # Run Visualiser (without creating extra folder)
        python3 "$SRC_DIR/visualiser.py" "$ANALYSER_CSV" "$DETECTOR_CSV" "$VISUALS_FOLDER"

        echo "\n\033[1;32mCompleted processing: ${FILE##*/}\033[0m"
    else
        echo "\033[1mInvalid index:\033[0m $INDEX"
    fi
done

echo "\033[1;32mAll selected files processed.\033[0m Results saved in $RESULTS_DIR"