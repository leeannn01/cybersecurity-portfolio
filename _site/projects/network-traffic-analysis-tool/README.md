# Network Traffic Analysis Toolkit
**File Name**: 'cybersecurity-portfolio/projects/network-traffic-analysis-tool/README.md

**Purpose**: Detailed Documentation for the Network Analysis Toolkit

## Project Overview
The Network Traffic Analysis Toolkit analyzes network traffic **from PCAP files** to detect anomalies and visualize trends.  
**Goal**: Improve **threat detection** in network environments.  
**Key Techniques**: Packet capture, Python analysis, anomaly detection, visualisation of network traffic anomaly


## Table of Contents  
- [Project Structure](#project-structure)
- [About This Project](#about-this-project)  
- [Installation & Setup](#installation--setup)  
- [Usage](#usage)  
- [Future Enhancements](#future-enhancements)  

## Project Structure
```
network-traffic-analysis-tool/  
├──README.md                            # Project details
├── src                                 # Python scripts for processing
|   ├── analyser.py                         # Analyser script
|   ├── detector.py                         # Detection script (Malware detection)
|   └── visualiser.py                       # Visualiser script
├── scripts/                            # Bash scripts 
|   ├── capture_traffic.sh                  # tcpdump automation
|   ├── run_pcap_analysis.sh                # Automated run of src scripts
├── docs/                               # Documentation and reports
│   ├── websites.txt                        # List of website to scraped
│   └── manuf                               # MAC address OUI Lookup
├── data/                               # Folder (PCAP files - from both web scrapping/downloaded)
|   ├── pcap1
|   └── pcap2
└── results/                            # All analysed results saved within 
    └── pcap1
        ├── downloads_pcap1/            # Downlable content within payload saved within 
        |   ├── .jpeg
        |   └── .bmp
        ├── payload_pcap1.txt           # Payload extracted
        ├── pcap1.csv                   # Packet Data extracted
        ├── Malicious Traffic/          # Results from Detector saved within (a csv and text summary)
        |   ├── malicious_summary_pcap1.txt
        |   └── malicious_traffic_pcap1.csv
        └── Visuals/                    # Results from Visualiser
```

## About This Project
### **Description:**  
A set of Python and Bash scripts for **capturing, analyzing, detecting, and visualizing** network traffic patterns and security threats from PCAP files.  

This toolkit is designed for **security researchers and network analysts** to:
- Capture live network traffic.  
- Analyze `.pcap` files for security insights.  
- Detect suspicious patterns (e.g., DoS attacks, unauthorized access).  
- Visualize network trends with **Python & Matplotlib**.

### Skills & Technologies Used: 
- **Programming & Scripting:** Python, Bash, PowerShell  
- **Networking & Security:** Wireshark, Tcpdump, Scapy, pyshark
- **Data Analysis & Visualization:** Pandas, Matplotlib  

### **Files & Scripts:**  
- [`capture_traffic.sh`](scripts/capture_traffic.sh) - Captures network traffic using `tcpdump`.  
- [`run_pcap_analysis.sh`](scripts/run_pcap_analysis.sh) - Automates packet analysis from captured files.  
- [`analyzer.py`](scripts/analyzer.py) - Extracts network insights from PCAP files.  
- [`detector.py`](scripts/detector.py) - Identifies anomalies in traffic.  
- [`visualizer.py`](scripts/visualizer.py) - Generates visual reports of network traffic.  

### Quick Links:
1. **[View My SRC code](./src/)**  
2. **[View My bash scripts](./scripts/)**  
3. **[Read My Project Writeup](./pages/blog.md)**  
4. **[Contact Me](./pages/contact.md)**  


## **Installation & Setup:** 
This project is built using **Python** and **Bash**

### To view the portfolio locally:
```bash
git clone https://github.com/yourusername/cybersecurity-portfolio.git
cd ./network-traffic-analysis-tool
```

### Install Dependencies
```bash
pip install scapy pandas matplotlib pyshark
```

### Setup Permissions
```bash
chmod +x scripts/* .sh

```


## Usage
```bash
bash ./scripts/capture_traffic.sh     # Start capturing network traffic
bash ./scripts/run_pcap_analysis      # Analyse a pcap file (Automated run: analyse-detect-visualise)
python ./src/analyser.py ./data/sample.pcap    # Analyse a single pcap
```


## Future Enhancements  
Planned improvements for my Network Traffic Analysis Toolkit:  
- [ ] Implement a machine learning model for traffic anomaly detection.  
- [ ] Expand visualization to include real-time monitoring dashboards.  
