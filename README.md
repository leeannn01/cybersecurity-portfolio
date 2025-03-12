# Cybersecurity Portfolio
Portfolio showcasing cybersecurity projects, insights, and learnings

## Table of Contents  
- [About This Portfolio](#about-this-portfolio)  
- [Projects](#projects)  
- [Installation & Usage](#installation--usage)  
- [Skills & Technologies Used](#skills--technologies-used)  
- [Future Enhancements](#future-enhancements)  

---

## Portfolio Structure
```
cybersecurity-portfolio/
├── _config.yml           # Site settings
├── index.md              # Homepage
├── _pages/               # Custom pages
│   ├── projects.md       # Projects page
│   ├── blog.md           # Blog page
│   ├── contact.md        # Contact page
│   ├── writeups.md       # Cybersecurity write-ups
├── _posts/               # Blog posts (if needed)
│   ├── 2025-03-12-example.md
│   ├── 2025-03-10-pcap-analysis.md
├── writeups/             # Cybersecurity technical write-ups
│   ├── example.md
│   ├── pcap-analysis.md
├── projects/             # Project details
│   ├── network-analysis/  
│   │   ├── README.md     # Project write-up
│   │   ├── analyzer.py   # Code file
│   │   ├── detector.py   # Detection script
├── LICENSE                  # Project license
└── README.md                # Project overview
```
---

## About This Portfolio  
This portfolio contains my cybersecurity-related projects, including:  
- **Network Traffic Analysis Toolkit** – A Python & Bash toolset for capturing, analyzing, detecting, and visualizing network traffic anomalies.  
- **Security Research & Learning Notes** – Research articles and documentation on cybersecurity techniques, threat intelligence, and system vulnerabilities.  

These projects demonstrate my ability to work with **packet analysis (PCAPs), network monitoring, security scripting, and automated threat detection.**  

---

## Projects  

### **Network Traffic Analysis Toolkit**  
📌 **Description:**  
A set of Python and Bash scripts for **capturing, analyzing, detecting, and visualizing** network traffic patterns and security threats from PCAP files.  

📂 **Key Features:**  
- Capture real-time network traffic using `tcpdump`.  
- Analyze `.pcap` files to extract insights.  
- Detect suspicious patterns using Python-based anomaly detection.  
- Visualize results using Matplotlib and Pandas.  

📜 **Files & Scripts:**  
- [`capture_traffic.sh`](scripts/capture_traffic.sh) - Captures network traffic using `tcpdump`.  
- [`run_pcap_analysis.sh`](scripts/run_pcap_analysis.sh) - Automates packet analysis from captured files.  
- [`analyzer.py`](scripts/analyzer.py) - Extracts network insights from PCAP files.  
- [`detector.py`](scripts/detector.py) - Identifies anomalies in traffic.  
- [`visualizer.py`](scripts/visualizer.py) - Generates visual reports of network traffic.  

---

## **Installation & Usage:**  
```bash
git clone https://github.com/yourusername/cybersecurity-portfolio.git
cd cybersecurity-portfolio
bash capture_traffic.sh  # Start capturing network traffic
bash run_pcap_analysis.sh   # Automated analysis of pcap file (analyse-detect-visualise)
```
---

## Skills & Technologies Used  
- **Programming & Scripting:** Python, Bash, PowerShell  
- **Networking & Security:** Wireshark, Tcpdump, Scapy, pyshark
- **Data Analysis & Visualization:** Pandas, Matplotlib  
  

## Future Enhancements  
Planned improvements for my Network Traffic Analysis Toolkit:  
- [ ] Implement a machine learning model for traffic anomaly detection.  
- [ ] Expand visualization to include real-time monitoring dashboards.  
