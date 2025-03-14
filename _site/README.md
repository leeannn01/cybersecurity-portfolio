# Cybersecurity Portfolio
Portfolio showcasing cybersecurity projects, insights, and learnings

## Table of Contents  
- [About This Portfolio](#about-this-portfolio)  
- [Portfolio Structure](#portfolio-structure)
- [Projects](#projects)  
- [Installation & Setup](#installation--setup)  
- [Skills & Technologies Used](#skills--technologies-used)  

## About This Portfolio  
This portfolio contains my cybersecurity-related projects, including:  
- **Network Traffic Analysis Toolkit** – A Python & Bash toolset for capturing, analyzing, detecting, and visualizing network traffic anomalies.  
- **Security Research & Learning Notes** – Research articles and documentation on cybersecurity techniques, threat intelligence, and system vulnerabilities.  

These projects demonstrate my ability to work with **packet analysis (PCAPs), network monitoring, security scripting, and automated threat detection.**  

## Portfolio Structure
```
cybersecurity-portfolio/
├── _config.yml                             # Site settings
├── index.md                                # Homepage
├── pages/                                  # Custom pages
│   ├── projects.md                         # Projects page
│   ├── blog.md                             # Blog page
│   ├── contact.md                          # Contact page
│   └── writeup.md                          # Cybersecurity write-ups
|   
├── posts/                                  # Blog posts (if needed)
│   ├── 2025-03-12-example.md
│   └── 2025-03-10-pcap-analysis.md
|   
├── writeups/                               # Cybersecurity technical write-ups
│   ├── example.md
│   └── pcap-analysis.md
|
├── projects/                               # Project details
│   └── network-traffic-analysis-tool/  
│       ├── README.md                       # Project write-up
│       ├── src/                            # Python scripts for processing
|       ├── scripts/                        # Bash scripts 
|       ├── docs/                           # Documentation and reports
|       ├── data/                           # Folder (PCAP files - from both web scrapping/downloaded)
|       └── results/                        # All analysed results saved within 
|           └── pcap1
|               ├── downloads_pcap1/        # Downlable content within payload saved within 
|               ├── payload_pcap1.txt       # Payload extracted
|               ├── pcap1.csv               # Packet Data extracted
|               ├── Malicious Traffic/      # Results from Detector saved within (a csv and text summary)
|               └── Visuals/                # Results from Visualiser
├── LICENSE                                 # Project license
└── README.md                               # Portfolio overview
```

## Projects  
### **Network Traffic Analysis Toolkit**  
**Description:**  
A set of Python and Bash scripts for **capturing, analyzing, detecting, and visualizing** network traffic patterns and security threats from PCAP files.  

**Key Features:**  
- Capture real-time network traffic using `tcpdump`.  
- Analyze `.pcap` files to extract insights.  
- Detect suspicious patterns using Python-based anomaly detection.  
- Visualize results using Matplotlib and Pandas.  

**Quick Links:**  
1. **[View My Projects](./pages/projects.md)**  
2. **[Read My Blog](./pages/blog.md)**  
3. **[Contact Me](./pages/contact.md)**  


## **Installation & Setup:** 
This portfolio is built using Markdown and GitHub Pages

### To view the portfolio locally:
```bash
git clone https://github.com/yourusername/cybersecurity-portfolio.git
cd cybersecurity-portfolio
```

## Skills & Technologies Used  
- **Programming & Scripting:** Python, Bash, PowerShell  
- **Networking & Security:** Wireshark, Tcpdump, Scapy, pyshark
- **Data Analysis & Visualization:** Pandas, Matplotlib  
  
