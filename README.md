## 🚀 Project Roadmap

### 🧱 Phase 1 – Basics
- [x] CLI setup with argparse
- [x] TCP port scanning
- [x] Output open ports to console

### ⚙️ Phase 2 – Features
- [x] UDP port scanning
- [x] Banner grabbing
- [x] Save output to file

### ⚡ Phase 3 – Speed & Usability
- [x] Add multithreading
- [x] Colorful output (with `colorama`)
- [x] Use top common ports

### 🔬 Phase 4 – Advanced
- [x] Subnet scanning (CIDR support)
- [x] Basic OS fingerprinting
- [x] Web GUI (Flask)

### 🛡️ Phase 5 – Security Exploration
- [x] Add stealth scan mode (SYN scan)
- [x] Detect firewall or filtered ports

---

# 🛡️ Python Port Scanner – CLI + Web GUI

A modular, multi-threaded port scanner built in Python, featuring both a command-line interface and a Flask-based web GUI.

This tool was created to help me deeply understand TCP/UDP scanning, service enumeration, and how tools like `nmap` work under the hood. The **web GUI was built with AI assistance**, as I'm still new to front-end development.

## 🔧 Features

- ✅ TCP & UDP port scanning  
- ✅ Banner grabbing (detects open service info)  
- ✅ Stealth scanning using SYN packets (requires root)  
- ✅ OS fingerprinting (based on TTL values)  
- ✅ Save/download scan results  
- ✅ Scan top common ports (via wordlist)  
- ✅ Multi-threading for fast performance  
- ✅ Simple Flask GUI to run scans from browser  
- ✅ Firewall detection logic (especially for UDP)

## 💻 Requirements Before Running Locally

Make sure you have the following installed:

- Python 3.7 or later
- Npcap

Install required Python libraries:
```bash
pip install colorama flask scapy
```

## 📦 Project Structure

```
port_scanner/
├── scanner.py             ← CLI scanner
├── app.py                 ← Flask GUI
├── utils.py               ← Shared scanner logic
├── wordlists/
│   └── common_ports.txt   ← Top common ports (like Nmap)
├── output/                ← Scan result logs. Not in github, it will be created when you run
│   └── *.txt
└── README.md
```

## 🚀 Getting Started

### ▶️ CLI Mode
```bash
python scanner.py -t scanme.nmap.org -p 1-1024 -s both -o output/report.txt
```

### 🌐 Web GUI Mode
```bash
python app.py
# Then open http://127.0.0.1:5000 in your browser
```

This tool is for **educational and ethical use only**. Scanning systems without permission is illegal and unethical.

## 📬 Contact

Made by **Borhan Javadian**  
Open to feedback, ideas, and improvements!
