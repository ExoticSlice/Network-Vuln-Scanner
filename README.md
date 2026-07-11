[![Run Tests](https://github.com/ExoticSlice/Network-Vuln-Scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/ExoticSlice/Network-Vuln-Scanner/actions/workflows/tests.yml)

# Network Vulnerability Scanner

A Python-based network vulnerability scanner that discovers live hosts, enumerates services, queries the NVD API for real CVEs, scores risk using CVSS, generates professional PDF pentest reports, and displays findings on a live web dashboard.

Built as a portfolio project to demonstrate practical cybersecurity and software engineering skills.

---

## Features

- Host discovery using Nmap ping sweep
- Port and service enumeration with version detection
- CVE lookup via the NVD API (nvd.nist.gov)
- CVSS-based risk scoring (Critical / High / Medium / Low)
- PDF pentest-style report generation
- Flask web dashboard with Chart.js severity breakdown chart
- GitHub Actions CI pipeline with pytest

---

## Technologies Used

- Python 3
- Nmap / python-nmap
- NVD REST API
- ReportLab (PDF generation)
- Flask (web dashboard)
- Chart.js (data visualisation)
- pytest (unit testing)
- GitHub Actions (CI/CD)

---

## Lab Environment

- Kali Linux (attacker VM)
- Metasploitable 2 (vulnerable target VM)
- VirtualBox with host-only network (192.168.56.0/24)
- GVM/OpenVAS for reference scanning

---

## Installation

```bash
git clone https://github.com/ExoticSlice/Network-Vuln-Scanner.git
cd Network-Vuln-Scanner
python3 -m venv scanner-env
source scanner-env/bin/activate
pip install python-nmap requests jinja2 reportlab flask pytest
```

---

## Usage

**Run the scanner:**

```bash
sudo python3 scanner.py
```

**Generate a PDF report:**

```bash
sudo python3 report.py
```

**Launch the web dashboard:**

```bash
sudo python3 app.py
```

Then open `http://127.0.0.1:5000` in your browser.

**Run tests:**

```bash
pytest test_scanner.py -v
```

---

## Project Structure

Network-Vuln-Scanner/
├── scanner.py # Host discovery and service enumeration
├── cve_lookup.py # NVD API CVE lookup
├── risk_engine.py # CVSS risk scoring
├── report.py # PDF report generator
├── app.py # Flask web dashboard
├── templates/
│ └── dashboard.html # Dashboard HTML template
├── test_scanner.py # Pytest unit tests
└── .github/
└── workflows/
└── tests.yml # GitHub Actions CI pipeline

---

## Screenshots

_Dashboard and PDF report screenshots coming soon._

---

## Author

Alan Saji — Cybersecurity Student at Manchester Metropolitan University  
GitHub: [ExoticSlice](https://github.com/ExoticSlice)
