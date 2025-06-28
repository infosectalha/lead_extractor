# Passive Automated Lead Profiler Tool

## 🛠️ Objective
A Python-based automation tool designed for cybersecurity analysts and outreach professionals to safely profile domains and assess their reputation, trustworthiness, and technical setup — using only legally safe and passive recon techniques.

## ✅ Current Features (Phase 1 Implementation)

This version of the tool supports profiling a single domain provided as a command-line argument. It gathers the following information:

1.  **🗂️ WHOIS Domain Intelligence**:
    *   Domain registrar info
    *   Creation date, expiration date
    *   Domain age (in years/months)
2.  **🔐 SSL Certificate Check**:
    *   SSL enabled and valid?
    *   Expiry date
    *   Issuer info
    *   Common Name (CN) and Subject Alternative Names (SAN)
3.  **🛡️ VirusTotal Integration (Placeholder)**:
    *   Currently a placeholder. Full integration requires a VirusTotal API key.
    *   Will eventually return detection ratio and malicious categories.
4.  **🧱 Tech Stack Detection (Basic)**:
    *   Detects server type from the `Server` HTTP header (e.g., Apache, Nginx).
    *   *Advanced tech stack detection (CMS, JS frameworks) is planned for future phases.*
5.  **🔍 SEO Index Visibility (Placeholder)**:
    *   Currently a placeholder advising manual checks.
    *   *Automated checks are complex and planned for future investigation.*
6.  **⚠️ Security Header Analysis**:
    *   Analyzes presence or absence of:
        *   Content-Security-Policy
        *   Strict-Transport-Security
        *   X-Frame-Options
        *   X-XSS-Protection
    *   Lists which of these specific headers are missing.
7.  **🤖 robots.txt Presence**:
    *   Checks if `robots.txt` exists.
    *   Lists Disallow rules, Sitemap directives, and other common directives.
    *   Provides a short preview of the content.
8.  **🌐 DNS Record Lookup**:
    *   Extracts:
        *   A (IPv4) records
        *   NS (Name Server) records
        *   MX (Mail Server) records

## 💻 Tech Stack
*   Language: Python 3.x
*   Libraries: See `requirements.txt` (includes `python-whois`, `requests`, `dnspython`)

## 🚀 Setup and Usage

1.  **Clone the Repository (or download the files)**:
    ```bash
    # git clone <repository_url>
    # cd lead_profiler
    ```
    (Assuming files are in a `lead_profiler` directory)

2.  **Install Dependencies**:
    It's recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  **Run the Profiler**:
    Provide a single domain or email address as a command-line argument.
    ```bash
    python profiler.py example.com
    ```
    Or with an email:
    ```bash
    python profiler.py admin@example.com
    ```
    The tool will output the collected information in a JSON format to the console.

## 📄 Output
Currently, the tool prints a JSON object containing the full analysis results to the standard output.
*CSV output and per-domain mini-reports are planned for future phases.*

## 🚫 Excluded (As per initial design)
*   No active scanning (Nmap, Nikto).
*   No WhatWeb CLI or port probing.
*   No banner grabbing beyond basic HTTP headers.

## 🧑‍💼 Target Use Case
Built for cybersecurity outreach analysts to automate passive domain analysis. The tool aims to handle multiple domains efficiently in later phases and generate reports useful for client outreach and credibility assessment.
