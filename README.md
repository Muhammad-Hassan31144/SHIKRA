# SHIKRA: Specialized in Hunting Intelligent, Known Ransomware for Analysis

## Overview
SHIKRA is a cutting-edge, automated ransomware forensic analysis platform engineered for enterprise-grade cybersecurity. Designed to offer rapid, in-depth forensic insights, SHIKRA leverages a QEMU-based Windows 10 victim VM—provisioned and controlled by an Ubuntu-based automation script—to execute ransomware in a realistic, user-simulated environment. It extracts detailed forensic logs using industry-standard tools and securely transfers them to a cloud database for centralized, real-time analysis through an interactive web dashboard.

## Key Features
- **Automated Victim VM Provisioning:**  
  Deploy a Windows 10 victim VM via QEMU on an Ubuntu host with randomized hardware identifiers and realistic resource allocation, ensuring ransomware cannot easily detect the virtual environment.

- **Forensic Tool Automation:**  
  Utilize Bash/PowerShell scripts to automatically install and configure essential forensic tools (ProcMon, RegShot, Wireshark, INetSim, Volatility) on the host, keeping analysis functions external to the victim VM.

- **User Simulation & Anti-Evasion:**  
  Mimic real user activity (mouse movements, keystrokes, application usage) and set realistic system uptime to bypass ransomware evasion tactics, ensuring the malware executes fully.

- **Secure Log Extraction & Cloud Integration:**  
  Extract logs via shared folders or serial port redirection and upload them to a centralized cloud database (Firebase/MongoDB) using a secure API, enabling comprehensive forensic analysis and historical trend tracking.

- **Interactive Web Dashboard:**  
  Access real-time visualization, filtering, and automated report generation through an intuitive web UI built with React and Flask, empowering cybersecurity professionals to quickly derive actionable insights.

## Why SHIKRA?
- **Ransomware is Evolving:** With attacks increasing by over 300% annually, traditional analysis tools are no longer sufficient.
- **Enterprise-Grade Automation:** SHIKRA minimizes manual intervention and delivers consistent, repeatable forensic results.
- **Actionable Intelligence:** By centralizing and visualizing forensic data, SHIKRA enables rapid, data-driven decision-making in incident response and threat mitigation.

## Creating Fake Wifi