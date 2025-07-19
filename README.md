# 🛡️ RedFogE Cybersecurity Lab Installer

**Non-Kali Cybersecurity Lab Setup for AlmaLinux 9.6 (Headless/VM-Optimized)**

Welcome to the **RedFogE Cybersecurity Lab Installer** — a fully interactive, modular, and open-source Bash script designed to set up a powerful cybersecurity toolkit on top of a clean **AlmaLinux 9.6** installation. Whether you're a penetration tester, blue team analyst, or cybersecurity student, this tool lets you build a professional-grade lab environment **without Kali Linux**.

## 🚀 Features

- ✅ **Interactive Menu** – Select only the categories you need (e.g., Recon, Exploitation, Blue Team).
- ✅ **Offline-Ready Packaging** – Includes `.tar.gz` bundle with install script, logs, and instructions.
- ✅ **No GUI Required** – Perfect for VMs, remote servers, or headless environments.
- ✅ **Detailed Logging** – Separate log files per tool category in `~/lab-install-logs`.
- ✅ **Installed Binaries Tracker** – Lists exact binary paths in `installed-binaries.txt`.
- ✅ **RVM-based Ruby Setup** – Handles Ruby setup for Metasploit automatically.
- ✅ **Modular & Re-runnable** – Safe to run multiple times. Skips what's already installed.

## 📦 Tools Installed by Category

### 🧱 Base System
- Development Tools, Vim, Git, Cockpit, Bash-completion, etc.

### 🔍 Recon & Enumeration
- **Amass**

### 🎯 Scanning & Web Testing
- **Nmap**, **Dirsearch**

### 🛠️ Exploitation Framework
- **Metasploit Framework** (via RVM & Ruby)

### 🔐 Password Cracking
- **John the Ripper** (Jumbo), **Hashcat**

### 🛡️ Blue Team Tools
- **Auditd**, **AIDE**, **Suricata**, **Wireshark**, **TCPDump**

### 🐍 Python Libraries
- **pwntools**, **requests**, **flask**, **scapy**

### 🧰 Virtualization Helpers
- **Virt-Manager**, **libvirt**

## 📁 Usage

1. Clone this repo:
   ```bash
   git clone https://github.com/RedFogE/RedFogE.git
   cd RedFogE
   ```

2. Make script executable:
   ```bash
   chmod +x install-RedFogE.sh
   ```

3. Run the script (interactive mode:
   ```bash
   ./install-RedFogE.sh
   ```

## 📝 Logs and Reports

- All actions are logged to `~/lab-install-logs/`
- Installed tools and paths saved to: `~/lab-install-logs/installed-binaries.txt`

## 🧾 License

This project is licensed under the **GNU GPLv3**. Feel free to use, modify, and share with the community.
