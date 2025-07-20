#!/bin/bash

# 🔥 RedFogE Cybersecurity Lab Installer for AlmaLinux 9.6 🔥
# ------------------------------------------------------------
# Build a full-featured, Kali-free cybersecurity lab with ease.
# Includes: Recon, Exploitation, Blue Team, and more.
# Logs: ~/lab-install-logs | License: GPL-3.0-or-later
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of the RedFogE Cybersecurity Toolkit.
#
# Copyright (C) 2025 RedFogE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

### Interactive Cybersecurity Lab Installer for AlmaLinux 9.6 ###
# Description: Menu-based installer to selectively install cybersecurity tools on a headless AlmaLinux 9.6 VM

set -euo pipefail

### CONFIGURATION ###
LOG_DIR="$HOME/lab-install-logs"
BINARIES_EXPORT_FILE="$LOG_DIR/installed-binaries.txt"
INSTALLED_SOFTWARE=()

mkdir -p "$LOG_DIR"
> "$BINARIES_EXPORT_FILE"

### UTILITY FUNCTIONS ###
log_and_retry() {
  local log_file="$1"
  shift # Remove the log file from arguments

  local command=("$@") # Store all remaining args as a single array
  local max_retries=3
  local retry_delay=5 # seconds

  for ((i = 1; i <= max_retries; i++)); do
    echo "Attempting: ${command[@]}" | tee -a "$log_file"
    "${command[@]}" 2>&1 | tee -a "$log_file"
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
      echo "Success!" | tee -a "$log_file"
      return 0
    else
      echo "Failed (attempt $i/$max_retries).  Retrying in $retry_delay seconds..." | tee -a "$log_file"
      sleep $retry_delay
    fi
  done

  echo "ERROR: Failed after multiple retries. Check the log file." | tee -a "$log_file"
  return 1
}

record_binary() {
  local binary_name="$1"
  local binary_path
  binary_path=$(command -v "$binary_name" 2>/dev/null || echo "/opt/$binary_name")
  echo "$binary_name: $binary_path" >> "$BINARIES_EXPORT_FILE"
}

enable_crb() {
  local log="$LOG_DIR/00-crb.log"
  echo "Enabling CRB repository..."
  log_and_retry "$log" sudo dnf config-manager --set-enabled crb
  log_and_retry "$log" sudo dnf makecache
}

validate_7z() {
  if ! command -v 7z >/dev/null 2>&1; then
    echo "[!] 7z not found. Installing p7zip..."
    sudo dnf install -y p7zip p7zip-plugins
  fi
}

install_john_optional_libs() {
  local log="$LOG_DIR/optional-libs.log"
  echo "Installing optional libraries for John the Ripper..."
  log_and_retry "$log" sudo dnf install -y openssl-devel gmp-devel zlib-devel bzip2-devel libpcap-devel \
    unrar openmpi-devel libtool automake autoconf yasm pkgconfig gcc-c++ git cmake make
}

### INSTALL FUNCTIONS ###
install_base() {
  local log="$LOG_DIR/01-base.log"
  echo "Installing base packages..."

  log_and_retry "$log" sudo dnf install -y epel-release dnf-plugins-core
  log_and_retry "$log" sudo dnf groupinstall -y "Development Tools"

  log_and_retry "$log" sudo dnf install -y \
    vim screen unzip zip p7zip p7zip-plugins the_silver_searcher \
    net-tools whois traceroute curl wget bind-utils bash-completion cockpit \
    git gcc make zlib-devel openssl-devel libffi-devel readline-devel sqlite-devel \
    bzip2 autoconf automake libtool patch java-11-openjdk-devel ncurses-devel \
    gnupg2 python3 python3-pip

  INSTALLED_SOFTWARE+=("Base Packages")
}

install_recon() {
  local log="$LOG_DIR/02-recon.log"
  echo "Installing recon tools..."

  log_and_retry "$log" curl -LO https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip
  log_and_retry "$log" unzip amass_linux_amd64.zip
  log_and_retry "$log" sudo mv amass_Linux_amd64/amass /usr/local/bin
  rm -rf amass_Linux_amd64 amass_linux_amd64.zip

  INSTALLED_SOFTWARE+=("Amass")
  record_binary "amass"
}

install_scanning() {
  local log="$LOG_DIR/03-scanning.log"
  echo "Installing scanning tools..."

  log_and_retry "$log" sudo dnf install -y nmap
  log_and_retry "$log" git clone https://github.com/maurosoria/dirsearch.git ~/tools/dirsearch
  log_and_retry "$log" sudo ln -sf ~/tools/dirsearch/dirsearch.py /usr/local/bin/dirsearch
  log_and_retry "$log" chmod +x /usr/local/bin/dirsearch
  log_and_retry "$log" pip3 install -r ~/tools/dirsearch/requirements.txt

  INSTALLED_SOFTWARE+=("Nmap" "Dirsearch")
  record_binary "nmap"
  record_binary "dirsearch"
}

install_exploitation() {
  local log="$LOG_DIR/04-exploitation.log"
  echo "Installing Metasploit Framework..."

  enable_crb
  log_and_retry "$log" sudo dnf install -y postgresql postgresql-devel libyaml-devel libpcap-devel libxml2-devel libxslt-devel gnupg2 curl

  # NOTE: Do not wrap the following RVM installation commands in log_and_retry
  # They require direct execution due to piped input and sourcing behavior.  
  echo "Installing RVM and Ruby..."
  curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -
  curl -sSL https://rvm.io/pkuczynski.asc | gpg2 --import -
  curl -sSL https://get.rvm.io | bash -s stable

  if [ -s "$HOME/.rvm/scripts/rvm" ]; then
    source "$HOME/.rvm/scripts/rvm"
  else
    echo "[!] RVM not found. Exiting."
    exit 1
  fi

  log_and_retry "$log" rvm install 3.3.8
  log_and_retry "$log" rvm use 3.3.8 --default

  log_and_retry "$log" git clone https://github.com/rapid7/metasploit-framework.git ~/metasploit-framework
  log_and_retry "$log" gem install bundler
  log_and_retry "$log" bundle install --gemfile ~/metasploit-framework/Gemfile

  echo 'export PATH="$PATH:$HOME/metasploit-framework"' >> ~/.bashrc
  log_and_retry "$log" sudo ln -sf ~/metasploit-framework/msfconsole /usr/local/bin/msfconsole
  source ~/.bashrc

  INSTALLED_SOFTWARE+=("Metasploit Framework")
  record_binary "msfconsole"
}

install_password_crackers() {
  local log="$LOG_DIR/05-passwords.log"
  echo "Installing password cracking tools..."

  validate_7z
  install_john_optional_libs

  log_and_retry "$log" cd /opt
  log_and_retry "$log" sudo git clone https://github.com/openwall/john -b bleeding-jumbo john
  log_and_retry "$log" cd /opt/john/src
  log_and_retry "$log" sudo ./configure
  log_and_retry "$log" sudo make -sj"$(nproc)"

  echo "alias john='/opt/john/run/john'" >> ~/.bashrc
  source ~/.bashrc

  INSTALLED_SOFTWARE+=("John the Ripper")
  record_binary "john"

  log_and_retry "$log" cd /opt
  log_and_retry "$log" sudo curl -LO https://hashcat.net/files/hashcat-6.2.6.7z
  log_and_retry "$log" sudo 7z x hashcat-6.2.6.7z
  log_and_retry "$log" sudo mv hashcat-6.2.6 hashcat
  log_and_retry "$log" sudo rm -f hashcat-6.2.6.7z
  log_and_retry "$log" sudo chown -R "$USER":"$USER" /opt/hashcat

  echo 'alias hashcat="/opt/hashcat/hashcat.bin"' >> ~/.bashrc
  source ~/.bashrc

  INSTALLED_SOFTWARE+=("Hashcat")
  record_binary "hashcat"
}

install_blue_team() {
  local log="$LOG_DIR/06-blueteam.log"
  echo "Installing Blue Team tools..."

  log_and_retry "$log" sudo dnf install -y audit aide suricata tcpdump wireshark wireshark-cli
  log_and_retry "$log" sudo systemctl enable --now auditd
  log_and_retry "$log" sudo systemctl enable --now suricata

  INSTALLED_SOFTWARE+=("Auditd" "AIDE" "Suricata" "TCPDump" "Wireshark")
  for tool in auditd aide suricata tcpdump wireshark; do
    record_binary "$tool"
  done
}

install_python_libs() {
  local log="$LOG_DIR/07-python.log"
  echo "Installing Python hacking libraries..."

  log_and_retry "$log" pip3 install pwntools requests flask scapy
  INSTALLED_SOFTWARE+=("Pwntools" "Requests" "Flask" "Scapy")
}

install_virtualization_helpers() {
  local log="$LOG_DIR/08-virt.log"
  echo "Installing Virtualization helpers..."

  log_and_retry "$log" sudo dnf install -y virt-manager libvirt libvirt-client virt-install
  log_and_retry "$log" sudo systemctl enable --now libvirtd

  INSTALLED_SOFTWARE+=("Virt-Manager" "Libvirt")
  record_binary "virt-manager"
  record_binary "virsh"
}

show_menu() {
  echo "\n===== Non-Kali Cybersecurity Lab Installer ====="
  echo "1) 🧱 Base Setup"
  echo "2) 🔍 Recon & Enumeration"
  echo "3) 🎯 Scanning & Web Testing"
  echo "4) 🛠️ Exploitation Frameworks"
  echo "5) 🔐 Password Cracking"
  echo "6) 🛡️ Blue Team Tools"
  echo "7) 🐍 Python Hacking Libraries"
  echo "8) 🧰 Virtualization Helpers"
  echo "9) 🦾 Finish & Exit"
  echo "10) 🔁 Reboot System Now"
  echo "==============================================="
}

print_summary() {
  echo -e "\n📦 INSTALLATION SUMMARY"
  echo "-----------------------------"
  for tool in "${INSTALLED_SOFTWARE[@]}"; do
    echo "✅ $tool"
  done
  echo "-----------------------------"
  echo "🗂️  Logs saved to: $LOG_DIR"
  echo "📁 Installed binaries listed in: $BINARIES_EXPORT_FILE"
  echo "🟢 Done. You can now use the tools installed."
}

while true; do
  show_menu
  read -rp "Select an option [1-10]: " choice
  case $choice in
    1) install_base;;
    2) install_recon;;
    3) install_scanning;;
    4) install_exploitation;;
    5) install_password_crackers;;
    6) install_blue_team;;
    7) install_python_libs;;
    8) install_virtualization_helpers;;
    9) print_summary; echo "✅ Installation complete. Reloading shell..."; exec bash;;
    10)
      print_summary
      echo
      read -rp "Are you sure you want to reboot the system now? [y/N]: " confirm
      if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo "🔁 Rebooting now..."
        sudo reboot
      else
        echo "❌ Reboot cancelled. Returning to menu."
      fi
      ;;
    *) echo "❌ Invalid choice. Try again.";;
  esac
  echo "\n✅ Done. Press Enter to continue..."
  read
  clear
  echo "Resuming menu..."
  sleep 1
  clear
done
