#!/bin/bash
# cleanup_lab.sh — tear down Vagrant lab and remove temporary files
set -e
echo "[*] Destroying Vagrant VMs..."
vagrant destroy -f kali ubuntu-dc ubuntu-victim || true
echo "[*] Removing generated reports and captures..."
rm -rf reports/*.md capture-*.pcap scans/ out/ || true
echo "[*] Done. Please check VirtualBox / VMware to ensure VMs are removed."
