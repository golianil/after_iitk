# Lab 01 — Reconnaissance (Passive & Active) — Lab-only

**Goal:** Learn to discover hosts, services, and basic web content in an isolated lab.
**Ethics reminder:** Only run against lab hosts listed in your Vagrant inventory (192.168.56.0/24).

## Tools
- nmap, masscan, amass (optional for DNS), gobuster, curl, dnsutils

## Tasks
1. From `kali`, enumerate hosts on the lab network:
```bash
# Ping sweep (fast)
nmap -sn 192.168.56.0/24
# TCP SYN scan and version detection on the victim
nmap -sS -sV -Pn 192.168.56.12 -p- --min-rate 1000 -oN scans/victim_full_tcp.txt
```
2. Web discovery:
```bash
curl -I http://192.168.56.12/
# Directory brute force (wordlist required)
gobuster dir -u http://192.168.56.12/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40
```
3. DNS reconnaissance (if you configured internal DNS):
```bash
dig @192.168.56.11 victim.lab ANY +short
```
## Deliverable
- Short recon report (hosts discovered, open ports, services, HTTP interesting pages). Save to `reports/recon.md`.
