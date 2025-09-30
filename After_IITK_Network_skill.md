# 12-Week Intensive Network & Cybersecurity Schedule

**Goal:** Become proficient in networking fundamentals and network security (blue-team & red-team skills). Includes OSI, VPNs, tunneling, packet analysis, IDS/IPS, routing/switching, cloud networking, and hands-on labs.

**Study cadence:** 8–12 hours/week (recommended). Each week includes: Topics, Objectives, Hands-on Lab, Commands / Exercises, Deliverable.

---
```
Blue-team / Network analyst → IDS/IPS, Zeek/Suricata, SIEM, network forensics, threat hunting, cloud networking monitoring.

Red-team / Pentest → advanced scanning, exploit delivery over network, pivoting, ARP/DNS spoofing, tunneling, wireless attacks.
Learn routers, switches, firewalls, gateways, NAT, VLANs, ACLs, routing protocols — yes, you need them. Start with fundamentals (Cisco-style concepts) first, then add cloud networking (AWS/Azure/GCP) after you can comfortably subnet, route, and capture packets.
```

## Week 1 — Foundations: OSI / TCP-IP & Basic Tools
**Topics**
- OSI vs TCP/IP models: layers, responsibilities.
- Ethernet, MAC addresses, ARP.
- IP addressing, subnetting, CIDR.
- Tools: `ip`, `ss`, `ifconfig`/`ip addr`, `ping`, `traceroute`.

**Objectives**
- Know each OSI layer and examples of protocols at each layer.
- Do subnetting by hand; calculate network/broadcast/host ranges.

**Lab**
- Install Linux VM (Ubuntu). Run:
  - `ip a`, `ip route`, `ss -tunlp`
  - `ping 8.8.8.8`, `traceroute 8.8.8.8`
- Practice subnetting: determine subnets for `192.168.1.0/24` into `/26`.

**Commands / Exercises**
```bash
ip a
ip route
ss -tunlp
ping -c 4 8.8.8.8
traceroute -n 8.8.8.8
```

**Deliverable**
- One-page cheat sheet: OSI vs TCP-IP mapping + 10 subnetting Q&A.

---

## Week 2 — Packet Capture & Analysis (Wireshark / tcpdump)
**Topics**
- Packet capture basics, capture filters vs display filters.
- TCP handshake, flags, sequence/ack numbers.
- Using Wireshark GUI and `tcpdump` / `tshark`.

**Objectives**
- Capture traffic, filter by protocol/port, follow TCP streams, extract files.

**Lab**
- Capture web traffic: `sudo tcpdump -i any -w web.pcap port 80 or port 443`
- Open in Wireshark; follow TCP stream; filter `http` and `tls`.

**Commands**
```bash
sudo tcpdump -i any -c 1000 -w capture.pcap
tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri
```

**Deliverable**
- 1 captured PCAP and a short analysis: show a TCP handshake and a retried packet.

---

## Week 3 — TCP/IP Deep Dive & Common Services
**Topics**
- TCP internals (windowing, retransmit, RST), UDP semantics.
- Common services: DNS, DHCP, HTTP(S), SMB, SSH.
- Port scanning basics with `nmap`.

**Objectives**
- Interpret TCP retransmissions, resets; identify common service fingerprints.

**Lab**
- Use `nmap` to scan a lab network:
```bash
nmap -sS -sV -O 10.0.2.0/24
```
- Capture probes and analyze responses.

**Deliverable**
- `nmap` scan report (top 20 hosts/services) and a short writeup on one interesting service.

---

## Week 4 — Switching, VLANs & L2 Concepts
**Topics**
- Switch operation, MAC address tables, broadcast domains.
- VLANs and trunking (802.1Q), STP basics.

**Objectives**
- Create VLANs in a virtualized lab (GNS3 / EVE-NG / Packet Tracer) and test isolation.

**Lab**
- Build two VLANs (10 & 20), place VMs in each VLAN, confirm isolation.
- Use `arp -a`, `bridge` commands to inspect.

**Deliverable**
- Topology diagram (PNG) and commands used to create VLANs.

---

## Week 5 — Routing, NAT & ACLs
**Topics**
- Routing basics, static vs dynamic, default gateway.
- NAT types (SNAT, DNAT, PAT) and port forwarding.
- ACLs on routers and basic firewall rules.

**Objectives**
- Configure basic routing and NAT in pfSense or GNS3.

**Lab**
- Deploy pfSense VM:
  - Create NAT rule exposing a web server.
  - Add firewall rule to allow only TCP/80 from WAN.

**Commands / Tips**
- pfSense GUI steps (documented in lab file).
- `iptables -t nat -L -n -v` for Linux NAT inspection.

**Deliverable**
- pfSense config snapshot + explanation of NAT flow.

---

## Week 6 — VPN & Tunneling (Architecture & Hands-on)
**Topics**
- VPN types: IPsec, OpenVPN (SSL/TLS), WireGuard.
- Tunneling concepts: SSH tunnels, SOCKS, port forwarding, DNS tunneling basics.
- Use-cases: secure remote access, red-team pivoting, exfiltration.

**Objectives**
- Understand differences between site-to-site and remote-access VPNs.
- Create a working VPN (WireGuard or OpenVPN) and an SSH tunnel.

**Lab**
- WireGuard quick start on two VMs:
  - Install `wireguard`, generate keys, configure peers.
- SSH tunnel example:
```bash
# Local forward: forward local port 9000 to remote:80
ssh -L 9000:localhost:80 user@remote
# SOCKS proxy:
ssh -D 1080 user@remote
```
- DNS tunneling awareness (simulate with `iodine` in lab, but **do not use on production**).

**Deliverable**
- VPN connection logs + steps + demonstration of tunneled HTTP over SSH.

---

## Week 7 — Firewalls, Gateways & WAFs
**Topics**
- Stateful vs stateless firewalls, connection tracking.
- Next-gen firewalls (Palo Alto, Fortinet concepts) and WAF basics.
- Proxy vs gateway behaviors.

**Objectives**
- Create firewall rules and test how stateful inspection affects flows.

**Lab**
- pfSense: implement stateful blocking, test with `hping3`:
```bash
# send TCP SYN to test firewall handling
hping3 -S -p 80 target
```
- Configure a simple ModSecurity-based WAF (Docker image) in front of a web app.

**Deliverable**
- Report on firewall behavior for stateful vs stateless rules.

---

## Week 8 — IDS / IPS & Network Monitoring (Zeek / Suricata)
**Topics**
- Signature-based vs anomaly-based detection.
- Zeek (Bro) logs & scripting basics.
- Suricata rule writing and EVE JSON output.

**Objectives**
- Run Zeek and Suricata in lab, generate alerts, and parse logs.

**Lab**
- Install Security Onion or standalone Zeek+Suricata:
  - Run a simple Suricata rule:
```yaml
alert http any any -> any any (msg:"Test HTTP POST"; content:"/test"; sid:1000001; rev:1;)
```
- Use Zeek to extract HTTP logs:
```bash
zeek -r capture.pcap local
cat http.log
```

**Deliverable**
- Two detection rules (Suricata + Zeek script) and sample alert JSON.

---

## Week 9 — Network Forensics & PCAP Triage
**Topics**
- PCAP triage methodology, session reconstruction.
- File extraction, IOC hunting, timeline building.

**Objectives**
- Given a PCAP, extract files and identify suspicious traffic (C2 beacons, exfil).

**Lab**
- Use `tshark` / `Bro` / `NetworkMiner` to extract artifacts:
```bash
tshark -r sample.pcap -Y "http" -T fields -e http.file_data
```
- Use `foremost` / `binwalk` for carved files.

**Deliverable**
- Full PCAP triage report with extracted files & IOC list.

---

## Week 10 — Encrypted Traffic & TLS Fingerprinting
**Topics**
- TLS handshake, certificates, SNI.
- JA3 / JA3S TLS fingerprints, JARM.
- TLS inspection concepts and limitations.

**Objectives**
- Compute JA3 fingerprints and identify differences between clients.

**Lab**
- Capture TLS traffic and run JA3:
```bash
# Using a tool like ja3 or tlsgrab
ja3er capture.pcap
```
- Inspect cert chain with `openssl s_client -connect host:443 -servername host`.

**Deliverable**
- JA3 list and short note on how to use JA3 in detections.

---

## Week 11 — Cloud Networking & VPC Security
**Topics**
- VPC basics: Subnets, route tables, security groups, NACLs.
- VPC flow logs, cloud NAT, peering, transit gateway basics.
- Cloud provider differences (AWS/Azure/GCP).

**Objectives**
- Create a small VPC (AWS free tier) and enable VPC Flow Logs.

**Lab**
- AWS: create VPC, public/private subnets, an EC2 instance in private subnet, NAT gateway for egress.
- Enable flow logs and analyze logs in CloudWatch or S3.

**Deliverable**
- Flow logs sample + short hunt rule for unusual outbound connections.

---

## Week 12 — Red/Blue Capstone & Review
**Topics**
- Offensive techniques: pivoting (SSH tunnels, SOCKS, proxychains), Responder/SMB relay basics (lab only).
- Blue techniques: detection, containment, incident report writing, IOC export.

**Objectives**
- Run a simulated assessment: attacker performs a scan and pivot; defender detects via Suricata/Zeek and produces an incident report.

**Lab**
- Capstone scenario (lab):
  1. Attacker (Kali VM) runs `nmap` and uses `ssh -D` to pivot.
  2. Attacker hosts a simple reverse shell; defender captures PCAP and generates alerts.
  3. Produce incident report with timeline, IOCs, and remediation steps.

**Deliverable**
- Full incident response report + repository with lab configs and PCAP.

---

# Ongoing practice & assessment
- Weekly: 1 writeup (lab summary) uploaded to GitHub.
- Monthly: public blog post or Medium writeup (optional).
- Keep a portfolio: PCAPs (sanitized), Zeek/Suricata rules, firewall configs.

============================================

# Lab Instructions & Commands (supplementary)

This file provides step-by-step instructions and copy-paste commands for the labs referenced in the 12-week schedule.

## Prerequisites
- Host OS: Windows / macOS / Linux with virtualization (VirtualBox / VMware).  
- VMs: Ubuntu Server (for services), Kali Linux (attacker), pfSense (firewall), Security Onion (monitoring) optional.  
- Tools to install on Ubuntu/Kali:
  - tcpdump, tshark, wireshark, nmap, netcat, hping3, scapy, traceroute, curl
  - zeek (bro), suricata, jq, tshark
  - wireguard or openvpn
  - docker / docker-compose (for running test web apps and ModSecurity WAF)

## Quick install snippets (Ubuntu)
```bash
sudo apt update && sudo apt install -y build-essential git curl wget apt-transport-https   tcpdump tshark wireshark nmap netcat-openbsd hping3 python3-pip docker.io docker-compose
# scapy
pip3 install scapy
# suricata (Ubuntu apt repo)
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update && sudo apt install -y suricata
# zeek (download and build or use packages)
# wireguard
sudo apt install -y wireguard
```

## WireGuard example (peer-to-peer simple)
On Host A:
```bash
wg genkey | tee privateA.key | wg pubkey > publicA.key
# create /etc/wireguard/wg0.conf with keys and peer info
sudo wg-quick up wg0
```
On Host B: similar steps, exchange public keys, configure allowed IPs.

## OpenSSH tunnel examples
- Local forward
```bash
ssh -L 9000:internal-host:80 user@bastion
# Now browse http://localhost:9000
```
- Dynamic SOCKS proxy
```bash
ssh -D 1080 user@bastion
# Configure browser to use SOCKS5 proxy 127.0.0.1:1080
```

## Suricata simple rule & run
Create `/etc/suricata/rules/local.rules` with:
```
alert http any any -> any any (msg:"Test HTTP POST"; content:"/test"; sid:1000001; rev:1;)
```
Run with:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
# Or run on a pcap:
suricata -r capture.pcap -c /etc/suricata/suricata.yaml -l out/
```

## Zeek basics
- Run on pcap:
```bash
zeek -r capture.pcap local
# outputs logs: conn.log, http.log, dns.log
```
- Simple Zeek script to log HTTP user-agent (example):
```bro
# http_user_agent.zeek
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string,
                   version: string)
{
    local ua = c$http$User-Agent;
    print fmt("%s %s %s", c$id$src_h, c$id$dest_h, ua);
}
```

## PCAP triage commands
```bash
# list unique hosts from pcap
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -nr | head

# extract files from HTTP
strings capture.pcap | grep -E "HTTP/1.1|Content-Type:" -n
```

## Useful utilities
- `stern` / `kubetail` for tailing logs in K8s labs.
- `mitmproxy` for intercepting HTTP(S) in some labs (with caution).
- `netcat` for simple listeners:
  - Listener: `nc -lvnp 4444`
  - Client: `nc target 4444 < file`


=========================================

# Resources, References & Checklists

## Books
- *Computer Networking: A Top-Down Approach* — Kurose & Ross
- *Practical Packet Analysis* — Chris Sanders
- *The Practice of Network Security Monitoring* — Richard Bejtlich
- *TCP/IP Illustrated, Volume 1* — W. Richard Stevens

## Courses & Platforms
- TryHackMe: Networking Path, Offensive & Defensive Paths
- Hack The Box: Academy + labs (red-team practice)
- GNS3 Academy / EVE-NG labs (network device emulation)
- Security Onion documentation & Deployment guides
- Pluralsight / CBT Nuggets CCNA courses
- SANS: FOR500 / GCIA / GCIH for advanced detection & IR (paid)

## Tools Quick-Reference
- Capture: Wireshark, tcpdump, tshark
- Scanning: nmap, masscan
- Packet crafting: scapy, hping3
- IDS/IPS: Zeek, Suricata, Snort
- Logging/Analysis: Security Onion, ELK (Elastic), Splunk
- VPN/Tunnel: wireguard, openvpn, ssh
- Firewalls: pfSense, iptables/nftables

## Checklists
- Subnetting cheat sheet (CIDR ranges)
- OSI layer mapping cheat sheet (common protocols per layer)
- Incident report template: Summary, Timeline, IOCs, Affected hosts, Remediation.

## Safety & Ethics
- Do all testing in your lab or authorized targets.
- Never perform active scans or attacks against systems you do not own or have explicit permission to test.

