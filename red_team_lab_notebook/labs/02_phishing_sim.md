# Lab 02 — Phishing Simulation (Gophish) — Safe, contained simulation

**Goal:** Simulate a phishing campaign in a lab to practice awareness and detection. Use a lab-only SMTP sink or local mail capture (MailHog) — do not send to real addresses.

## Setup (on Kali or a separate VM)
1. Install Gophish (open-source phishing framework):
```bash
# Download and run Gophish (example)
wget https://github.com/gophish/gophish/releases/download/v0.11.0/gophish-v0.11.0-linux-64bit.zip
unzip gophish-*.zip
cd gophish
./gophish
```
2. Configure Gophish to use MailHog or a local catch-all SMTP server so that emails stay within lab:
```bash
# Run MailHog (docker recommended)
docker run -d -p 8025:8025 -p 1025:1025 mailhog/mailhog
# In Gophish SMTP settings: host=127.0.0.1, port=1025
```
3. Create a single campaign with a landing page hosted in the lab (e.g., victim web host). Use fake test accounts you control **only**.

## Detection exercise
- Monitor the lab IDS/Zeek logs for outbound HTTP connections from the victim that correspond to the simulated phishing click.
- Correlate Gophish campaign events with logs from Security Onion (if deployed).

## Deliverable
- Campaign summary (no real emails), timeline of events, and the IDS logs that show the simulated activity.
