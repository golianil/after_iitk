# Red-Team Lab Notebook (Ethical, Lab-Only)

**Status:** For authorized learning, red-team practice, and purple-team detection testing **only**.
**Important legal & ethical notice:** Do **not** run any offensive techniques against systems you do not own or have explicit written permission to test. This lab is intended for private, isolated environments (local VMs or cloud accounts you control). Misuse may be illegal and unethical.

This notebook contains:
- A reproducible **local Vagrant-based lab** to practice reconnaissance, post-exploitation simulations (defensive-friendly), and detection.
- Hands-on scenario guides (recon, simulated initial access, post-exploitation, pivoting, C2 lab setup) designed for educational use.
- Detection and purple-team exercises using Zeek/Suricata/Security Onion and writing detection content (Suricata rules, Sigma rules examples).
- A **report template** to document findings and recommendations.
- Cleanup scripts and cost/safety notes for cloud variants.

**Prerequisites (host machine):**
- 16+ GB RAM recommended, multi-core CPU, ~50 GB free disk space.
- VirtualBox or VMware (supported by Vagrant).
- Vagrant (2.2.x+) installed.
- Git, curl, and basic Linux shell tools.

**Structure of this pack:**
- Vagrantfile — spins up 3 VMs: `kali`, `ubuntu-dc` (Samba AD minimal), `ubuntu-victim` (Linux victim). Optional: guidance to add Security Onion or a Windows AD image if you have licensed media.
- labs/ — step-by-step lab scenarios (recon, phishing simulation, AD enumeration (safe), C2 install (lab-only), detection tuning).
- scripts/ — convenience scripts (cleanup, snapshot helpers).
- report_template.md — engagement/report template for lab exercises.

Read the **legal & ethics** section in each lab before attempting exercises. Use this notebook responsibly.
