# Lab 03 — Lightweight AD-like Environment & Enumeration (Safe)

**Goal:** Practice discovery and mapping of directory-like environments. This lab uses a Samba AD-lite setup or a prebuilt Windows AD VM if you have licensed images. The intent is to practice enumeration in a lab, not credential theft against unconsenting systems.

## Options
- Option A: Use a licensed Windows Server evaluation ISO in your lab to build a real AD. (Follow Microsoft evaluation licensing rules).
- Option B: Use Samba AD provisioning on the `ubuntu-dc` VM. The Samba provisioning steps are non-trivial and are included for completeness; proceed only in lab and follow docs.

## Enumerating (example) — using safe, read-only enumeration
From `kali` (with appropriate tools installed):
```bash
# Install impacket utils for safe enumeration (ldapenum, etc.)
pip3 install impacket
# Example: list SMB shares (read-only)
smbclient -L //192.168.56.12 -N
# Example: DNS enumeration (if AD DNS configured)
dig @192.168.56.11 _ldap._tcp.dc._msdcs.lab SRV +short
```
## BloodHound (graph analytics) — lab-only
- BloodHound requires data collectors (SharpHound). In lab, use it to visualize relationships **only** and do not use it as a vector for credential harvesting on non-lab systems.
- Run BloodHound UI on a host and import collected JSON from your lab data collector runs (in lab only).

## Deliverable
- Enumeration notes and a sanitized BloodHound graph exported as a PDF (lab-only).
