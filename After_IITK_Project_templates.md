
# SEG_Project_templates.md

This file contains templates and practical step-by-step lab blueprints you can reuse.

---

## A. Pentest Report Template (SEG_Pentest_Report.md)
Use this template when producing an assessment.

### Cover Page
- Title: Security Assessment / Penetration Test
- Client: <Client-Name>
- Date: <Date>
- Scope: <IP ranges / Hosts / Apps>
- Authors: <Your Name>

### Executive Summary
- High-level findings (1–3 bullets)
- Business impact (concise)

### Methodology
- Reconnaissance
- Scanning
- Exploitation
- Post-exploitation
- Reporting

### Findings (per item)
1. Title: <Finding title>
   - Severity: Critical / High / Medium / Low
   - Affected assets: <list>
   - Description: <technical explanation>
   - PoC: <commands, screenshots>
   - Recommendation: <fix steps>
   - CVSS: <score if computed>

### Appendix
- Full command logs
- Screenshots
- Raw outputs (redacted)
- Tools versions

---

## B. Lab Build — AD Domain (blueprint)
**Objective:** Deploy a 1-DC + 2 client AD environment for testing.

### VM Specs
- DC: Windows Server 2019, 2vCPU, 6GB RAM, 60GB disk
- Client1: Windows 10, 2vCPU, 4GB RAM, 40GB disk
- Client2: Windows 10, 2vCPU, 4GB RAM, 40GB disk
- Attacker: Kali Linux, 2vCPU, 4GB RAM, 40GB disk

### Steps
1. Install Windows Server; configure static IP; install Active Directory Domain Services; create domain `seg.local`.
2. Promote DC, create OUs, users: `corp\alice`, `corp\bob`, `corp\svc_backup`.
3. Join clients to domain; create a simple file share on `Client2` with sensitive file for exfil.
4. Install BloodHound ingestor (SharpHound) on attacker to enumerate domain relationships.
5. Snapshot VMs.

---

## C. Lab Build — Cloud (AWS) misconfig blueprint
**Objective:** Simulate S3 public data leak and IAM over-permission.

### Steps
1. Create AWS sandbox account with MFA and billing alerts.
2. Create S3 bucket `seg-demo-<yourid>`, add sample "secrets.txt".
3. Set bucket ACL to public (for testing only).
4. Create IAM user `developer` with policy granting `s3:*` on the bucket (excessive perms).
5. Demonstrate data access via `aws-cli` and suggest remediation: policy scoping, encryption at rest, block public access.

---

## D. Sample Engagement Checklist (SEG_Engagement_Checklist.md)
- [ ] Signed contract + SOW
- [ ] Signed NDA
- [ ] Define scope (IPs, domains, apps)
- [ ] Testing windows / ROE
- [ ] Emergency contact
- [ ] Data handling policy
- [ ] Report delivery schedule

---

## E. Example Commands & Useful Snippets
**EML parsing (python)**:
```
from email import policy, parser
with open('sample.eml','rb') as f:
    msg = parser.BytesParser(policy=policy.default).parse(f)
subject = msg['subject']
for part in msg.walk():
    if part.get_content_disposition() == 'attachment':
        payload = part.get_payload(decode=True)
```

**Basic pwntools exploit skeleton**:
```python
from pwn import *
p = process('./vuln')
payload = b'A'*136 + p64(0xdeadbeef)
p.sendline(payload)
p.interactive()
```

---

# End of project templates
