# 1-Page Kubernetes Security Lab Checklist (Commands & Tools)

## Environment
- Install:
  - `kind` or `k3d` or `minikube`
  - `kubectl`
  - `trivy`, `kube-bench`, `kube-hunter`, `gatekeeper`, `falco`

## Quick cluster setup (kind)
```bash
kind create cluster --name kcsa-lab
kubectl cluster-info --context kind-kcsa-lab
kubectl create namespace dev
```

## RBAC test
```bash
kubectl create serviceaccount sa-dev -n dev
kubectl create role pod-reader --verb=get,list --resource=pods -n dev
kubectl create rolebinding rb-dev --role=pod-reader --serviceaccount=dev:sa-dev -n dev
kubectl auth can-i create pods --as=system:serviceaccount:dev:sa-dev -n dev
```

## NetworkPolicy test (example)
- Apply `networkpolicy.yaml` to deny all ingress then allow from namespace `frontend`.
```bash
kubectl apply -f networkpolicy.yaml -n backend
```

## Image scanning
```bash
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL myregistry/myimage:tag
```

## Hardening checks
```bash
# kube-bench
kube-bench
# kube-hunter
kube-hunter --remote
```

## Admission & policy
```bash
# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml
# Test a constraint template + constraint
kubectl apply -f disallow-hostpath-template.yaml
kubectl apply -f disallow-hostpath-constraint.yaml
```

## Audit & Logging (local)
- Enable audit in kind via extraConfig (or simulate by logging audit events).
- Inspect `kubectl get events -A` and `kubectl logs` of kube-system controllers.

## Useful utilities
- `kubectl explain <resource>` — read resource schema.
- `kubectl auth can-i ... --as=system:serviceaccount:...` — test RBAC.
- `stern` or `kubetail` — tail multiple pod logs conveniently.

---

Keep this checklist as a single-page quick reference during labs.

=========================================================================================

# KCSA 8-Week Practical Study Plan

**Goal:** Pass KCSA and gain hands-on Kubernetes security fundamentals.

## Week 1 — Foundations & Exam Map
- Read: KCSA exam guide + Kubernetes basics (Pods, Services, Namespaces).
- Labs:
  - Install `kind` or `k3d` and `kubectl`.
  - Deploy `nginx` sample app.
- Commands:
  - `kind create cluster --name kcsa1`
  - `kubectl create deployment nginx --image=nginx`
  - `kubectl get pods -A`

## Week 2 — RBAC & ServiceAccounts
- Learn: Roles, RoleBindings, ClusterRoles, ClusterRoleBindings, ServiceAccounts.
- Labs:
  - Create a namespace `dev` and a Role allowing `get,list` pods.
  - Bind it to a ServiceAccount and test with `kubectl auth can-i`.
- Commands:
  - `kubectl create namespace dev`
  - `kubectl create serviceaccount sa-dev -n dev`
  - `kubectl create role pod-reader --verb=get,list --resource=pods -n dev`
  - `kubectl create rolebinding rb-dev --role=pod-reader --serviceaccount=dev:sa-dev -n dev`
  - `kubectl auth can-i get pods --as=system:serviceaccount:dev:sa-dev -n dev`

## Week 3 — Pod Security & SecurityContext
- Learn: SecurityContext, runAsUser, readOnlyRootFilesystem, privileged=false.
- Labs:
  - Deploy a pod with `securityContext` restrictions; attempt to run a privileged container.
- Commands:
  - Example manifest snippet to test.

## Week 4 — NetworkPolicy & Pod-to-Pod Controls
- Learn: CNI basics, NetworkPolicy semantics (ingress/egress).
- Labs:
  - Create two namespaces (frontend/backend) and restrict traffic using NetworkPolicy.
- Commands:
  - `kubectl apply -f networkpolicy.yaml`
  - `kubectl exec -n frontend <pod> -- curl http://backend-service:80`

## Week 5 — Image Security & Supply Chain Basics
- Learn: Image signing, vulnerability scanning, registries.
- Tools: `trivy`, `clair`, `notary`
- Labs:
  - Scan images: `trivy image nginx:latest`
  - Run a private registry or use Docker Hub and test pull policies.

## Week 6 — Audit Logging & Admission Controllers
- Learn: Audit policy, Admission (OPA/Gatekeeper), PodSecurity admission.
- Labs:
  - Enable audit logs on Kind cluster (use kube-apiserver flags or simulate).
  - Install Gatekeeper and deploy a simple constraint (e.g., disallow hostPath).
- Commands:
  - `kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml`

## Week 7 — Hardening & Scanning Tools
- Tools: `kube-bench`, `kube-hunter`, `kubeaudit`, Falco
- Labs:
  - Run `kube-bench` and remediate 2 findings.
  - Run `kube-hunter` in active mode against cluster (lab only).
- Commands:
  - `kube-bench --version 1.4.0 --config-dir /path/to/config`

## Week 8 — Review & Mock Exam
- Review exam objectives and re-run labs where you had issues.
- Take practice tests and time-boxed lab walkthroughs.
- Deliverable: Write a 1‑page "Security Hardening Report" for your lab cluster summarizing 5 mitigations you applied.

---

**Tips**
- Use `kubectl --kubeconfig=...` for multi-cluster practice.
- Keep small YAML snippets in a repo and version control your lab.
- Record short screencasts when you fix an issue — good portfolio evidence.

==================================================================================================

# 12-Month Roadmap — Cloud Security & Malware Analyst Tracks (Hybrid)

**Objective:** Provide two parallel tracks (Cloud/Kubernetes Security & Offensive/Malware) so you can blend skills.

## Months 0–2: KCSA completion (hands-on)
- Finish the 8-week plan and pass the exam.
- Deliverable: K8s hardening report + GitHub repo with manifests.

## Months 3–5: Foundation split (pick parallel learning)
- Cloud Fundamentals:
  - AWS Free Tier labs (IAM, S3, EC2, VPC, CloudTrail).
  - Complete Solutions Architect Associate or Cloud Practitioner.
- Offense Fundamentals:
  - Basic pentest labs (TryHackMe / Hack The Box beginner paths).
  - Learn Kali toolset, `nmap`, `burpsuite`, `sqlmap`.

## Months 6–9: Specialize
- Cloud/K8s Path:
  - CKS (or CKA+CKS). Implement OPA/Gatekeeper, Falco, Trivy, image signing.
  - Start AWS Security – Specialty prep (or AZ-500 if Azure).
- Offensive/Malware Path:
  - OSCP study & labs (buffer overflows, web, pivoting).
  - Begin reversing basics: Ghidra, x64dbg, static/dynamic triage.

## Months 10–12: Advanced & Portfolio
- Cloud Path:
  - Advanced detection: SIEM hunting (Elastic/Splunk Sigma rules), cloud forensics basics.
  - Build a cloud-native incident playbook.
- Malware Path:
  - Deep reversing: Practical Malware Analysis exercises, REMnux labs.
  - Create 3 malware analysis reports and YARA rules.

## Ongoing (throughout 12 months)
- Weekly: 5–10 hours of hands-on labs + 1 writeup per 2 weeks.
- Monthly: Publish 1 blog post / GitHub writeup.
- Quarterly: Take one certification exam or milestone (e.g., KCSA, then CKS or eCPPT/OSCP).

## Deliverables after 12 months
- Kubernetes security repo (manifests, policies, scanners).
- Pentest & malware writeups (one full OSCP-style report + two malware analyses).
- Two certs achieved (e.g., KCSA + OSCP or KCSA + CKS + AWS Security depending on chosen path).



