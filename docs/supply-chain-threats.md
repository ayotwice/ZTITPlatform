# Supply Chain Threat Model

## Overview

Software supply chain attacks have become one of the most significant threats to enterprise security. This document outlines the threat landscape and how this platform defends against these attacks.

## Notable Supply Chain Attacks

### Shai-Hulud (2024)

**Attack Vector:**
A sophisticated backdoor inserted into legitimate software update mechanisms. Named after the giant sandworms from Dune, it "burrows" into systems and remains dormant until activated.

**Characteristics:**
- Targets widely-used enterprise software
- Injected during the build/signing process
- Legitimate digital signatures (signed by compromised vendor)
- Communication with C2 via DNS or HTTPS blending with normal traffic
- Modular payload - can download additional capabilities

**Why It's Dangerous:**
- Bypasses traditional perimeter security
- Legitimate signatures evade most controls
- Wide blast radius (affects all customers of vendor)
- Long dwell time before detection

### SolarWinds (2020)

Compromised build process injected backdoor into Orion updates. Affected ~18,000 organizations including government agencies.

### Codecov (2021)

Bash uploader script modified to exfiltrate CI/CD secrets.

### ua-parser-js (2021)

Popular npm package hijacked to install cryptominers.

---

## Threat Model

### Attack Surfaces

1. **Software Packages**
   - Compromised packages in public repositories (npm, PyPI)
   - Typosquatting (similar names to popular packages)
   - Account takeover of maintainers

2. **Build Systems**
   - Compromised CI/CD pipelines
   - Malicious build dependencies
   - Tampered artifacts

3. **Distribution**
   - Compromised update servers
   - Man-in-the-middle on update channels
   - DNS hijacking

4. **Devices**
   - Pre-installed malware on hardware
   - Compromised firmware
   - Supply chain for accessories

### Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| Nation-state | Espionage, disruption | Very high, patient |
| Criminal | Financial | High, opportunistic |
| Hacktivist | Ideology | Medium |
| Insider | Various | Direct access |

---

## Defense Strategy

### Layer 1: Visibility (SBOM)

**Goal:** Know exactly what software is installed across all devices.

**Implementation:**
- Generate SBOM for every device via MDM
- Track all packages with versions
- Maintain package-to-device mapping
- Update continuously (not point-in-time)

**Enables:**
- "Which devices have package X?" - answered in seconds
- Baseline for anomaly detection
- Compliance evidence

### Layer 2: Prevention (Allowlisting)

**Goal:** Only approved software can be installed.

**Implementation:**
- Maintain allowlist of approved packages
- Block installation of unapproved software
- Require security review for new additions
- GitOps process for allowlist changes

**Trade-offs:**
- More friction for users
- Requires process for exceptions
- Must balance security vs. productivity

### Layer 3: Detection (Vulnerability Scanning)

**Goal:** Identify vulnerable packages before exploitation.

**Implementation:**
- Daily scans against CVE databases
- Real-time alerting on critical findings
- Integration with NVD, OSV, GitHub Advisories
- Blocklist known-malicious packages

**Coverage:**
- Known vulnerabilities (CVE-based)
- Known-malicious packages
- Does NOT catch zero-day compromises

### Layer 4: Response (Incident Handling)

**Goal:** Minimize impact when compromise occurs.

**Implementation:**
- Automated alerting (Slack, PagerDuty)
- Device isolation capability
- Rapid identification of affected devices
- Playbooks for common scenarios

**Key Metrics:**
- Time to detect
- Time to isolate
- Number of affected devices

---

## Shai-Hulud-Specific Defenses

### Detection Indicators

```yaml
# Example detection rules
detections:
  - name: "Uncommon network destinations"
    description: "New outbound connections to unusual domains"
    
  - name: "Process anomaly"
    description: "Unexpected child processes from trusted applications"
    
  - name: "Scheduled task creation"
    description: "New persistence mechanisms"
```

### Response Playbook

1. **Immediate (0-15 minutes)**
   - Identify affected devices via SBOM query
   - Isolate affected devices from network
   - Preserve forensic evidence (don't power off)
   - Notify security team

2. **Short-term (1-4 hours)**
   - Assess scope of compromise
   - Determine data exposure risk
   - Contain lateral movement
   - Begin stakeholder communication

3. **Recovery (1-7 days)**
   - Rebuild affected devices from known-good
   - Rotate credentials that may be compromised
   - Monitor for re-infection
   - Conduct retrospective

---

## Metrics & Monitoring

### Key Performance Indicators

| Metric | Target | Measurement |
|--------|--------|-------------|
| SBOM coverage | 100% | Devices with current SBOM |
| Scan frequency | Daily | Time since last scan |
| Vulnerability backlog | <10 critical | Unpatched critical CVEs |
| Allowlist violations | <5/week | Unapproved installs detected |
| Detection latency | <24 hours | Time from CVE publish to scan |

### Dashboards

- Fleet vulnerability posture
- Package inventory trends
- Allowlist violation frequency
- Incident response metrics

---

## Future Enhancements

1. **Behavioral Analysis**
   - Detect anomalous package behavior
   - ML-based threat detection

2. **Build Verification**
   - SLSA compliance checking
   - Reproducible builds verification

3. **Vendor Risk Scoring**
   - Security posture of software vendors
   - Automated vendor assessments

4. **Threat Intelligence Integration**
   - Real-time feed of emerging threats
   - Automatic blocklist updates
