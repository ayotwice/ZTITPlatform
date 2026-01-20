# Architecture Documentation

## Overview

This Zero Trust IT Platform implements a defense-in-depth approach to device security and access control. Rather than trusting devices based solely on network location or user identity, we continuously verify device health before granting access.

## Core Architecture Principles

### 1. Never Trust, Always Verify

Traditional IT security assumed devices on the corporate network were trustworthy. This model fails in a remote-first world. Our approach:

- **Every access request is evaluated** against device posture
- **Trust is ephemeral** - device state changes can revoke access
- **Multiple signals** inform trust decisions (MDM + EDR + patching)

### 2. Policy as Code

All security policies are defined in code and version controlled:

```
terraform/          # Infrastructure definitions
policies/           # Declarative policy YAML
.github/workflows/  # Automated deployment
```

Benefits:
- **Audit trail** - Every change is a PR with reviewer
- **Reproducibility** - Can recreate any configuration
- **Testing** - Validate changes before applying

### 3. Defense in Depth

Multiple layers of protection:

```
┌─────────────────────────────────────────────┐
│ Layer 1: Identity (Okta)                    │
│   - Who is requesting access?               │
│   - Is MFA satisfied?                       │
├─────────────────────────────────────────────┤
│ Layer 2: Device Trust (Policy Engine)       │
│   - Is device managed and compliant?        │
│   - Is device patched within SLA?           │
│   - Are there active threats?               │
├─────────────────────────────────────────────┤
│ Layer 3: Application Policies               │
│   - Does user have permission?              │
│   - Is device posture sufficient?           │
├─────────────────────────────────────────────┤
│ Layer 4: Supply Chain Security              │
│   - Is installed software approved?         │
│   - Are there vulnerable packages?          │
└─────────────────────────────────────────────┘
```

## Component Architecture

### Policy Engine

The central decision point for access control.

**Responsibilities:**
- Evaluate device posture against policies
- Calculate risk scores
- Return ALLOW/DENY/STEP_UP decisions
- Log all decisions for audit

**Key Files:**
- `src/policy_engine/evaluator.py` - Main decision engine
- `src/policy_engine/rules/` - Individual policy rules

### Device Trust Gateway

Bridges MDM, EDR, and identity providers.

**Data Flow:**
```
Kandji (MDM) ──┐
               ├──► Trust Broker ──► Okta
CrowdStrike ───┘         │
                         ▼
                   Policy Engine
```

**Key Files:**
- `src/device_gateway/trust_broker.py` - Trust synthesis
- `src/device_gateway/providers/` - API clients

### Supply Chain Security

Protects against software supply chain attacks.

**Components:**
1. **SBOM Manager** - Tracks all software inventory
2. **Vulnerability Scanner** - Correlates with CVE databases
3. **Package Allowlist** - Controls approved software
4. **Alert Manager** - Notifies on threats

**Attack Defense (Shai-Hulud):**
```
1. Maintain complete software inventory (SBOM)
2. Continuously scan for known-bad packages
3. Block deployment of unapproved software
4. Alert on detection of malicious packages
5. Rapid identification of affected devices
```

## Data Flow

### Access Request Flow

```
User clicks "Open GitHub"
         │
         ▼
┌─────────────────────┐
│ Okta Login Page     │
│ (Identity verified) │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Device Trust Check  │◄───── Kandji/CrowdStrike data
│ (Policy Engine)     │
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    │           │
    ▼           ▼
 ALLOW       DENY
    │           │
    ▼           ▼
 Access     Remediation
 Granted    Instructions
```

### Continuous Compliance

```
┌────────────────────────────────────────┐
│ Scheduled Jobs (GitHub Actions)        │
├────────────────────────────────────────┤
│ Daily: SBOM vulnerability scan         │
│ Hourly: Device compliance sync         │
│ On-demand: Emergency CVE check         │
└────────────────────────────────────────┘
          │
          ▼
┌────────────────────────────────────────┐
│ Findings                               │
├────────────────────────────────────────┤
│ Critical → PagerDuty + Slack + Email   │
│ High → Slack + Email                   │
│ Medium → Slack                         │
│ Low → Weekly report                    │
└────────────────────────────────────────┘
```

## Security Considerations

### Fail-Closed Design

When in doubt, deny access:
- Unknown device → DENY
- Missing compliance data → DENY
- API failure → DENY (log for investigation)

### Least Privilege

Access policies follow least privilege:
- Role-based access control
- Time-limited sessions
- No persistent admin access

### Audit Logging

Every decision is logged:
```json
{
  "request_id": "req-12345",
  "user": "alice@company.com",
  "device": "device-001",
  "application": "github",
  "decision": "ALLOW",
  "posture_score": 85,
  "policies_evaluated": ["device_compliance", "patch_sla", "posture_check"],
  "timestamp": "2025-01-19T14:30:00Z"
}
```

## Scalability

### Current Design
- Single-region deployment
- Synchronous policy evaluation
- Cache-friendly architecture

### Future Considerations
- Multi-region for latency
- Async evaluation for non-critical paths
- Event-driven architecture for real-time updates
