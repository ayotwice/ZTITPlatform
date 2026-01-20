# Zero Trust IT Platform

A comprehensive IT security platform demonstrating **Zero Trust architecture**, **Policy-as-Code**, **Device Trust**, and **Supply Chain Security**.

> Built as a technical demonstration for Ashby's Senior IT Engineer role, showcasing first-principles thinking about modern IT infrastructure automation.

## 🎯 What This Solves

Modern IT teams face a critical challenge: **How do you enforce security policies at scale without becoming a bottleneck?**

This platform demonstrates the answer through four integrated components:

| Component | Problem Solved |
|-----------|---------------|
| **Policy Engine** | Access decisions based on device posture, not just identity |
| **Device Trust Gateway** | Real-time compliance data from MDM to identity provider |
| **Policy-as-Code** | Infrastructure changes via PR, not admin panel clicks |
| **Supply Chain Security** | SBOM tracking to defend against attacks like Shai-Hulud |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        GitOps Layer                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ Pull Request │───▶│GitHub Actions│───▶│Terraform Apply│      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
        ┌───────────────────┐   ┌───────────────────┐
        │   Okta Policies   │   │  Google Workspace │
        └─────────┬─────────┘   └───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Zero Trust Policy Engine                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │Device Comply │  │ Patch SLA    │  │ Risk Score   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                                ▲
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Device Trust Gateway                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Kandji/Iru   │  │ CrowdStrike  │  │ Compliance   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                                ▲
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Supply Chain Security                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ SBOM Manager │  │ Vuln Scanner │  │ Allowlist    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/ayotwice/ZTITPlatform.git
cd ZTITPlatform

# Install dependencies
pip install -r requirements.txt

# Run the policy evaluator demo
python -m src.policy_engine.evaluator

# Run supply chain vulnerability scan
python -m src.supply_chain.vuln_scanner

# Validate Terraform configurations
cd terraform/okta && terraform init && terraform validate
```

## 📁 Repository Structure

```
├── src/
│   ├── policy_engine/      # Zero Trust access decisions
│   ├── device_gateway/     # MDM ↔ IdP integration
│   └── supply_chain/       # SBOM & vulnerability tracking
├── terraform/
│   ├── okta/               # Authentication policies as code
│   ├── google/             # Workspace group management
│   └── modules/            # Reusable zero-trust patterns
├── policies/               # Declarative policy definitions (YAML)
├── .github/workflows/      # GitOps automation
└── docs/                   # Architecture & design decisions
```

## 🔐 Key Features

### Zero Trust Policy Engine
- **Device Compliance Checks**: Validates encryption, MDM enrollment, and security posture
- **Patch SLA Enforcement**: Blocks access if device is >14 days behind on updates
- **Risk-Based Access**: Dynamically adjusts permissions based on posture score
- **Audit Logging**: Every decision logged for compliance evidence

### Device Trust Gateway
- **Real-time Posture Updates**: Webhook integration for instant compliance changes
- **Multi-source Validation**: Combines MDM + EDR data for trust decisions
- **Graceful Degradation**: Continues operating if a provider is unavailable

### Supply Chain Security (Anti-Shai-Hulud)
- **SBOM Generation**: Tracks all software packages across the fleet
- **CVE Correlation**: Cross-references against NVD and OSV databases
- **Package Allowlisting**: Prevents unapproved software installation
- **Incident Response**: Rapid identification of affected devices during attacks

MIT License - Built as a demonstration of IT automation principles.
