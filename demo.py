#!/usr/bin/env python3
"""
Zero Trust Platform - Interactive Demo

Run this to see the platform in action!
Usage: python demo.py
"""

from datetime import datetime, timedelta
from src.policy_engine.models import DevicePosture, User, Application, AccessRequest
from src.policy_engine.evaluator import PolicyEvaluator
from src.device_gateway import TrustBroker, TrustLevel
from src.supply_chain import SBOMManager, VulnerabilityScanner, PackageAllowlistManager


def demo_policy_engine():
    """Demonstrate the Zero Trust Policy Engine."""
    print("\n" + "=" * 70)
    print("ZERO TRUST POLICY ENGINE - ACCESS DECISION DEMO")
    print("=" * 70)
    
    evaluator = PolicyEvaluator()
    user = User(
        user_id="u001",
        email="alice@ashby.com",
        department="Engineering",
        role="Engineer",
        mfa_enrolled=True,
    )
    app = Application(
        app_id="github",
        name="GitHub",
        sensitivity="high",
        requires_compliant_device=True,
    )
    
    # SCENARIO 1: Compliant Device
    print("\n[SCENARIO 1] Compliant macOS device requesting GitHub access")
    print("-" * 70)
    
    device1 = DevicePosture(
        device_id="MBP-ENG-042",
        serial_number="C02XG1FHJGH5",
        platform="macos",
        os_version="14.2.1",
        disk_encrypted=True,
        mdm_enrolled=True,
        mdm_provider="kandji",
        last_patch_date=datetime.now() - timedelta(days=5),
        firewall_enabled=True,
        edr_installed=True,
        edr_provider="crowdstrike",
        active_threats=0,
    )
    
    request1 = AccessRequest(
        request_id="req-001",
        timestamp=datetime.now(),
        user=user,
        device=device1,
        application=app,
        source_ip="10.0.1.50",
        user_agent="Chrome",
    )
    
    result1 = evaluator.evaluate(request1)
    
    print(f"User: {user.email}")
    print(f"Device: {device1.device_id}")
    print(f"  - Encrypted: {device1.disk_encrypted}")
    print(f"  - MDM Enrolled: {device1.mdm_enrolled}")
    print(f"  - EDR Installed: {device1.edr_installed}")
    print(f"  - Days since patch: {(datetime.now() - device1.last_patch_date).days}")
    print(f"\n>>> DECISION: {result1.decision.value.upper()}")
    
    # SCENARIO 2: Unpatched Device
    print("\n[SCENARIO 2] Device 20 days behind on patches (violates 14-day SLA)")
    print("-" * 70)
    
    device2 = DevicePosture(
        device_id="MBP-SALES-007",
        serial_number="C02YK2ABCDE",
        platform="macos",
        os_version="14.0.0",
        disk_encrypted=True,
        mdm_enrolled=True,
        last_patch_date=datetime.now() - timedelta(days=20),
        firewall_enabled=True,
        edr_installed=True,
        active_threats=0,
    )
    
    request2 = AccessRequest(
        request_id="req-002",
        timestamp=datetime.now(),
        user=user,
        device=device2,
        application=app,
        source_ip="10.0.1.51",
        user_agent="Chrome",
    )
    
    result2 = evaluator.evaluate(request2)
    
    print(f"Device: {device2.device_id}")
    print(f"Days since patch: {(datetime.now() - device2.last_patch_date).days} (SLA: 14 days)")
    print(f"\n>>> DECISION: {result2.decision.value.upper()}")
    if result2.failed_policies:
        print(f"Failed policies: {result2.failed_policies}")
    
    # SCENARIO 3: Compromised Device
    print("\n[SCENARIO 3] Device with active malware detection")
    print("-" * 70)
    
    device3 = DevicePosture(
        device_id="MBP-FIN-003",
        serial_number="C02ZL3FGHIJ",
        platform="macos",
        os_version="14.2.1",
        disk_encrypted=True,
        mdm_enrolled=True,
        last_patch_date=datetime.now() - timedelta(days=3),
        firewall_enabled=True,
        edr_installed=True,
        active_threats=2,
    )
    
    request3 = AccessRequest(
        request_id="req-003",
        timestamp=datetime.now(),
        user=user,
        device=device3,
        application=app,
        source_ip="10.0.1.52",
        user_agent="Chrome",
    )
    
    result3 = evaluator.evaluate(request3)
    
    print(f"Device: {device3.device_id}")
    print(f"Active threats detected: {device3.active_threats}")
    print(f"\n>>> DECISION: {result3.decision.value.upper()}")


def demo_device_gateway():
    """Demonstrate the Device Trust Gateway."""
    print("\n" + "=" * 70)
    print("DEVICE TRUST GATEWAY - MDM/EDR INTEGRATION DEMO")
    print("=" * 70)
    
    broker = TrustBroker()
    
    devices = [
        ("compliant-device", "Fully compliant device"),
        ("noncompliant-device", "Non-compliant device"),
    ]
    
    for device_id, description in devices:
        print(f"\n[{description}]")
        print("-" * 70)
        
        signal = broker.evaluate_device(device_id)
        
        print(f"Device ID: {signal.device_id}")
        print(f"Trust Level: {signal.trust_level.value.upper()}")
        print(f"Trust Score: {signal.trust_score}/100")
        print(f"  - MDM Compliant: {signal.mdm_compliant}")
        print(f"  - Encryption: {signal.encryption_enabled}")
        print(f"  - EDR Healthy: {signal.edr_healthy}")


def demo_supply_chain():
    """Demonstrate Supply Chain Security."""
    print("\n" + "=" * 70)
    print("SUPPLY CHAIN SECURITY - SBOM & VULNERABILITY DEMO")
    print("=" * 70)
    
    # Initialize
    sbom_manager = SBOMManager()
    sbom_manager.import_mock_data()
    scanner = VulnerabilityScanner(sbom_manager)
    allowlist = PackageAllowlistManager()
    
    # Fleet overview
    print("\n[Fleet Overview]")
    print("-" * 70)
    fleet = sbom_manager.export_fleet_sbom()
    print(f"Devices tracked: {fleet['device_count']}")
    print(f"Unique packages: {fleet['unique_packages']}")
    
    # Vulnerability scan
    print("\n[Vulnerability Scan]")
    print("-" * 70)
    report = scanner.get_vulnerability_report()
    print(f"Devices scanned: {report['fleet_size']}")
    print(f"Devices with CRITICAL vulns: {report['devices_with_critical']}")
    print(f"Unique CVEs found: {report['unique_cves']}")
    
    # Shai-Hulud check
    print("\n[Supply Chain Attack Check: Shai-Hulud]")
    print("-" * 70)
    affected = scanner.find_affected_by_cve("CVE-2024-SHAI")
    print(f"Devices affected by Shai-Hulud: {len(affected)}")
    
    # Allowlist check
    print("\n[Package Allowlist Check]")
    print("-" * 70)
    packages = [
        ("Slack", "4.35.126"),
        ("compromised-package", "1.0.0"),
        ("unknown-app", "2.0.0"),
    ]
    for name, version in packages:
        allowed = allowlist.is_allowed(name, version)
        blocked = allowlist.is_blocked(name)
        if blocked:
            status = "BLOCKED"
        elif allowed:
            status = "ALLOWED"
        else:
            status = "NOT APPROVED"
        print(f"  {name}@{version}: {status}")


def main():
    """Run all demos."""
    print("\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#" + "  ASHBY ZERO TRUST IT PLATFORM - TECHNICAL DEMO".center(68) + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)
    
    demo_policy_engine()
    demo_device_gateway()
    demo_supply_chain()
    
    print("\n" + "=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print("\nThis demonstrates John's requirement from the video:")
    print('"Applications can only be accessed from company machines where we')
    print('know that they dont have an active compromise and are patched')
    print('inside of a two-week SLA"')
    print("\n")


if __name__ == "__main__":
    main()
