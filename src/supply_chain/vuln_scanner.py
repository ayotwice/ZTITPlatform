"""
Vulnerability Scanner

Correlates SBOM data with vulnerability databases to identify
at-risk devices and packages.

Data Sources:
- NVD (National Vulnerability Database)
- OSV (Open Source Vulnerabilities)
- GitHub Security Advisories

This is the core defense against supply chain attacks like Shai-Hulud.
When a vulnerability is discovered in a package, we can immediately:
1. Identify all affected devices
2. Block access from those devices
3. Alert admins for remediation
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set

from .sbom_manager import SBOMManager, DeviceSBOM, Package

logger = logging.getLogger(__name__)


class Severity(Enum):
    """CVE Severity levels (CVSS v3)."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    NONE = "none"          # 0.0


@dataclass
class Vulnerability:
    """
    Represents a known vulnerability.
    """
    cve_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float
    
    # Affected packages
    affected_packages: List[Dict] = field(default_factory=list)
    
    # Fix information
    fixed_versions: List[str] = field(default_factory=list)
    
    # Metadata
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    
    # References
    references: List[str] = field(default_factory=list)
    
    def affects_package(self, name: str, version: str) -> bool:
        """Check if this CVE affects a specific package version."""
        for affected in self.affected_packages:
            if affected.get("name", "").lower() == name.lower():
                # In production, would do proper version comparison
                affected_versions = affected.get("versions", [])
                if version in affected_versions or "*" in affected_versions:
                    return True
        return False


@dataclass
class ScanResult:
    """Result of scanning a device for vulnerabilities."""
    device_id: str
    scan_time: datetime
    
    vulnerabilities: List[Dict] = field(default_factory=list)
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    @property
    def total_count(self) -> int:
        return self.critical_count + self.high_count + self.medium_count + self.low_count
    
    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0
    
    def to_dict(self) -> Dict:
        return {
            "device_id": self.device_id,
            "scan_time": self.scan_time.isoformat(),
            "total_vulnerabilities": self.total_count,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "vulnerabilities": self.vulnerabilities,
        }


class VulnerabilityScanner:
    """
    Scans SBOM data against vulnerability databases.
    
    Key capabilities:
    - Cross-reference packages with CVE databases
    - Calculate risk scores for devices
    - Generate alerts for critical vulnerabilities
    - Track remediation progress
    
    Defense against supply chain attacks (Shai-Hulud):
    - Continuous monitoring for new CVEs
    - Rapid identification of affected devices
    - Integration with access policies to block at-risk devices
    
    Example:
        scanner = VulnerabilityScanner(sbom_manager)
        
        # Scan a device
        result = scanner.scan_device("device-001")
        if result.has_critical:
            block_device_access("device-001")
            alert_security_team(result)
    """
    
    def __init__(self, sbom_manager: Optional[SBOMManager] = None):
        """
        Initialize scanner.
        
        Args:
            sbom_manager: SBOM manager for device inventories
        """
        self.sbom_manager = sbom_manager or SBOMManager()
        self._vuln_db: Dict[str, Vulnerability] = {}
        self._load_vulnerability_database()
    
    def _load_vulnerability_database(self) -> None:
        """
        Load vulnerability data.
        
        In production, this would fetch from:
        - NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
        - OSV API (https://api.osv.dev/v1/query)
        - GitHub Advisory API
        
        For demo, we use mock data including Shai-Hulud example.
        """
        # Shai-Hulud - Supply chain malware example
        self._vuln_db["CVE-2024-SHAI"] = Vulnerability(
            cve_id="CVE-2024-SHAI",
            title="Shai-Hulud Supply Chain Malware",
            description=(
                "A sophisticated supply chain attack that injects malicious code "
                "into legitimate software updates. The malware establishes persistence "
                "and can exfiltrate sensitive data. Named after the sandworms of Dune."
            ),
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            affected_packages=[
                {"name": "compromised-package", "versions": ["1.0.0", "1.0.1"]},
            ],
            fixed_versions=["1.0.2"],
            published_date=datetime(2024, 12, 1),
            references=[
                "https://example.com/shai-hulud-analysis",
            ],
        )
        
        # Real-world inspired examples
        self._vuln_db["CVE-2023-44487"] = Vulnerability(
            cve_id="CVE-2023-44487",
            title="HTTP/2 Rapid Reset Attack",
            description="DoS vulnerability in HTTP/2 implementations.",
            severity=Severity.HIGH,
            cvss_score=7.5,
            affected_packages=[
                {"name": "node", "versions": ["18.0.0", "19.0.0", "20.0.0"]},
            ],
            fixed_versions=["18.18.2", "20.8.1"],
            published_date=datetime(2023, 10, 10),
        )
        
        self._vuln_db["CVE-2023-0286"] = Vulnerability(
            cve_id="CVE-2023-0286",
            title="OpenSSL X.400 Address Type Confusion",
            description="Type confusion in X.400 address processing.",
            severity=Severity.HIGH,
            cvss_score=7.4,
            affected_packages=[
                {"name": "openssl", "versions": ["1.0.2", "1.1.1", "3.0.0", "3.0.1", "3.0.2"]},
            ],
            fixed_versions=["1.1.1t", "3.0.8"],
            published_date=datetime(2023, 2, 7),
        )
        
        self._vuln_db["CVE-2022-42889"] = Vulnerability(
            cve_id="CVE-2022-42889",
            title="Apache Commons Text RCE (Text4Shell)",
            description="Remote code execution via StringSubstitutor.",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            affected_packages=[
                {"name": "commons-text", "versions": ["1.5", "1.6", "1.7", "1.8", "1.9"]},
            ],
            fixed_versions=["1.10.0"],
            published_date=datetime(2022, 10, 13),
        )
        
        logger.info(f"Loaded {len(self._vuln_db)} vulnerabilities into database")
    
    def scan_device(self, device_id: str) -> ScanResult:
        """
        Scan a device's SBOM for vulnerabilities.
        
        Returns:
            ScanResult with all found vulnerabilities
        """
        sbom = self.sbom_manager.get_sbom(device_id)
        
        result = ScanResult(
            device_id=device_id,
            scan_time=datetime.now(),
        )
        
        if not sbom:
            logger.warning(f"No SBOM found for device {device_id}")
            return result
        
        # Check each package against vulnerability database
        for package in sbom.packages:
            vulns = self._check_package(package)
            for vuln in vulns:
                result.vulnerabilities.append({
                    "cve_id": vuln.cve_id,
                    "package": package.name,
                    "installed_version": package.version,
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "fixed_in": vuln.fixed_versions,
                    "title": vuln.title,
                })
                
                # Count by severity
                if vuln.severity == Severity.CRITICAL:
                    result.critical_count += 1
                elif vuln.severity == Severity.HIGH:
                    result.high_count += 1
                elif vuln.severity == Severity.MEDIUM:
                    result.medium_count += 1
                else:
                    result.low_count += 1
        
        logger.info(
            f"Scan complete for {device_id}: "
            f"{result.total_count} vulnerabilities found "
            f"({result.critical_count} critical)"
        )
        
        return result
    
    def _check_package(self, package: Package) -> List[Vulnerability]:
        """Check a package against all known vulnerabilities."""
        found = []
        for vuln in self._vuln_db.values():
            if vuln.affects_package(package.name, package.version):
                found.append(vuln)
        return found
    
    def scan_fleet(self) -> Dict[str, ScanResult]:
        """
        Scan all devices in the fleet.
        
        Returns:
            Dict of device_id -> ScanResult
        """
        results = {}
        
        for device_id in self.sbom_manager._sbom_cache.keys():
            results[device_id] = self.scan_device(device_id)
        
        # Summary statistics
        total_critical = sum(r.critical_count for r in results.values())
        total_high = sum(r.high_count for r in results.values())
        
        logger.info(
            f"Fleet scan complete: {len(results)} devices, "
            f"{total_critical} critical, {total_high} high severity"
        )
        
        return results
    
    def find_affected_by_cve(self, cve_id: str) -> List[str]:
        """
        Find all devices affected by a specific CVE.
        
        Critical for incident response - when a new CVE is disclosed,
        quickly identify all affected devices.
        """
        vuln = self._vuln_db.get(cve_id)
        if not vuln:
            logger.warning(f"CVE {cve_id} not in database")
            return []
        
        affected_devices = []
        
        for device_id, sbom in self.sbom_manager._sbom_cache.items():
            for package in sbom.packages:
                if vuln.affects_package(package.name, package.version):
                    affected_devices.append(device_id)
                    break
        
        return affected_devices
    
    def get_vulnerability_report(self) -> Dict:
        """
        Generate a fleet-wide vulnerability report.
        
        Suitable for security dashboard or compliance reporting.
        """
        results = self.scan_fleet()
        
        # Aggregate vulnerability counts
        vuln_counts: Dict[str, int] = {}
        for result in results.values():
            for vuln in result.vulnerabilities:
                cve_id = vuln["cve_id"]
                vuln_counts[cve_id] = vuln_counts.get(cve_id, 0) + 1
        
        # Sort by impact (device count)
        sorted_vulns = sorted(
            vuln_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        
        return {
            "generated_at": datetime.now().isoformat(),
            "fleet_size": len(results),
            "devices_with_critical": sum(1 for r in results.values() if r.has_critical),
            "total_vulnerabilities": sum(r.total_count for r in results.values()),
            "unique_cves": len(vuln_counts),
            "most_prevalent": [
                {"cve_id": cve, "affected_devices": count}
                for cve, count in sorted_vulns[:10]
            ],
        }


# Demo entry point
if __name__ == "__main__":
    # Initialize with mock data
    sbom_manager = SBOMManager()
    sbom_manager.import_mock_data()
    
    scanner = VulnerabilityScanner(sbom_manager)
    
    print(f"\n{'='*60}")
    print("Vulnerability Scanner Demo")
    print(f"{'='*60}")
    
    # Scan single device
    result = scanner.scan_device("device-001")
    print(f"\nDevice 001 Scan:")
    print(f"  Total: {result.total_count}")
    print(f"  Critical: {result.critical_count}")
    print(f"  High: {result.high_count}")
    
    # Fleet scan
    fleet_results = scanner.scan_fleet()
    print(f"\nFleet Scan:")
    print(f"  Devices scanned: {len(fleet_results)}")
    
    # Find devices affected by specific CVE
    affected = scanner.find_affected_by_cve("CVE-2024-SHAI")
    print(f"\nDevices affected by Shai-Hulud: {len(affected)}")
    
    # Generate report
    report = scanner.get_vulnerability_report()
    print(f"\nVulnerability Report:")
    print(f"  Unique CVEs: {report['unique_cves']}")
    print(f"  Devices with critical: {report['devices_with_critical']}")
    
    print(f"{'='*60}\n")
