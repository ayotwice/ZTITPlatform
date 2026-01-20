"""
Package Allowlist Manager

Manages approved software packages that can be installed on devices.
Part of supply chain security - prevents unapproved or malicious
software from being deployed.

Defense Strategy:
1. Maintain allowlist of approved packages and versions
2. Alert on installation of non-approved software
3. Block deployment of known-malicious packages
4. Track approval workflow and exceptions
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """Package approval status."""
    APPROVED = "approved"
    PENDING = "pending"
    DENIED = "denied"
    DEPRECATED = "deprecated"
    BLOCKED = "blocked"  # Known malicious


@dataclass
class AllowlistEntry:
    """
    An entry in the software allowlist.
    """
    package_name: str
    approved_versions: List[str]
    status: ApprovalStatus
    
    # Approval metadata
    approved_by: Optional[str] = None
    approved_date: Optional[datetime] = None
    
    # Deployment restrictions
    allowed_departments: List[str] = field(default_factory=list)  # Empty = all
    requires_justification: bool = False
    
    # Security review
    security_reviewed: bool = False
    last_review_date: Optional[datetime] = None
    
    # Notes
    notes: str = ""
    
    def is_version_approved(self, version: str) -> bool:
        """Check if a specific version is approved."""
        if self.status != ApprovalStatus.APPROVED:
            return False
        return version in self.approved_versions or "*" in self.approved_versions


@dataclass
class AllowlistViolation:
    """
    Record of an allowlist violation.
    """
    device_id: str
    package_name: str
    package_version: str
    violation_type: str  # "unapproved", "blocked", "wrong_version"
    detected_at: datetime
    
    # Resolution
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolution_notes: str = ""


class PackageAllowlistManager:
    """
    Manages the software package allowlist.
    
    Key capabilities:
    - Define approved packages and versions
    - Check installations against allowlist
    - Track violations and exceptions
    - Support approval workflows
    
    Integration points:
    - Kandji/Jamf: Prevent non-approved app installs
    - SBOM Scanner: Detect violations in software inventory
    - Policy Engine: Factor allowlist compliance into access decisions
    
    Example:
        manager = PackageAllowlistManager()
        
        # Check if package is allowed
        if manager.is_allowed("Slack", "4.35.126"):
            proceed_with_install()
        else:
            raise SecurityViolation("Package not on allowlist")
    """
    
    def __init__(self):
        """Initialize with default allowlist."""
        self._allowlist: Dict[str, AllowlistEntry] = {}
        self._violations: List[AllowlistViolation] = []
        self._blocklist: Set[str] = set()
        
        self._load_default_allowlist()
    
    def _load_default_allowlist(self) -> None:
        """Load default approved packages."""
        
        # Standard productivity apps
        approved_apps = [
            ("Google Chrome", ["*"], "Standard browser"),
            ("Firefox", ["*"], "Alternative browser"),
            ("Slack", ["*"], "Company communication"),
            ("Zoom", ["*"], "Video conferencing"),
            ("1Password", ["*"], "Password management"),
            ("Microsoft Office", ["*"], "Productivity suite"),
            ("Visual Studio Code", ["*"], "Development"),
            ("iTerm2", ["*"], "Terminal"),
            ("Docker", ["*"], "Containerization"),
        ]
        
        # Security tools - always approved
        security_apps = [
            ("CrowdStrike Falcon", ["*"], "EDR - required"),
            ("Kandji", ["*"], "MDM agent"),
        ]
        
        for name, versions, notes in approved_apps + security_apps:
            self._allowlist[name.lower()] = AllowlistEntry(
                package_name=name,
                approved_versions=versions,
                status=ApprovalStatus.APPROVED,
                approved_by="IT Security",
                approved_date=datetime(2024, 1, 1),
                security_reviewed=True,
                notes=notes,
            )
        
        # Blocked packages (known malicious or problematic)
        self._blocklist = {
            "compromised-package",  # Shai-Hulud vector
            "malicious-helper",
            "fake-antivirus",
        }
        
        logger.info(
            f"Loaded allowlist: {len(self._allowlist)} approved, "
            f"{len(self._blocklist)} blocked"
        )
    
    def is_allowed(self, package_name: str, version: str) -> bool:
        """
        Check if a package/version is allowed.
        
        Returns:
            True if package and version are approved
        """
        # Check blocklist first
        if package_name.lower() in self._blocklist:
            return False
        
        entry = self._allowlist.get(package_name.lower())
        if not entry:
            return False
        
        return entry.is_version_approved(version)
    
    def is_blocked(self, package_name: str) -> bool:
        """Check if package is on blocklist."""
        return package_name.lower() in self._blocklist
    
    def check_device_compliance(
        self,
        device_id: str,
        installed_packages: List[Dict],
    ) -> List[AllowlistViolation]:
        """
        Check device's installed packages against allowlist.
        
        Returns:
            List of violations found
        """
        violations = []
        
        for pkg in installed_packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            
            if self.is_blocked(name):
                violation = AllowlistViolation(
                    device_id=device_id,
                    package_name=name,
                    package_version=version,
                    violation_type="blocked",
                    detected_at=datetime.now(),
                )
                violations.append(violation)
                logger.warning(f"BLOCKED package detected: {name} on {device_id}")
                
            elif not self.is_allowed(name, version):
                violation = AllowlistViolation(
                    device_id=device_id,
                    package_name=name,
                    package_version=version,
                    violation_type="unapproved",
                    detected_at=datetime.now(),
                )
                violations.append(violation)
                logger.info(f"Unapproved package: {name}@{version} on {device_id}")
        
        self._violations.extend(violations)
        return violations
    
    def add_to_allowlist(
        self,
        package_name: str,
        versions: List[str],
        approved_by: str,
        notes: str = "",
        security_reviewed: bool = False,
    ) -> AllowlistEntry:
        """
        Add a package to the allowlist.
        
        In production, this would go through an approval workflow.
        """
        entry = AllowlistEntry(
            package_name=package_name,
            approved_versions=versions,
            status=ApprovalStatus.APPROVED,
            approved_by=approved_by,
            approved_date=datetime.now(),
            security_reviewed=security_reviewed,
            notes=notes,
        )
        
        self._allowlist[package_name.lower()] = entry
        logger.info(f"Added to allowlist: {package_name} by {approved_by}")
        
        return entry
    
    def add_to_blocklist(self, package_name: str, reason: str) -> None:
        """Add a package to the blocklist."""
        self._blocklist.add(package_name.lower())
        logger.warning(f"Added to blocklist: {package_name} - {reason}")
    
    def get_pending_violations(self) -> List[AllowlistViolation]:
        """Get unresolved violations."""
        return [v for v in self._violations if not v.resolved]
    
    def get_allowlist_report(self) -> Dict:
        """Generate allowlist status report."""
        return {
            "generated_at": datetime.now().isoformat(),
            "approved_packages": len(self._allowlist),
            "blocked_packages": len(self._blocklist),
            "pending_violations": len(self.get_pending_violations()),
            "total_violations": len(self._violations),
            "approved_list": [
                {
                    "name": entry.package_name,
                    "versions": entry.approved_versions,
                    "reviewed": entry.security_reviewed,
                }
                for entry in self._allowlist.values()
            ],
            "blocked_list": list(self._blocklist),
        }


# Demo entry point
if __name__ == "__main__":
    manager = PackageAllowlistManager()
    
    print(f"\n{'='*60}")
    print("Package Allowlist Manager Demo")
    print(f"{'='*60}")
    
    # Check some packages
    packages = [
        ("Slack", "4.35.126"),
        ("compromised-package", "1.0.0"),
        ("unknown-app", "2.0.0"),
    ]
    
    print("\nPackage Checks:")
    for name, version in packages:
        allowed = manager.is_allowed(name, version)
        blocked = manager.is_blocked(name)
        status = "BLOCKED" if blocked else ("ALLOWED" if allowed else "NOT APPROVED")
        print(f"  {name}@{version}: {status}")
    
    # Check device compliance
    device_packages = [
        {"name": "Slack", "version": "4.35.126"},
        {"name": "compromised-package", "version": "1.0.0"},
        {"name": "random-tool", "version": "1.0.0"},
    ]
    
    violations = manager.check_device_compliance("device-001", device_packages)
    print(f"\nDevice 001 Violations: {len(violations)}")
    for v in violations:
        print(f"  - {v.package_name}: {v.violation_type}")
    
    # Report
    report = manager.get_allowlist_report()
    print(f"\nAllowlist Report:")
    print(f"  Approved: {report['approved_packages']}")
    print(f"  Blocked: {report['blocked_packages']}")
    print(f"  Violations: {report['total_violations']}")
    
    print(f"{'='*60}\n")
