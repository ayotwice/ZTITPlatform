"""
Supply Chain Security package.

Provides SBOM management, vulnerability scanning, and 
package allowlisting for supply chain attack prevention.
"""

from .sbom_manager import SBOMManager, DeviceSBOM, Package, PackageType
from .vuln_scanner import VulnerabilityScanner, ScanResult, Vulnerability, Severity
from .package_allowlist import PackageAllowlistManager, AllowlistEntry, ApprovalStatus
from .alerts import AlertManager, Alert, AlertSeverity, AlertChannel

__all__ = [
    # SBOM
    "SBOMManager",
    "DeviceSBOM",
    "Package",
    "PackageType",
    # Vulnerability scanning
    "VulnerabilityScanner",
    "ScanResult",
    "Vulnerability",
    "Severity",
    # Allowlist
    "PackageAllowlistManager",
    "AllowlistEntry",
    "ApprovalStatus",
    # Alerts
    "AlertManager",
    "Alert",
    "AlertSeverity",
    "AlertChannel",
]
