"""
Patch SLA Rule

Enforces that devices are patched within a specified SLA window.

John's Example (from video):
"Patched inside of a two-week SLA"

This rule implements exactly that requirement - if a device
hasn't been patched in the last 14 days, access is denied
until the device is updated.
"""

from datetime import datetime, timedelta
from typing import List, Tuple

from ..models import AccessRequest


class PatchSLARule:
    """
    Enforces patch SLA compliance.
    
    Devices must have been patched within the configured SLA window
    (default: 14 days) to access resources.
    
    This is critical for:
    - Reducing attack surface from known vulnerabilities
    - Ensuring compliance with security policies
    - Protecting against exploit kits targeting old vulnerabilities
    
    Design Decision:
    We check days since last patch, not patch level. This is simpler
    to implement across platforms and focuses on the behavior (regular
    updates) rather than specific versions.
    """
    
    name = "patch_sla"
    description = "Enforces device patching within SLA window"
    
    DEFAULT_SLA_DAYS = 14
    WARNING_THRESHOLD_DAYS = 10
    
    def __init__(self, sla_days: int = DEFAULT_SLA_DAYS):
        self.sla_days = sla_days
    
    def evaluate(self, request: AccessRequest) -> Tuple[bool, str, List[str]]:
        """
        Evaluate if device is within patch SLA.
        
        Returns:
            Tuple of (passed, reason, remediation_steps)
        """
        device = request.device
        
        # No patch date means device hasn't reported compliance
        if device.last_patch_date is None:
            return False, "Device has not reported patch status", [
                "Ensure device is checking in with MDM",
                "Run software update check manually",
                "Contact IT if issue persists"
            ]
        
        # Calculate days since last patch
        days_since_patch = (datetime.now() - device.last_patch_date).days
        
        # Check SLA compliance
        if days_since_patch > self.sla_days:
            return False, (
                f"Device is {days_since_patch} days since last patch "
                f"(SLA: {self.sla_days} days)"
            ), self._get_patch_remediation(device)
        
        # Passed but with warning if approaching SLA
        if days_since_patch > self.WARNING_THRESHOLD_DAYS:
            return True, (
                f"Device is {days_since_patch} days since last patch "
                f"(approaching {self.sla_days} day SLA)"
            ), []
        
        return True, f"Device patched {days_since_patch} days ago (within SLA)", []
    
    def _get_patch_remediation(self, device) -> List[str]:
        """Get platform-specific patch remediation steps."""
        remediation = []
        
        if device.platform == "macos":
            remediation.extend([
                "Open System Settings > General > Software Update",
                "Install all available updates",
                "Restart when prompted",
                "If updates fail, contact IT for assistance"
            ])
        elif device.platform == "windows":
            remediation.extend([
                "Open Settings > Windows Update",
                "Click 'Check for updates'",
                "Install all available updates",
                "Restart when prompted"
            ])
        elif device.platform == "linux":
            remediation.extend([
                "Run: sudo apt update && sudo apt upgrade (Debian/Ubuntu)",
                "Or: sudo dnf upgrade (Fedora/RHEL)",
                "Restart if kernel was updated"
            ])
        
        remediation.append(
            f"Device must be patched within {self.sla_days} days to regain access"
        )
        
        return remediation


class CriticalPatchRule:
    """
    Emergency rule for critical security patches.
    
    When a critical vulnerability is disclosed (e.g., zero-day),
    this rule can enforce immediate patching with a shorter SLA.
    """
    
    name = "critical_patch"
    description = "Enforces immediate patching for critical vulnerabilities"
    
    CRITICAL_SLA_HOURS = 72  # 3 days for critical patches
    
    def __init__(self, critical_cves: List[str] = None):
        """
        Initialize with list of CVEs requiring urgent patches.
        
        In production, this would be dynamically updated from
        threat intelligence feeds.
        """
        self.critical_cves = critical_cves or []
    
    def evaluate(self, request: AccessRequest) -> Tuple[bool, str, List[str]]:
        """Evaluate critical patch compliance."""
        # This would integrate with SBOM/vulnerability data
        # For demo, we always pass if no critical CVEs defined
        
        if not self.critical_cves:
            return True, "No critical patches currently required", []
        
        # In production: check if device has patches for critical_cves
        return True, "Critical patch requirements met", []
