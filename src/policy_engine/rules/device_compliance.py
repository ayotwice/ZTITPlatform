"""
Device Compliance Rule

Checks that the device meets baseline security requirements:
- Disk encryption enabled
- MDM enrolled
- Firewall enabled
- EDR installed
- No active threats

This is typically the first rule evaluated as it ensures
the device is managed and has basic protections.
"""

from typing import List, Tuple
from ..models import AccessRequest


class DeviceComplianceRule:
    """
    Validates device meets baseline compliance requirements.
    
    John's Example (from video):
    "Applications can only be accessed from company machines
    where we know that they don't have an active compromise"
    
    This rule enforces:
    1. Device is enrolled in MDM (managed device)
    2. Disk encryption is enabled (data protection)
    3. Firewall is active (network protection)  
    4. EDR is installed (threat detection)
    5. No active threats detected (not compromised)
    """
    
    name = "device_compliance"
    description = "Validates device meets baseline security requirements"
    
    def evaluate(self, request: AccessRequest) -> Tuple[bool, str, List[str]]:
        """
        Evaluate device compliance.
        
        Returns:
            Tuple of (passed, reason, remediation_steps)
        """
        device = request.device
        app = request.application
        
        # Skip compliance check for apps that don't require it
        if not app.requires_compliant_device:
            return True, "Compliance not required for this application", []
        
        failures = []
        remediation = []
        
        # Check MDM enrollment
        if not device.mdm_enrolled:
            failures.append("Device is not enrolled in MDM")
            remediation.append(
                "Enroll device in company MDM (Kandji/Iru) via Self Service"
            )
        
        # Check disk encryption
        if not device.disk_encrypted:
            failures.append("Disk encryption is not enabled")
            if device.platform == "macos":
                remediation.append(
                    "Enable FileVault: System Settings > Privacy & Security > FileVault"
                )
            elif device.platform == "windows":
                remediation.append("Enable BitLocker via Group Policy or Settings")
        
        # Check firewall
        if not device.firewall_enabled:
            failures.append("Firewall is not enabled")
            if device.platform == "macos":
                remediation.append(
                    "Enable Firewall: System Settings > Network > Firewall"
                )
        
        # Check EDR
        if not device.edr_installed:
            failures.append("EDR software is not installed")
            remediation.append(
                "Install CrowdStrike Falcon via Self Service or IT portal"
            )
        
        # Check for active threats (CRITICAL)
        if device.has_active_compromise():
            failures.append(
                f"CRITICAL: Device has {device.active_threats} active threat(s)"
            )
            remediation.append("Contact IT Security immediately for incident response")
            remediation.append("Disconnect from network until cleared")
        
        # Return result
        if failures:
            reason = "; ".join(failures)
            return False, reason, remediation
        
        return True, "Device meets all baseline compliance requirements", []


class ManagedDeviceRule:
    """
    Stricter rule requiring device to be company-managed.
    
    Some applications require not just compliance, but that
    the device is a company-issued, fully managed device.
    """
    
    name = "managed_device"
    description = "Requires device to be company-managed"
    
    APPROVED_MDM_PROVIDERS = {"kandji", "jamf", "intune", "iru"}
    
    def evaluate(self, request: AccessRequest) -> Tuple[bool, str, List[str]]:
        """Evaluate if device is company-managed."""
        device = request.device
        app = request.application
        
        if not app.requires_managed_device:
            return True, "Managed device not required for this application", []
        
        # Check MDM enrollment with approved provider
        if not device.mdm_enrolled:
            return False, "Device must be company-managed", [
                "This application requires a company-issued device",
                "Contact IT to request a managed device"
            ]
        
        if device.mdm_provider and device.mdm_provider.lower() not in self.APPROVED_MDM_PROVIDERS:
            return False, f"MDM provider '{device.mdm_provider}' is not approved", [
                f"Approved providers: {', '.join(self.APPROVED_MDM_PROVIDERS)}"
            ]
        
        return True, "Device is properly managed", []
