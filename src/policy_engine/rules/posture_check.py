"""
Posture Check Rule

Calculates an overall device posture score and makes
access decisions based on the score and risk tolerance.

This implements a more nuanced zero-trust approach than
simple pass/fail rules - devices can have degraded access
based on their overall security posture.
"""

from typing import List, Tuple
from ..models import AccessRequest, DevicePosture


class PostureCheckRule:
    """
    Calculates device posture score and evaluates against thresholds.
    
    Posture scoring allows for:
    - Graduated access based on device health
    - Risk-based decision making
    - Continuous trust evaluation
    
    Score Components:
    - Encryption: 20 points
    - MDM Enrollment: 20 points
    - EDR Installed: 20 points
    - Patch Compliance: 15 points
    - Firewall: 10 points
    - Security Features: 15 points (SIP, Gatekeeper, etc.)
    
    Maximum Score: 100
    """
    
    name = "posture_check"
    description = "Evaluates overall device security posture"
    
    # Score thresholds
    MINIMUM_SCORE = 60  # Below this, deny access
    WARNING_SCORE = 75  # Below this, log warning
    
    # Sensitivity multipliers
    SENSITIVITY_MULTIPLIERS = {
        "low": 0.8,     # Lower bar for low-sensitivity apps
        "medium": 1.0,  # Standard threshold
        "high": 1.1,    # Higher bar for sensitive apps
        "critical": 1.2 # Highest bar for critical apps
    }
    
    def evaluate(self, request: AccessRequest) -> Tuple[bool, str, List[str]]:
        """
        Evaluate device posture score.
        
        Returns:
            Tuple of (passed, reason, remediation_steps)
        """
        device = request.device
        app = request.application
        
        # Calculate posture score
        score, score_breakdown = self._calculate_score(device)
        
        # Adjust threshold based on app sensitivity
        multiplier = self.SENSITIVITY_MULTIPLIERS.get(app.sensitivity, 1.0)
        adjusted_minimum = self.MINIMUM_SCORE * multiplier
        
        # Store score on device for other rules to use
        device.posture_score = score
        
        # Evaluate against threshold
        if score < adjusted_minimum:
            return False, (
                f"Posture score {score:.0f} below minimum {adjusted_minimum:.0f} "
                f"for {app.sensitivity}-sensitivity application"
            ), self._get_remediation(score_breakdown)
        
        if score < self.WARNING_SCORE:
            return True, (
                f"Posture score {score:.0f} (warning: below {self.WARNING_SCORE})"
            ), []
        
        return True, f"Posture score {score:.0f} meets requirements", []
    
    def _calculate_score(self, device: DevicePosture) -> Tuple[float, dict]:
        """
        Calculate posture score from device attributes.
        
        Returns:
            Tuple of (total_score, breakdown_dict)
        """
        breakdown = {}
        
        # Encryption (20 points)
        if device.disk_encrypted:
            breakdown["encryption"] = {"score": 20, "status": "encrypted"}
        else:
            breakdown["encryption"] = {"score": 0, "status": "not encrypted"}
        
        # MDM Enrollment (20 points)
        if device.mdm_enrolled:
            breakdown["mdm"] = {"score": 20, "status": "enrolled"}
        else:
            breakdown["mdm"] = {"score": 0, "status": "not enrolled"}
        
        # EDR (20 points, reduced if threats detected)
        if device.edr_installed:
            if device.active_threats > 0:
                # Major penalty for active threats
                breakdown["edr"] = {"score": 5, "status": f"{device.active_threats} threats"}
            else:
                breakdown["edr"] = {"score": 20, "status": "healthy"}
        else:
            breakdown["edr"] = {"score": 0, "status": "not installed"}
        
        # Patch Compliance (15 points)
        if device.is_within_patch_sla():
            breakdown["patching"] = {"score": 15, "status": "compliant"}
        elif device.last_patch_date is not None:
            breakdown["patching"] = {"score": 5, "status": "overdue"}
        else:
            breakdown["patching"] = {"score": 0, "status": "unknown"}
        
        # Firewall (10 points)
        if device.firewall_enabled:
            breakdown["firewall"] = {"score": 10, "status": "enabled"}
        else:
            breakdown["firewall"] = {"score": 0, "status": "disabled"}
        
        # Security Features (15 points total)
        security_score = 0
        security_status = []
        
        if device.sip_enabled:
            security_score += 7.5
            security_status.append("SIP")
        
        if device.gatekeeper_enabled:
            security_score += 7.5
            security_status.append("Gatekeeper")
        
        breakdown["security_features"] = {
            "score": security_score,
            "status": ", ".join(security_status) if security_status else "none"
        }
        
        # Calculate total
        total = sum(item["score"] for item in breakdown.values())
        
        return total, breakdown
    
    def _get_remediation(self, breakdown: dict) -> List[str]:
        """Generate remediation steps based on score breakdown."""
        remediation = []
        
        for component, data in breakdown.items():
            if data["score"] == 0:
                if component == "encryption":
                    remediation.append("Enable disk encryption (FileVault/BitLocker)")
                elif component == "mdm":
                    remediation.append("Enroll device in company MDM")
                elif component == "edr":
                    remediation.append("Install endpoint protection (CrowdStrike)")
                elif component == "patching":
                    remediation.append("Install pending system updates")
                elif component == "firewall":
                    remediation.append("Enable system firewall")
        
        if not remediation:
            remediation.append("Contact IT to review device configuration")
        
        return remediation
