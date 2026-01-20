"""
Data models for the Zero Trust Policy Engine.

These models represent the core entities used in access decisions:
- Devices and their compliance state
- Users and their attributes
- Access requests and policy evaluations
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ComplianceStatus(Enum):
    """Device compliance status levels."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    PENDING = "pending"


class RiskLevel(Enum):
    """Risk levels for access decisions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AccessDecision(Enum):
    """Access decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"  # Require additional authentication
    QUARANTINE = "quarantine"  # Limited access for remediation


@dataclass
class DevicePosture:
    """
    Represents the security posture of a device.
    
    This is the core data structure for zero-trust decisions.
    All fields contribute to the overall trust score.
    """
    device_id: str
    serial_number: str
    platform: str  # "macos", "windows", "linux"
    os_version: str
    
    # Encryption status
    disk_encrypted: bool = False
    encryption_type: Optional[str] = None  # "filevault", "bitlocker"
    
    # MDM enrollment
    mdm_enrolled: bool = False
    mdm_provider: Optional[str] = None  # "kandji", "jamf", "intune"
    
    # Patch compliance
    last_patch_date: Optional[datetime] = None
    patch_sla_days: int = 14  # Maximum allowed days since last patch
    pending_updates: int = 0
    
    # Security controls
    firewall_enabled: bool = False
    sip_enabled: bool = True  # System Integrity Protection (macOS)
    gatekeeper_enabled: bool = True  # macOS app verification
    
    # EDR status
    edr_installed: bool = False
    edr_provider: Optional[str] = None  # "crowdstrike", "sentinelone"
    active_threats: int = 0
    last_scan_date: Optional[datetime] = None
    
    # Calculated fields
    posture_score: float = 0.0
    compliance_status: ComplianceStatus = ComplianceStatus.UNKNOWN
    last_check: datetime = field(default_factory=datetime.now)
    
    def is_within_patch_sla(self) -> bool:
        """Check if device is within the patch SLA window."""
        if self.last_patch_date is None:
            return False
        days_since_patch = (datetime.now() - self.last_patch_date).days
        return days_since_patch <= self.patch_sla_days
    
    def has_active_compromise(self) -> bool:
        """Check if device shows signs of active compromise."""
        return self.active_threats > 0
    
    def meets_baseline(self) -> bool:
        """Check if device meets minimum security baseline."""
        return all([
            self.disk_encrypted,
            self.mdm_enrolled,
            self.firewall_enabled,
            self.edr_installed,
            not self.has_active_compromise(),
        ])


@dataclass
class User:
    """Represents a user requesting access."""
    user_id: str
    email: str
    department: str
    role: str
    
    # Risk factors
    is_privileged: bool = False
    mfa_enrolled: bool = False
    last_login: Optional[datetime] = None
    failed_logins_24h: int = 0
    
    # Location context
    country: Optional[str] = None
    is_known_location: bool = True


@dataclass
class Application:
    """Represents an application being accessed."""
    app_id: str
    name: str
    sensitivity: str  # "low", "medium", "high", "critical"
    
    # Access requirements
    requires_compliant_device: bool = True
    requires_mfa: bool = True
    requires_managed_device: bool = False
    allowed_platforms: list = field(default_factory=lambda: ["macos", "windows"])
    
    # Data classification
    contains_pii: bool = False
    contains_financial: bool = False


@dataclass
class AccessRequest:
    """
    Represents an access request to be evaluated.
    
    This is the input to the policy evaluator.
    """
    request_id: str
    timestamp: datetime
    user: User
    device: DevicePosture
    application: Application
    
    # Context
    source_ip: str
    user_agent: str
    session_id: Optional[str] = None


@dataclass
class PolicyEvaluation:
    """
    Result of evaluating an access request against policies.
    
    This is the output of the policy evaluator.
    """
    request_id: str
    decision: AccessDecision
    risk_level: RiskLevel
    
    # Evaluation details
    policies_evaluated: list = field(default_factory=list)
    failed_policies: list = field(default_factory=list)
    
    # Reasons for decision
    reasons: list = field(default_factory=list)
    
    # Recommendations for remediation
    remediation_steps: list = field(default_factory=list)
    
    # Audit trail
    evaluated_at: datetime = field(default_factory=datetime.now)
    evaluator_version: str = "1.0.0"
    
    def to_audit_log(self) -> dict:
        """Generate an audit log entry for this evaluation."""
        return {
            "request_id": self.request_id,
            "decision": self.decision.value,
            "risk_level": self.risk_level.value,
            "policies_evaluated": self.policies_evaluated,
            "failed_policies": self.failed_policies,
            "reasons": self.reasons,
            "evaluated_at": self.evaluated_at.isoformat(),
        }
