"""
Device Trust Gateway - Trust Broker

The central service that bridges MDM, EDR, and Identity Provider
to enable real-time device trust decisions.

This implements the "Device Trust Gateway" pattern where:
1. MDM (Kandji) provides device compliance data
2. EDR (CrowdStrike) provides threat status
3. Trust Broker synthesizes this into trust signals
4. IdP (Okta) consumes trust signals for access decisions
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from .providers.kandji_client import KandjiClient
from .providers.okta_client import OktaDeviceClient
from .providers.crowdstrike_client import CrowdStrikeClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    """Device trust levels."""
    TRUSTED = "trusted"
    DEGRADED = "degraded"  # Some issues but usable
    UNTRUSTED = "untrusted"
    QUARANTINED = "quarantined"  # Active threat


@dataclass
class TrustSignal:
    """
    A trust signal to be sent to the identity provider.
    
    This is the output of the trust broker - a synthesized
    view of device health from multiple sources.
    """
    device_id: str
    trust_level: TrustLevel
    
    # Compliance data
    mdm_compliant: bool
    encryption_enabled: bool
    patch_compliant: bool
    
    # Threat data
    edr_healthy: bool
    active_threats: int
    
    # Metadata
    last_check: datetime
    sources: List[str]
    
    # For Okta device trust
    trust_score: float  # 0-100
    
    def to_okta_attributes(self) -> Dict:
        """Convert to Okta device trust attributes."""
        return {
            "device_id": self.device_id,
            "trust_level": self.trust_level.value,
            "trust_score": self.trust_score,
            "mdm_compliant": self.mdm_compliant,
            "encryption_enabled": self.encryption_enabled,
            "patch_compliant": self.patch_compliant,
            "edr_healthy": self.edr_healthy,
            "active_threats": self.active_threats,
            "last_verified": self.last_check.isoformat(),
        }


class TrustBroker:
    """
    The Device Trust Gateway broker.
    
    Collects device state from multiple providers and synthesizes
    into a unified trust signal for the identity provider.
    
    Design Principles:
    - Fail-closed: If we can't verify, we don't trust
    - Multiple sources: Cross-reference data for accuracy
    - Real-time: Support webhook updates for instant changes
    - Audit trail: Log all trust decisions
    
    Example:
        broker = TrustBroker()
        signal = broker.evaluate_device("device-123")
        
        if signal.trust_level == TrustLevel.TRUSTED:
            grant_full_access()
        elif signal.trust_level == TrustLevel.DEGRADED:
            grant_limited_access()
        else:
            deny_access()
    """
    
    def __init__(
        self,
        kandji_client: Optional[KandjiClient] = None,
        okta_client: Optional[OktaDeviceClient] = None,
        crowdstrike_client: Optional[CrowdStrikeClient] = None,
    ):
        """
        Initialize with provider clients.
        
        If not provided, uses mock clients for demonstration.
        """
        self.kandji = kandji_client or KandjiClient()
        self.okta = okta_client or OktaDeviceClient()
        self.crowdstrike = crowdstrike_client or CrowdStrikeClient()
    
    def evaluate_device(self, device_id: str) -> TrustSignal:
        """
        Evaluate trust level for a device.
        
        Collects data from all providers and synthesizes
        into a trust signal.
        """
        logger.info(f"Evaluating trust for device {device_id}")
        sources = []
        
        # Get MDM compliance data
        mdm_data = self.kandji.get_device_compliance(device_id)
        if mdm_data:
            sources.append("kandji")
        
        # Get EDR threat status
        edr_data = self.crowdstrike.get_device_status(device_id)
        if edr_data:
            sources.append("crowdstrike")
        
        # Synthesize trust signal
        signal = self._synthesize_trust(device_id, mdm_data, edr_data, sources)
        
        # Log decision
        logger.info(
            f"Trust decision for {device_id}: {signal.trust_level.value} "
            f"(score: {signal.trust_score})"
        )
        
        return signal
    
    def _synthesize_trust(
        self,
        device_id: str,
        mdm_data: Optional[Dict],
        edr_data: Optional[Dict],
        sources: List[str],
    ) -> TrustSignal:
        """Synthesize trust signal from provider data."""
        
        # Default to untrusted if no data
        if not mdm_data and not edr_data:
            return TrustSignal(
                device_id=device_id,
                trust_level=TrustLevel.UNTRUSTED,
                mdm_compliant=False,
                encryption_enabled=False,
                patch_compliant=False,
                edr_healthy=False,
                active_threats=0,
                last_check=datetime.now(),
                sources=sources,
                trust_score=0.0,
            )
        
        # Extract MDM data
        mdm_compliant = mdm_data.get("compliant", False) if mdm_data else False
        encryption_enabled = mdm_data.get("encryption_enabled", False) if mdm_data else False
        patch_compliant = mdm_data.get("patch_compliant", False) if mdm_data else False
        
        # Extract EDR data
        edr_healthy = edr_data.get("healthy", False) if edr_data else False
        active_threats = edr_data.get("active_threats", 0) if edr_data else 0
        
        # Calculate trust score
        trust_score = self._calculate_trust_score(
            mdm_compliant, encryption_enabled, patch_compliant,
            edr_healthy, active_threats
        )
        
        # Determine trust level
        trust_level = self._determine_trust_level(trust_score, active_threats)
        
        return TrustSignal(
            device_id=device_id,
            trust_level=trust_level,
            mdm_compliant=mdm_compliant,
            encryption_enabled=encryption_enabled,
            patch_compliant=patch_compliant,
            edr_healthy=edr_healthy,
            active_threats=active_threats,
            last_check=datetime.now(),
            sources=sources,
            trust_score=trust_score,
        )
    
    def _calculate_trust_score(
        self,
        mdm_compliant: bool,
        encryption_enabled: bool,
        patch_compliant: bool,
        edr_healthy: bool,
        active_threats: int,
    ) -> float:
        """
        Calculate trust score from 0-100.
        
        Weights:
        - MDM Compliant: 25
        - Encryption: 25
        - Patch Compliant: 20
        - EDR Healthy: 20
        - No Threats: 10
        """
        score = 0.0
        
        if mdm_compliant:
            score += 25
        if encryption_enabled:
            score += 25
        if patch_compliant:
            score += 20
        if edr_healthy:
            score += 20
        if active_threats == 0:
            score += 10
        else:
            # Penalty for threats
            score -= min(active_threats * 20, 50)
        
        return max(0.0, min(100.0, score))
    
    def _determine_trust_level(self, score: float, active_threats: int) -> TrustLevel:
        """Determine trust level from score and threat count."""
        
        # Immediate quarantine for active threats
        if active_threats > 0:
            return TrustLevel.QUARANTINED
        
        if score >= 80:
            return TrustLevel.TRUSTED
        elif score >= 50:
            return TrustLevel.DEGRADED
        else:
            return TrustLevel.UNTRUSTED
    
    def sync_to_okta(self, signal: TrustSignal) -> bool:
        """
        Sync trust signal to Okta device trust.
        
        Updates the device record in Okta with current trust attributes.
        """
        try:
            okta_attrs = signal.to_okta_attributes()
            self.okta.update_device_trust(signal.device_id, okta_attrs)
            logger.info(f"Synced trust signal to Okta for {signal.device_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to sync to Okta: {e}")
            return False
    
    def reconcile_all_devices(self) -> Dict[str, TrustSignal]:
        """
        Reconcile trust for all managed devices.
        
        This would typically run on a schedule to ensure
        trust signals stay current.
        """
        all_devices = self.kandji.list_devices()
        signals = {}
        
        for device in all_devices:
            device_id = device.get("device_id")
            if device_id:
                signals[device_id] = self.evaluate_device(device_id)
        
        return signals


# Demo entry point
if __name__ == "__main__":
    broker = TrustBroker()
    
    # Evaluate a sample device
    signal = broker.evaluate_device("demo-device-001")
    
    print(f"\n{'='*60}")
    print(f"Device: {signal.device_id}")
    print(f"Trust Level: {signal.trust_level.value.upper()}")
    print(f"Trust Score: {signal.trust_score}")
    print(f"\nCompliance:")
    print(f"  MDM Compliant: {signal.mdm_compliant}")
    print(f"  Encryption: {signal.encryption_enabled}")
    print(f"  Patch Compliant: {signal.patch_compliant}")
    print(f"\nSecurity:")
    print(f"  EDR Healthy: {signal.edr_healthy}")
    print(f"  Active Threats: {signal.active_threats}")
    print(f"\nSources: {', '.join(signal.sources)}")
    print(f"{'='*60}\n")
