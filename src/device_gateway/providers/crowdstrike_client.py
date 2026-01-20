"""
CrowdStrike Falcon EDR Client

Mock client for CrowdStrike Falcon API.

In production, this would make actual API calls to CrowdStrike
to retrieve device threat status and EDR health data.

CrowdStrike API Documentation: https://falcon.crowdstrike.com/documentation/
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import random

logger = logging.getLogger(__name__)


class CrowdStrikeClient:
    """
    Client for CrowdStrike Falcon API.
    
    Provides endpoint security data including:
    - Sensor health status
    - Active threat detections
    - Prevention actions
    - Device isolation status
    
    This is critical for zero-trust as it answers:
    "Does this device have an active compromise?"
    
    Example:
        client = CrowdStrikeClient(client_id="...", client_secret="...")
        status = client.get_device_status("device-123")
        
        if status["active_threats"] > 0:
            quarantine_device()
    """
    
    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: str = "https://api.crowdstrike.com",
        mock_mode: bool = True,
    ):
        """
        Initialize CrowdStrike client.
        
        Args:
            client_id: CrowdStrike API client ID
            client_secret: CrowdStrike API client secret
            base_url: API base URL
            mock_mode: If True, return mock data (for demo)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self.mock_mode = mock_mode
        self._access_token = None
        self._token_expiry = None
    
    def get_device_status(self, device_id: str) -> Optional[Dict]:
        """
        Get security status for a device.
        
        Returns:
            Dict with security status or None if device not found
        """
        if self.mock_mode:
            return self._mock_device_status(device_id)
        
        # Production: call /devices/entities/devices/v2
        raise NotImplementedError("Production API not implemented")
    
    def get_detections(self, device_id: str) -> List[Dict]:
        """
        Get active detections for a device.
        
        Returns:
            List of detection records
        """
        if self.mock_mode:
            return self._mock_detections(device_id)
        
        raise NotImplementedError("Production API not implemented")
    
    def is_device_healthy(self, device_id: str) -> bool:
        """Quick check if device is healthy (no active threats)."""
        status = self.get_device_status(device_id)
        return status.get("healthy", False) if status else False
    
    def get_prevention_policy(self, device_id: str) -> Optional[Dict]:
        """Get prevention policy applied to device."""
        if self.mock_mode:
            return {
                "policy_id": "policy-001",
                "policy_name": "Standard Workstation",
                "prevention_enabled": True,
                "detect_on_write": True,
                "quarantine_on_detect": True,
            }
        
        raise NotImplementedError("Production API not implemented")
    
    def _mock_device_status(self, device_id: str) -> Dict:
        """Generate mock device status for demo."""
        
        # Simulate different threat states
        if "compromised" in device_id:
            return {
                "device_id": device_id,
                "healthy": False,
                "sensor_version": "7.10.17106.0",
                "sensor_status": "online",
                "prevention_status": "active",
                "active_threats": 2,
                "threat_severity": "high",
                "last_seen": datetime.now().isoformat(),
                "quarantine_status": "pending",
                "detections": [
                    {
                        "detection_id": "det-001",
                        "severity": "high",
                        "type": "malware",
                        "description": "Suspicious process detected",
                    },
                    {
                        "detection_id": "det-002",
                        "severity": "medium",
                        "type": "suspicious_activity",
                        "description": "Unusual network connection",
                    },
                ],
            }
        elif "healthy" in device_id or random.random() > 0.1:
            return {
                "device_id": device_id,
                "healthy": True,
                "sensor_version": "7.10.17106.0",
                "sensor_status": "online",
                "prevention_status": "active",
                "active_threats": 0,
                "threat_severity": None,
                "last_seen": datetime.now().isoformat(),
                "quarantine_status": None,
                "detections": [],
            }
        else:
            # Rare case: device with issues
            return {
                "device_id": device_id,
                "healthy": False,
                "sensor_version": "7.10.17106.0",
                "sensor_status": "reduced_functionality",
                "prevention_status": "degraded",
                "active_threats": 1,
                "threat_severity": "medium",
                "last_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
                "quarantine_status": None,
                "detections": [
                    {
                        "detection_id": "det-003",
                        "severity": "medium",
                        "type": "pup",
                        "description": "Potentially unwanted program detected",
                    },
                ],
            }
    
    def _mock_detections(self, device_id: str) -> List[Dict]:
        """Generate mock detections for demo."""
        status = self._mock_device_status(device_id)
        return status.get("detections", [])
