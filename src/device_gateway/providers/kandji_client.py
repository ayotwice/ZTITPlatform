"""
Kandji/Iru MDM Client

Mock client for Kandji (now Iru) device management API.

In production, this would make actual API calls to Kandji/Iru
to retrieve device compliance and security data.

Kandji API Documentation: https://api-docs.kandji.io/
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import random

logger = logging.getLogger(__name__)


class KandjiClient:
    """
    Client for Kandji/Iru MDM API.
    
    Provides device compliance data including:
    - MDM enrollment status
    - Disk encryption status
    - Patch compliance
    - Security settings
    - Blueprint compliance
    
    Example:
        client = KandjiClient(api_token="your-token")
        compliance = client.get_device_compliance("device-123")
        
        if compliance["compliant"]:
            print("Device is compliant")
    """
    
    def __init__(
        self,
        api_token: Optional[str] = None,
        base_url: str = "https://company.api.kandji.io/api/v1",
        mock_mode: bool = True,
    ):
        """
        Initialize Kandji client.
        
        Args:
            api_token: Kandji API token
            base_url: Kandji API base URL
            mock_mode: If True, return mock data (for demo)
        """
        self.api_token = api_token
        self.base_url = base_url
        self.mock_mode = mock_mode
        
        if not mock_mode and not api_token:
            raise ValueError("API token required when not in mock mode")
    
    def get_device_compliance(self, device_id: str) -> Optional[Dict]:
        """
        Get compliance status for a specific device.
        
        Returns:
            Dict with compliance data or None if device not found
        """
        if self.mock_mode:
            return self._mock_compliance(device_id)
        
        # Production implementation would call Kandji API
        # endpoint: GET /devices/{device_id}/status
        raise NotImplementedError("Production API not implemented")
    
    def list_devices(self) -> List[Dict]:
        """
        List all devices in Kandji.
        
        Returns:
            List of device records
        """
        if self.mock_mode:
            return self._mock_device_list()
        
        raise NotImplementedError("Production API not implemented")
    
    def get_device_details(self, device_id: str) -> Optional[Dict]:
        """
        Get detailed device information.
        
        Returns:
            Dict with full device record
        """
        if self.mock_mode:
            return self._mock_device_details(device_id)
        
        raise NotImplementedError("Production API not implemented")
    
    def _mock_compliance(self, device_id: str) -> Dict:
        """Generate mock compliance data for demo."""
        
        # IMPORTANT: Check "noncompliant" BEFORE "compliant" to avoid substring match
        if "noncompliant" in device_id:
            # Non-compliant device: encryption off, firewall off, not patched
            return {
                "device_id": device_id,
                "compliant": False,
                "encryption_enabled": False,
                "encryption_type": None,
                "patch_compliant": False,
                "last_patch_date": (datetime.now() - timedelta(days=30)).isoformat(),
                "pending_updates": 5,
                "mdm_enrolled": True,
                "blueprint": "standard-macos",
                "blueprint_compliant": False,
                "firewall_enabled": False,
                "sip_enabled": True,
                "gatekeeper_enabled": True,
                "last_check_in": (datetime.now() - timedelta(hours=48)).isoformat(),
            }
        elif "compliant" in device_id:
            # Fully compliant device
            return {
                "device_id": device_id,
                "compliant": True,
                "encryption_enabled": True,
                "encryption_type": "filevault",
                "patch_compliant": True,
                "last_patch_date": (datetime.now() - timedelta(days=5)).isoformat(),
                "pending_updates": 0,
                "mdm_enrolled": True,
                "blueprint": "standard-macos",
                "blueprint_compliant": True,
                "firewall_enabled": True,
                "sip_enabled": True,
                "gatekeeper_enabled": True,
                "last_check_in": datetime.now().isoformat(),
            }
        else:
            # Random realistic data for demo
            compliant = random.random() > 0.3
            days_since_patch = random.randint(1, 20)
            
            return {
                "device_id": device_id,
                "compliant": compliant,
                "encryption_enabled": random.random() > 0.1,
                "encryption_type": "filevault",
                "patch_compliant": days_since_patch <= 14,
                "last_patch_date": (datetime.now() - timedelta(days=days_since_patch)).isoformat(),
                "pending_updates": random.randint(0, 3),
                "mdm_enrolled": True,
                "blueprint": "standard-macos",
                "blueprint_compliant": compliant,
                "firewall_enabled": random.random() > 0.2,
                "sip_enabled": True,
                "gatekeeper_enabled": True,
                "last_check_in": datetime.now().isoformat(),
            }
    
    def _mock_device_list(self) -> List[Dict]:
        """Generate mock device list for demo."""
        return [
            {"device_id": "device-001", "serial": "C02XG1FHJGH5", "user": "alice@company.com"},
            {"device_id": "device-002", "serial": "C02YK1ABCDE", "user": "bob@company.com"},
            {"device_id": "device-003", "serial": "C02ZL2FGHIJ", "user": "charlie@company.com"},
            {"device_id": "compliant-device", "serial": "C02AM3KLMNO", "user": "diane@company.com"},
            {"device_id": "noncompliant-device", "serial": "C02BN4PQRST", "user": "eve@company.com"},
        ]
    
    def _mock_device_details(self, device_id: str) -> Dict:
        """Generate mock device details for demo."""
        compliance = self._mock_compliance(device_id)
        
        return {
            **compliance,
            "serial_number": f"C02{device_id.upper()[:8]}",
            "model": "MacBook Pro (14-inch, 2023)",
            "os_version": "14.2.1",
            "processor": "Apple M3 Pro",
            "memory": "18 GB",
            "storage": "512 GB",
            "user_email": f"user-{device_id}@company.com",
            "department": "Engineering",
            "enrolled_date": (datetime.now() - timedelta(days=180)).isoformat(),
        }
