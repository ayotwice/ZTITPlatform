"""
Test suite for the Policy Engine.
"""

import pytest
from datetime import datetime, timedelta

from src.policy_engine.models import (
    DevicePosture,
    User,
    Application,
    AccessRequest,
    AccessDecision,
)
from src.policy_engine.evaluator import PolicyEvaluator


class TestPolicyEvaluator:
    """Tests for the PolicyEvaluator class."""
    
    def create_compliant_device(self) -> DevicePosture:
        """Create a fully compliant device for testing."""
        return DevicePosture(
            device_id="test-device-001",
            serial_number="TEST123",
            platform="macos",
            os_version="14.2.1",
            disk_encrypted=True,
            encryption_type="filevault",
            mdm_enrolled=True,
            mdm_provider="kandji",
            last_patch_date=datetime.now() - timedelta(days=5),
            firewall_enabled=True,
            sip_enabled=True,
            gatekeeper_enabled=True,
            edr_installed=True,
            edr_provider="crowdstrike",
            active_threats=0,
        )
    
    def create_noncompliant_device(self) -> DevicePosture:
        """Create a non-compliant device for testing."""
        return DevicePosture(
            device_id="test-device-002",
            serial_number="TEST456",
            platform="macos",
            os_version="13.0.0",
            disk_encrypted=False,
            mdm_enrolled=False,
            last_patch_date=datetime.now() - timedelta(days=30),
            firewall_enabled=False,
            edr_installed=False,
            active_threats=0,
        )
    
    def create_compromised_device(self) -> DevicePosture:
        """Create a device with active threats."""
        device = self.create_compliant_device()
        device.device_id = "test-device-003"
        device.active_threats = 2
        return device
    
    def create_user(self) -> User:
        """Create a test user."""
        return User(
            user_id="test-user-001",
            email="testuser@company.com",
            department="Engineering",
            role="Engineer",
            mfa_enrolled=True,
        )
    
    def create_application(self, sensitivity: str = "medium") -> Application:
        """Create a test application."""
        return Application(
            app_id="test-app-001",
            name="Test Application",
            sensitivity=sensitivity,
            requires_compliant_device=True,
            requires_mfa=True,
        )
    
    def create_request(
        self,
        device: DevicePosture = None,
        user: User = None,
        application: Application = None,
    ) -> AccessRequest:
        """Create a test access request."""
        return AccessRequest(
            request_id="test-request-001",
            timestamp=datetime.now(),
            user=user or self.create_user(),
            device=device or self.create_compliant_device(),
            application=application or self.create_application(),
            source_ip="192.168.1.100",
            user_agent="Mozilla/5.0 Test",
        )
    
    def test_compliant_device_allowed(self):
        """Test that a fully compliant device is allowed access."""
        evaluator = PolicyEvaluator()
        request = self.create_request()
        
        result = evaluator.evaluate(request)
        
        assert result.decision == AccessDecision.ALLOW
    
    def test_noncompliant_device_denied(self):
        """Test that a non-compliant device is denied access."""
        evaluator = PolicyEvaluator()
        device = self.create_noncompliant_device()
        request = self.create_request(device=device)
        
        result = evaluator.evaluate(request)
        
        assert result.decision == AccessDecision.DENY
        assert len(result.failed_policies) > 0
    
    def test_compromised_device_quarantined(self):
        """Test that a compromised device is quarantined."""
        evaluator = PolicyEvaluator()
        device = self.create_compromised_device()
        request = self.create_request(device=device)
        
        result = evaluator.evaluate(request)
        
        assert result.decision == AccessDecision.QUARANTINE
    
    def test_patch_sla_enforcement(self):
        """Test that devices outside patch SLA are denied."""
        evaluator = PolicyEvaluator()
        device = self.create_compliant_device()
        device.last_patch_date = datetime.now() - timedelta(days=20)
        request = self.create_request(device=device)
        
        result = evaluator.evaluate(request)
        
        assert result.decision == AccessDecision.DENY
        assert "patch_sla" in result.failed_policies
    
    def test_audit_logging(self):
        """Test that evaluations generate audit logs."""
        evaluator = PolicyEvaluator()
        request = self.create_request()
        
        result = evaluator.evaluate(request)
        audit_log = result.to_audit_log()
        
        assert "request_id" in audit_log
        assert "decision" in audit_log
        assert "evaluated_at" in audit_log


class TestDevicePosture:
    """Tests for DevicePosture model."""
    
    def test_is_within_patch_sla(self):
        """Test patch SLA calculation."""
        device = DevicePosture(
            device_id="test",
            serial_number="TEST",
            platform="macos",
            os_version="14.0",
            last_patch_date=datetime.now() - timedelta(days=10),
        )
        
        assert device.is_within_patch_sla() is True
        
        device.last_patch_date = datetime.now() - timedelta(days=20)
        assert device.is_within_patch_sla() is False
    
    def test_has_active_compromise(self):
        """Test active compromise detection."""
        device = DevicePosture(
            device_id="test",
            serial_number="TEST",
            platform="macos",
            os_version="14.0",
            active_threats=0,
        )
        
        assert device.has_active_compromise() is False
        
        device.active_threats = 1
        assert device.has_active_compromise() is True
    
    def test_meets_baseline(self):
        """Test baseline compliance check."""
        device = DevicePosture(
            device_id="test",
            serial_number="TEST",
            platform="macos",
            os_version="14.0",
            disk_encrypted=True,
            mdm_enrolled=True,
            firewall_enabled=True,
            edr_installed=True,
            active_threats=0,
        )
        
        assert device.meets_baseline() is True
        
        device.disk_encrypted = False
        assert device.meets_baseline() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
