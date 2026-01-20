"""
Alerting System for Supply Chain Security

Sends alerts for:
- Critical vulnerability discoveries
- Blocked package detections
- Allowlist violations
- Supply chain attack indicators

Channels:
- Slack (primary)
- Email (for critical alerts)
- Webhook (for integration with other systems)
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertChannel(Enum):
    """Alert delivery channels."""
    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"


@dataclass
class Alert:
    """
    Represents a security alert.
    """
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    
    # Context
    source: str  # Component that generated the alert
    affected_devices: List[str]
    
    # Alert metadata
    created_at: datetime
    
    # Action items
    remediation_steps: List[str]
    
    # References
    cve_ids: List[str] = None
    reference_urls: List[str] = None
    
    def to_slack_message(self) -> Dict:
        """Format alert for Slack."""
        severity_emoji = {
            AlertSeverity.CRITICAL: "🚨",
            AlertSeverity.HIGH: "⚠️",
            AlertSeverity.MEDIUM: "📢",
            AlertSeverity.LOW: "ℹ️",
            AlertSeverity.INFO: "📋",
        }
        
        emoji = severity_emoji.get(self.severity, "📋")
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {self.title}",
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": self.description,
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:* {self.severity.value.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Affected Devices:* {len(self.affected_devices)}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:* {self.source}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:* {self.created_at.strftime('%Y-%m-%d %H:%M UTC')}",
                    },
                ]
            },
        ]
        
        if self.remediation_steps:
            steps_text = "\n".join(f"• {step}" for step in self.remediation_steps)
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Remediation Steps:*\n{steps_text}",
                }
            })
        
        if self.cve_ids:
            cve_text = ", ".join(self.cve_ids)
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"CVEs: {cve_text}",
                    }
                ]
            })
        
        return {"blocks": blocks}


class AlertManager:
    """
    Manages security alerts and notifications.
    
    Features:
    - Multi-channel delivery (Slack, email, webhook)
    - Alert deduplication
    - Severity-based routing
    - Alert history and analytics
    
    Example:
        alerts = AlertManager()
        
        alert = alerts.create_vulnerability_alert(
            cve_id="CVE-2024-SHAI",
            affected_devices=["device-001", "device-002"],
        )
        
        alerts.send(alert)
    """
    
    def __init__(
        self,
        slack_webhook_url: Optional[str] = None,
        email_config: Optional[Dict] = None,
    ):
        """
        Initialize alert manager.
        
        Args:
            slack_webhook_url: Slack webhook for notifications
            email_config: Email SMTP configuration
        """
        self.slack_webhook = slack_webhook_url
        self.email_config = email_config
        
        self._alert_history: List[Alert] = []
        self._alert_counter = 0
    
    def create_vulnerability_alert(
        self,
        cve_id: str,
        affected_devices: List[str],
        severity: AlertSeverity = AlertSeverity.HIGH,
        description: Optional[str] = None,
    ) -> Alert:
        """
        Create an alert for a vulnerability detection.
        """
        self._alert_counter += 1
        
        return Alert(
            alert_id=f"VULN-{self._alert_counter:05d}",
            title=f"Vulnerability Detected: {cve_id}",
            description=description or f"CVE {cve_id} detected on {len(affected_devices)} device(s)",
            severity=severity,
            source="vulnerability_scanner",
            affected_devices=affected_devices,
            created_at=datetime.now(),
            remediation_steps=[
                "Identify affected packages",
                "Apply available patches",
                "If no patch available, consider compensating controls",
                "Verify remediation across all affected devices",
            ],
            cve_ids=[cve_id],
        )
    
    def create_supply_chain_alert(
        self,
        package_name: str,
        affected_devices: List[str],
        attack_type: str = "malicious_package",
    ) -> Alert:
        """
        Create an alert for a supply chain attack indicator.
        
        This is triggered when Shai-Hulud-like attacks are detected.
        """
        self._alert_counter += 1
        
        return Alert(
            alert_id=f"SUPPLY-{self._alert_counter:05d}",
            title=f"🚨 Supply Chain Attack Detected: {package_name}",
            description=(
                f"A potentially malicious package '{package_name}' has been detected "
                f"on {len(affected_devices)} device(s). This may indicate a supply chain "
                f"attack similar to Shai-Hulud. Immediate action required."
            ),
            severity=AlertSeverity.CRITICAL,
            source="supply_chain_monitor",
            affected_devices=affected_devices,
            created_at=datetime.now(),
            remediation_steps=[
                "ISOLATE affected devices from network immediately",
                "Do NOT power off devices (preserve forensic evidence)",
                "Contact security team for incident response",
                "Begin containment procedures",
                "Prepare for potential data breach notification",
            ],
        )
    
    def create_allowlist_violation_alert(
        self,
        device_id: str,
        package_name: str,
        violation_type: str,
    ) -> Alert:
        """
        Create an alert for an allowlist violation.
        """
        self._alert_counter += 1
        
        severity = (
            AlertSeverity.CRITICAL if violation_type == "blocked"
            else AlertSeverity.MEDIUM
        )
        
        return Alert(
            alert_id=f"ALLOW-{self._alert_counter:05d}",
            title=f"Allowlist Violation: {package_name}",
            description=(
                f"Device {device_id} has {violation_type} package '{package_name}' "
                f"installed which is not on the approved software list."
            ),
            severity=severity,
            source="allowlist_manager",
            affected_devices=[device_id],
            created_at=datetime.now(),
            remediation_steps=[
                "Review package legitimacy",
                "If legitimate, submit for allowlist approval",
                "If unauthorized, remove package and investigate",
            ],
        )
    
    def send(self, alert: Alert, channels: List[AlertChannel] = None) -> bool:
        """
        Send an alert through configured channels.
        
        Args:
            alert: Alert to send
            channels: Specific channels (default: auto-route by severity)
        """
        if channels is None:
            channels = self._route_by_severity(alert.severity)
        
        self._alert_history.append(alert)
        
        success = True
        for channel in channels:
            try:
                if channel == AlertChannel.SLACK:
                    self._send_slack(alert)
                elif channel == AlertChannel.EMAIL:
                    self._send_email(alert)
                elif channel == AlertChannel.WEBHOOK:
                    self._send_webhook(alert)
                
                logger.info(f"Alert {alert.alert_id} sent via {channel.value}")
            except Exception as e:
                logger.error(f"Failed to send alert via {channel.value}: {e}")
                success = False
        
        return success
    
    def _route_by_severity(self, severity: AlertSeverity) -> List[AlertChannel]:
        """Determine channels based on severity."""
        if severity == AlertSeverity.CRITICAL:
            return [AlertChannel.SLACK, AlertChannel.EMAIL, AlertChannel.PAGERDUTY]
        elif severity == AlertSeverity.HIGH:
            return [AlertChannel.SLACK, AlertChannel.EMAIL]
        else:
            return [AlertChannel.SLACK]
    
    def _send_slack(self, alert: Alert) -> None:
        """Send alert to Slack."""
        message = alert.to_slack_message()
        
        # In production, would POST to Slack webhook
        logger.info(f"[MOCK] Slack alert: {alert.title}")
        
        if self.slack_webhook:
            # Would use: requests.post(self.slack_webhook, json=message)
            pass
    
    def _send_email(self, alert: Alert) -> None:
        """Send alert via email."""
        logger.info(f"[MOCK] Email alert: {alert.title}")
        
        # In production, would use SMTP or email service
    
    def _send_webhook(self, alert: Alert) -> None:
        """Send alert to webhook endpoint."""
        payload = {
            "alert_id": alert.alert_id,
            "title": alert.title,
            "severity": alert.severity.value,
            "affected_devices": alert.affected_devices,
            "timestamp": alert.created_at.isoformat(),
        }
        logger.info(f"[MOCK] Webhook alert: {json.dumps(payload)}")
    
    def get_alert_summary(self) -> Dict:
        """Get summary of recent alerts."""
        by_severity = {s: 0 for s in AlertSeverity}
        for alert in self._alert_history:
            by_severity[alert.severity] += 1
        
        return {
            "total_alerts": len(self._alert_history),
            "by_severity": {s.value: c for s, c in by_severity.items()},
            "recent": [
                {
                    "id": a.alert_id,
                    "title": a.title,
                    "severity": a.severity.value,
                    "time": a.created_at.isoformat(),
                }
                for a in self._alert_history[-10:]
            ],
        }


# Demo entry point
if __name__ == "__main__":
    alerts = AlertManager()
    
    print(f"\n{'='*60}")
    print("Alert Manager Demo")
    print(f"{'='*60}")
    
    # Create and send different alert types
    vuln_alert = alerts.create_vulnerability_alert(
        cve_id="CVE-2023-44487",
        affected_devices=["device-001", "device-002"],
    )
    alerts.send(vuln_alert)
    print(f"\nSent: {vuln_alert.title}")
    
    supply_alert = alerts.create_supply_chain_alert(
        package_name="compromised-package",
        affected_devices=["device-003"],
    )
    alerts.send(supply_alert)
    print(f"Sent: {supply_alert.title}")
    
    # Get summary
    summary = alerts.get_alert_summary()
    print(f"\nAlert Summary:")
    print(f"  Total: {summary['total_alerts']}")
    print(f"  By Severity: {summary['by_severity']}")
    
    print(f"{'='*60}\n")
