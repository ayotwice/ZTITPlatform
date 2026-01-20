"""
Zero Trust Policy Evaluator

The central decision point for access control. Evaluates access requests
against a chain of policy rules and returns a decision.

Design Philosophy:
- Default deny: Access is blocked unless explicitly allowed
- Defense in depth: Multiple rules must pass
- Transparent decisions: Every decision includes reasons
- Audit-ready: Full logging for compliance
"""

import logging
from datetime import datetime
from typing import List, Optional

from .models import (
    AccessRequest,
    PolicyEvaluation,
    AccessDecision,
    RiskLevel,
)
from .rules.device_compliance import DeviceComplianceRule
from .rules.patch_sla import PatchSLARule
from .rules.posture_check import PostureCheckRule

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PolicyRule:
    """
    Base class for policy rules.
    
    Each rule evaluates one aspect of the access request
    and contributes to the overall decision.
    """
    
    name: str = "base_rule"
    description: str = "Base policy rule"
    
    def evaluate(self, request: AccessRequest) -> tuple[bool, str, List[str]]:
        """
        Evaluate the rule against an access request.
        
        Returns:
            tuple: (passed, reason, remediation_steps)
        """
        raise NotImplementedError


class PolicyEvaluator:
    """
    The main policy decision point.
    
    Evaluates access requests against a configurable chain of rules
    and returns a decision with full audit trail.
    
    Example:
        evaluator = PolicyEvaluator()
        request = AccessRequest(...)
        result = evaluator.evaluate(request)
        
        if result.decision == AccessDecision.ALLOW:
            grant_access()
        else:
            log_denial(result.reasons)
    """
    
    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        """
        Initialize the evaluator with a list of rules.
        
        If no rules provided, uses the default rule chain.
        """
        self.rules = rules or self._default_rules()
        self.version = "1.0.0"
        
    def _default_rules(self) -> List[PolicyRule]:
        """Return the default policy rule chain."""
        return [
            DeviceComplianceRule(),
            PatchSLARule(),
            PostureCheckRule(),
        ]
    
    def evaluate(self, request: AccessRequest) -> PolicyEvaluation:
        """
        Evaluate an access request against all policy rules.
        
        The evaluation follows these principles:
        1. All rules are evaluated (not short-circuit)
        2. Any failure results in denial
        3. All reasons are collected for transparency
        4. Risk level is determined by the most severe failure
        """
        logger.info(f"Evaluating access request {request.request_id}")
        
        policies_evaluated = []
        failed_policies = []
        all_reasons = []
        all_remediation = []
        
        # Evaluate each rule
        for rule in self.rules:
            rule_name = rule.name
            policies_evaluated.append(rule_name)
            
            try:
                passed, reason, remediation = rule.evaluate(request)
                
                if not passed:
                    failed_policies.append(rule_name)
                    all_reasons.append(f"[{rule_name}] {reason}")
                    all_remediation.extend(remediation)
                    logger.warning(f"Rule {rule_name} failed: {reason}")
                else:
                    logger.info(f"Rule {rule_name} passed")
                    
            except Exception as e:
                # Rule errors are treated as failures (fail-closed)
                failed_policies.append(rule_name)
                all_reasons.append(f"[{rule_name}] Error during evaluation: {str(e)}")
                logger.error(f"Rule {rule_name} error: {e}")
        
        # Determine decision
        if not failed_policies:
            decision = AccessDecision.ALLOW
            risk_level = RiskLevel.LOW
        elif self._should_quarantine(request, failed_policies):
            decision = AccessDecision.QUARANTINE
            risk_level = RiskLevel.HIGH
        elif self._can_step_up(request, failed_policies):
            decision = AccessDecision.STEP_UP
            risk_level = RiskLevel.MEDIUM
        else:
            decision = AccessDecision.DENY
            risk_level = self._calculate_risk_level(failed_policies)
        
        # Build evaluation result
        evaluation = PolicyEvaluation(
            request_id=request.request_id,
            decision=decision,
            risk_level=risk_level,
            policies_evaluated=policies_evaluated,
            failed_policies=failed_policies,
            reasons=all_reasons if all_reasons else ["All policies passed"],
            remediation_steps=all_remediation,
            evaluated_at=datetime.now(),
            evaluator_version=self.version,
        )
        
        # Log the decision for audit
        logger.info(f"Decision for {request.request_id}: {decision.value}")
        self._audit_log(evaluation)
        
        return evaluation
    
    def _should_quarantine(self, request: AccessRequest, failed: List[str]) -> bool:
        """Determine if device should be quarantined for remediation."""
        # Quarantine if device has active threats
        if request.device.has_active_compromise():
            return True
        return False
    
    def _can_step_up(self, request: AccessRequest, failed: List[str]) -> bool:
        """Determine if step-up authentication could resolve the failure."""
        # Step-up only works for certain policy failures
        step_up_eligible = {"mfa_policy", "session_policy"}
        return any(f in step_up_eligible for f in failed)
    
    def _calculate_risk_level(self, failed_policies: List[str]) -> RiskLevel:
        """Calculate risk level based on failed policies."""
        critical_policies = {"device_compliance", "active_threat"}
        high_policies = {"patch_sla", "encryption"}
        
        if any(p in critical_policies for p in failed_policies):
            return RiskLevel.CRITICAL
        elif any(p in high_policies for p in failed_policies):
            return RiskLevel.HIGH
        elif len(failed_policies) > 2:
            return RiskLevel.HIGH
        else:
            return RiskLevel.MEDIUM
    
    def _audit_log(self, evaluation: PolicyEvaluation) -> None:
        """Write evaluation to audit log."""
        # In production, this would write to SIEM or audit database
        audit_entry = evaluation.to_audit_log()
        logger.info(f"AUDIT: {audit_entry}")


# Demo entry point
if __name__ == "__main__":
    from datetime import datetime, timedelta
    from .models import DevicePosture, User, Application, AccessRequest
    
    # Create a sample device
    device = DevicePosture(
        device_id="device-001",
        serial_number="C02XG1FHJGH5",
        platform="macos",
        os_version="14.2.1",
        disk_encrypted=True,
        encryption_type="filevault",
        mdm_enrolled=True,
        mdm_provider="kandji",
        last_patch_date=datetime.now() - timedelta(days=7),
        firewall_enabled=True,
        edr_installed=True,
        edr_provider="crowdstrike",
        active_threats=0,
    )
    
    # Create a sample user
    user = User(
        user_id="user-001",
        email="engineer@company.com",
        department="Engineering",
        role="Software Engineer",
        mfa_enrolled=True,
    )
    
    # Create a sample application
    app = Application(
        app_id="app-001",
        name="GitHub",
        sensitivity="high",
        requires_compliant_device=True,
        requires_mfa=True,
    )
    
    # Create access request
    request = AccessRequest(
        request_id="req-001",
        timestamp=datetime.now(),
        user=user,
        device=device,
        application=app,
        source_ip="192.168.1.100",
        user_agent="Mozilla/5.0",
    )
    
    # Evaluate
    evaluator = PolicyEvaluator()
    result = evaluator.evaluate(request)
    
    print(f"\n{'='*60}")
    print(f"Access Decision: {result.decision.value.upper()}")
    print(f"Risk Level: {result.risk_level.value}")
    print(f"Policies Evaluated: {len(result.policies_evaluated)}")
    print(f"Failed Policies: {result.failed_policies}")
    print(f"\nReasons:")
    for reason in result.reasons:
        print(f"  - {reason}")
    if result.remediation_steps:
        print(f"\nRemediation Steps:")
        for step in result.remediation_steps:
            print(f"  - {step}")
    print(f"{'='*60}\n")
