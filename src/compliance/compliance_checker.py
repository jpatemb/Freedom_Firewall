"""
Freedom Firewall - Compliance Verification System
Automated Constitutional compliance checking
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ComplianceCheckType(Enum):
    """Types of compliance checks"""
    WARRANT_REQUIRED = "warrant_required"
    RETENTION_EXCEEDED = "retention_exceeded"
    PROBABLE_CAUSE_THRESHOLD = "probable_cause_threshold"
    DATA_DESTRUCTION = "data_destruction"
    AUDIT_TRAIL = "audit_trail"
    JUDICIAL_REVIEW = "judicial_review"


class ComplianceStatus(Enum):
    """Status of compliance check"""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    REVIEW_REQUIRED = "review_required"


class ComplianceViolation:
    """Represents a Constitutional compliance violation"""
    
    def __init__(self, violation_type: str, severity: str, description: str, 
                 remediation: str, authority: str):
        self.violation_type = violation_type
        self.severity = severity  # critical, high, medium, low
        self.description = description
        self.remediation = remediation
        self.authority = authority  # Constitutional basis
        self.timestamp = datetime.utcnow()
        self.resolved = False
    
    def to_dict(self) -> Dict:
        """Convert violation to dictionary"""
        return {
            "type": self.violation_type,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "authority": self.authority,
            "timestamp": self.timestamp.isoformat(),
            "resolved": self.resolved
        }


class ComplianceChecker:
    """
    Automated compliance verification system
    Ensures Freedom Firewall adheres to Constitutional requirements
    """
    
    def __init__(self):
        self.violations = []
        self.check_results = []
        
    def verify_warrant_requirement(self, investigation_id: str, 
                                 investigation_type: str,
                                 has_warrant: bool,
                                 warrant_number: Optional[str] = None) -> Dict:
        """Verify that required warrants are in place"""
        
        warrant_required_actions = [
            "investigate",
            "isolate",
            "content_monitoring",
            "extended_monitoring"
        ]
        
        result = {
            "check_type": ComplianceCheckType.WARRANT_REQUIRED.value,
            "investigation_id": investigation_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": ComplianceStatus.PASS.value
        }
        
        if investigation_type in warrant_required_actions:
            if not has_warrant:
                result["status"] = ComplianceStatus.FAIL.value
                violation = ComplianceViolation(
                    violation_type="missing_warrant",
                    severity="critical",
                    description=f"Investigation {investigation_id} type '{investigation_type}' "
                               f"requires warrant but none found",
                    remediation="Obtain court warrant before proceeding with investigation",
                    authority="Fourth Amendment - Right Against Unreasonable Search and Seizure"
                )
                self.violations.append(violation)
                logger.error(f"[COMPLIANCE] CRITICAL VIOLATION: {violation.description}")
            else:
                result["warrant_number"] = warrant_number
                logger.info(f"[COMPLIANCE] Warrant verified for investigation {investigation_id}")
        
        self.check_results.append(result)
        return result
    
    def verify_retention_policy(self, data_type: str, 
                               collected_date: str,
                               current_date: Optional[str] = None) -> Dict:
        """Verify that data is destroyed according to retention policy"""
        
        retention_limits = {
            "non_threat_metadata": 90,  # days
            "threat_metadata": 180,
            "warrant_authorized_content": 365,
            "investigation_evidence": 730  # 2 years after trial
        }
        
        if current_date is None:
            current_date = datetime.utcnow().isoformat()
        
        result = {
            "check_type": ComplianceCheckType.RETENTION_EXCEEDED.value,
            "data_type": data_type,
            "timestamp": datetime.utcnow().isoformat(),
            "status": ComplianceStatus.PASS.value
        }
        
        if data_type in retention_limits:
            collected = datetime.fromisoformat(collected_date)
            current = datetime.fromisoformat(current_date)
            days_retained = (current - collected).days
            max_retention = retention_limits[data_type]
            
            result["days_retained"] = days_retained
            result["max_retention_days"] = max_retention
            
            if days_retained > max_retention:
                result["status"] = ComplianceStatus.FAIL.value
                violation = ComplianceViolation(
                    violation_type="retention_exceeded",
                    severity="high",
                    description=f"Data of type '{data_type}' retained for {days_retained} days, "
                               f"exceeds limit of {max_retention} days",
                    remediation="Immediately destroy data per retention policy. "
                                "Verify destruction in audit system.",
                    authority="Fifth Amendment - Due Process / Data Protection Principles"
                )
                self.violations.append(violation)
                logger.error(f"[COMPLIANCE] VIOLATION: {violation.description}")
        
        self.check_results.append(result)
        return result
    
    def verify_probable_cause(self, investigation_id: str, 
                            confidence_score: float,
                            required_threshold: float = 0.7) -> Dict:
        """Verify that actions meet probable cause threshold"""
        
        result = {
            "check_type": ComplianceCheckType.PROBABLE_CAUSE_THRESHOLD.value,
            "investigation_id": investigation_id,
            "confidence_score": confidence_score,
            "required_threshold": required_threshold,
            "timestamp": datetime.utcnow().isoformat(),
            "status": ComplianceStatus.PASS.value
        }
        
        if confidence_score < required_threshold:
            result["status"] = ComplianceStatus.FAIL.value
            violation = ComplianceViolation(
                violation_type="insufficient_probable_cause",
                severity="critical",
                description=f"Investigation confidence {confidence_score} below "
                           f"probable cause threshold {required_threshold}",
                remediation="Additional evidence must be gathered. Investigation must be "
                           "escalated to higher confidence before proceeding.",
                authority="Fourth Amendment - Probable Cause Requirement"
            )
            self.violations.append(violation)
            logger.error(f"[COMPLIANCE] VIOLATION: {violation.description}")
        else:
            logger.info(f"[COMPLIANCE] Probable cause verified for investigation {investigation_id}")
        
        self.check_results.append(result)
        return result
    
    def verify_audit_trail(self, action_id: str, audit_entries: List[Dict]) -> Dict:
        """Verify that all actions are properly logged"""
        
        result = {
            "check_type": ComplianceCheckType.AUDIT_TRAIL.value,
            "action_id": action_id,
            "audit_entries_count": len(audit_entries),
            "timestamp": datetime.utcnow().isoformat(),
            "status": ComplianceStatus.PASS.value
        }
        
        if len(audit_entries) == 0:
            result["status"] = ComplianceStatus.FAIL.value
            violation = ComplianceViolation(
                violation_type="missing_audit_trail",
                severity="critical",
                description=f"Action {action_id} has no audit trail entries",
                remediation="All security actions must be logged immediately. "
                           "Investigate and log action retroactively.",
                authority="Administrative and transparency requirements"
            )
            self.violations.append(violation)
            logger.error(f"[COMPLIANCE] VIOLATION: {violation.description}")
        
        # Check for required fields in audit entries
        required_fields = ["timestamp", "action", "user", "result"]
        for entry in audit_entries:
            missing = [f for f in required_fields if f not in entry]
            if missing:
                result["status"] = ComplianceStatus.FAIL.value
                violation = ComplianceViolation(
                    violation_type="incomplete_audit_entry",
                    severity="high",
                    description=f"Audit entry missing required fields: {missing}",
                    remediation="Audit entries must contain all required fields for verification",
                    authority="Transparency and audit requirements"
                )
                self.violations.append(violation)
                logger.warning(f"[COMPLIANCE] VIOLATION: {violation.description}")
        
        self.check_results.append(result)
        return result
    
    def get_compliance_report(self) -> Dict:
        """Generate comprehensive compliance report"""
        
        violations_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for violation in self.violations:
            violations_by_severity[violation.severity].append(violation.to_dict())
        
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_checks": len(self.check_results),
            "checks_passed": len([c for c in self.check_results 
                                 if c["status"] == ComplianceStatus.PASS.value]),
            "checks_failed": len([c for c in self.check_results 
                                 if c["status"] == ComplianceStatus.FAIL.value]),
            "total_violations": len(self.violations),
            "violations_by_severity": violations_by_severity,
            "unresolved_violations": len([v for v in self.violations if not v.resolved]),
            "compliance_status": "PASS" if len(self.violations) == 0 else "FAIL",
            "constitutional_authorities": [
                "First Amendment - Free Speech and Assembly",
                "Fourth Amendment - Unreasonable Search and Seizure",
                "Fifth Amendment - Due Process",
                "Tenth Amendment - Reserved Powers"
            ]
        }
        
        logger.info(f"[COMPLIANCE] Report generated: "
                   f"Checks: {report['total_checks']}, "
                   f"Violations: {report['total_violations']}, "
                   f"Status: {report['compliance_status']}")
        
        return report
    
    def remediate_violation(self, violation: ComplianceViolation) -> bool:
        """Mark violation as remediated"""
        violation.resolved = True
        logger.info(f"[COMPLIANCE] Violation remediated: {violation.violation_type}")
        return True


# Example usage
if __name__ == "__main__":
    checker = ComplianceChecker()
    
    # Verify warrant requirement
    checker.verify_warrant_requirement(
        investigation_id="INV-001",
        investigation_type="investigate",
        has_warrant=True,
        warrant_number="2024-FED-001"
    )
    
    # Verify data retention
    collected_date = (datetime.utcnow() - timedelta(days=100)).isoformat()
    checker.verify_retention_policy(
        data_type="non_threat_metadata",
        collected_date=collected_date
    )
    
    # Verify probable cause
    checker.verify_probable_cause(
        investigation_id="INV-001",
        confidence_score=0.85
    )
    
    # Verify audit trail
    checker.verify_audit_trail(
        action_id="ACT-001",
        audit_entries=[
            {
                "timestamp": datetime.utcnow().isoformat(),
                "action": "investigate",
                "user": "agent@freedom-firewall.gov",
                "result": "success"
            }
        ]
    )
    
    # Generate report
    report = checker.get_compliance_report()
    print(f"Compliance Status: {report['compliance_status']}")
    print(f"Total Violations: {report['total_violations']}")
