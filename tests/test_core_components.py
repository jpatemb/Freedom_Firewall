"""
Freedom Firewall - Unit Tests for Core Components
Testing framework ensuring security and compliance
"""

import unittest
from datetime import datetime, timedelta
from src.core_engine.security_engine import (
    ThreatDetectionEngine, SecurityAction, ThreatLevel,
    ConstitutionalComplianceFramework
)
from src.threat_detection.detection_engine import (
    NetworkAnomalyDetector, MalwareSignatureDetector, NetworkFlow
)
from src.compliance.compliance_checker import (
    ComplianceChecker, ComplianceViolation
)


class TestConstitutionalCompliance(unittest.TestCase):
    """Test Constitutional compliance framework"""
    
    def setUp(self):
        self.compliance = ConstitutionalComplianceFramework()
    
    def test_warrant_required_for_investigation(self):
        """Verify warrant is required for investigation actions"""
        # Investigation without warrant should be denied
        is_authorized = self.compliance.is_action_authorized(
            action=SecurityAction.INVESTIGATE,
            threat_confidence=0.8,
            has_warrant=False
        )
        self.assertFalse(is_authorized)
        
        # Investigation with warrant should be authorized
        is_authorized = self.compliance.is_action_authorized(
            action=SecurityAction.INVESTIGATE,
            threat_confidence=0.8,
            has_warrant=True
        )
        self.assertTrue(is_authorized)
    
    def test_probable_cause_threshold(self):
        """Verify probable cause threshold is enforced"""
        # Low confidence should be denied
        is_authorized = self.compliance.is_action_authorized(
            action=SecurityAction.INVESTIGATE,
            threat_confidence=0.3,
            has_warrant=True
        )
        self.assertFalse(is_authorized)
        
        # High confidence should be approved
        is_authorized = self.compliance.is_action_authorized(
            action=SecurityAction.INVESTIGATE,
            threat_confidence=0.8,
            has_warrant=True
        )
        self.assertTrue(is_authorized)
    
    def test_monitoring_without_warrant(self):
        """Verify general monitoring allowed without warrant"""
        is_authorized = self.compliance.is_action_authorized(
            action=SecurityAction.MONITOR,
            threat_confidence=0.3,
            has_warrant=False
        )
        self.assertTrue(is_authorized)


class TestThreatDetection(unittest.TestCase):
    """Test threat detection capabilities"""
    
    def setUp(self):
        self.engine = ThreatDetectionEngine()
    
    def test_signature_detection(self):
        """Test signature-based threat detection"""
        alert = self.engine.analyze_traffic(
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            payload_signature="sql_injection_pattern"
        )
        
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_type, "sql_injection")
        self.assertGreaterEqual(alert.threat_level.value, ThreatLevel.MEDIUM.value)
    
    def test_low_confidence_not_alerted(self):
        """Test that low confidence threats are not alerted"""
        alert = self.engine.analyze_traffic(
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            payload_signature="unknown_pattern"
        )
        
        self.assertIsNone(alert)
    
    def test_threat_response_requires_authorization(self):
        """Test that threat response respects Constitutional constraints"""
        alert = self.engine.analyze_traffic(
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            payload_signature="sql_injection_pattern"
        )
        
        # Response should fail without warrant (for investigate actions)
        if alert.requires_warrant:
            result = self.engine.respond_to_threat(alert, has_warrant=False)
            self.assertFalse(result)


class TestComplianceVerification(unittest.TestCase):
    """Test compliance verification system"""
    
    def setUp(self):
        self.checker = ComplianceChecker()
    
    def test_warrant_verification(self):
        """Test warrant requirement verification"""
        result = self.checker.verify_warrant_requirement(
            investigation_id="INV-001",
            investigation_type="investigate",
            has_warrant=True,
            warrant_number="2024-FED-001"
        )
        
        self.assertEqual(result["status"], "pass")
    
    def test_warrant_missing_violation(self):
        """Test violation when warrant is missing"""
        self.checker.verify_warrant_requirement(
            investigation_id="INV-002",
            investigation_type="investigate",
            has_warrant=False
        )
        
        report = self.checker.get_compliance_report()
        self.assertGreater(report["total_violations"], 0)
        self.assertEqual(report["compliance_status"], "FAIL")
    
    def test_data_retention_enforcement(self):
        """Test data retention limit enforcement"""
        # Data retained beyond limit should fail
        old_date = (datetime.utcnow() - timedelta(days=100)).isoformat()
        result = self.checker.verify_retention_policy(
            data_type="non_threat_metadata",
            collected_date=old_date
        )
        
        self.assertEqual(result["status"], "fail")
        self.assertGreater(len(self.checker.violations), 0)
    
    def test_probable_cause_threshold_check(self):
        """Test probable cause verification"""
        # Low confidence should fail
        result = self.checker.verify_probable_cause(
            investigation_id="INV-003",
            confidence_score=0.5,
            required_threshold=0.7
        )
        
        self.assertEqual(result["status"], "fail")
    
    def test_audit_trail_verification(self):
        """Test audit trail verification"""
        # Empty audit trail should fail
        result = self.checker.verify_audit_trail(
            action_id="ACT-001",
            audit_entries=[]
        )
        
        self.assertEqual(result["status"], "fail")
        
        # Valid audit trail should pass
        result = self.checker.verify_audit_trail(
            action_id="ACT-002",
            audit_entries=[{
                "timestamp": datetime.utcnow().isoformat(),
                "action": "investigate",
                "user": "agent@freedom-firewall.gov",
                "result": "success"
            }]
        )
        
        self.assertEqual(result["status"], "pass")


class TestNetworkAnomalyDetection(unittest.TestCase):
    """Test network anomaly detection"""
    
    def setUp(self):
        self.detector = NetworkAnomalyDetector()
    
    def test_baseline_establishment(self):
        """Test baseline network behavior establishment"""
        flows = [
            NetworkFlow(
                source_ip="192.168.1.100",
                dest_ip="10.0.0.1",
                source_port=54321,
                dest_port=80,
                protocol="TCP",
                packet_count=100,
                byte_count=50000,
                duration_seconds=60,
                timestamp=datetime.utcnow().isoformat(),
                flags=["SYN", "ACK"]
            ),
        ]
        
        self.detector.establish_baseline(flows)
        self.assertGreater(len(self.detector.flow_baselines), 0)
    
    def test_anomaly_detection(self):
        """Test anomalous flow detection"""
        baseline_flows = [
            NetworkFlow(
                source_ip="192.168.1.100",
                dest_ip="10.0.0.1",
                source_port=54321,
                dest_port=80,
                protocol="TCP",
                packet_count=100,
                byte_count=50000,
                duration_seconds=60,
                timestamp=datetime.utcnow().isoformat(),
                flags=["SYN", "ACK"]
            ),
        ]
        
        self.detector.establish_baseline(baseline_flows)
        
        # Create anomalous flow (10x normal traffic)
        anomalous_flow = NetworkFlow(
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            source_port=54321,
            dest_port=80,
            protocol="TCP",
            packet_count=1000,  # 10x normal
            byte_count=500000,
            duration_seconds=60,
            timestamp=datetime.utcnow().isoformat(),
            flags=["SYN", "ACK", "RST"]
        )
        
        anomalies = self.detector.detect_anomalies([anomalous_flow])
        self.assertGreater(len(anomalies), 0)


class TestMalwareDetection(unittest.TestCase):
    """Test malware signature detection"""
    
    def setUp(self):
        self.detector = MalwareSignatureDetector()
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        result = self.detector.detect_signature(
            payload="SELECT * FROM users WHERE id = ' OR '1'='1",
            destination_port=3306
        )
        
        self.assertIsNotNone(result)
        pattern, confidence = result
        self.assertEqual(pattern.pattern_id, "SQL_001")
        self.assertGreater(confidence, 0)
    
    def test_xss_detection(self):
        """Test XSS attack detection"""
        result = self.detector.detect_signature(
            payload="<script>alert('XSS')</script>",
            destination_port=80
        )
        
        self.assertIsNotNone(result)
        pattern, confidence = result
        self.assertEqual(pattern.pattern_id, "XSS_001")
    
    def test_unknown_payload_no_match(self):
        """Test unknown payload doesn't match"""
        result = self.detector.detect_signature(
            payload="GET /index.html HTTP/1.1",
            destination_port=80
        )
        
        self.assertIsNone(result)


class TestIntegration(unittest.TestCase):
    """Integration tests for full system"""
    
    def setUp(self):
        self.engine = ThreatDetectionEngine()
        self.checker = ComplianceChecker()
    
    def test_end_to_end_threat_response(self):
        """Test complete threat detection and response workflow"""
        # Detect threat
        alert = self.engine.analyze_traffic(
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            payload_signature="sql_injection_pattern"
        )
        
        self.assertIsNotNone(alert)
        
        # Verify compliance before response
        self.checker.verify_probable_cause(
            investigation_id=alert.alert_id,
            confidence_score=float(alert.threat_level.value) / 5.0
        )
        
        if alert.requires_warrant:
            # Response requires warrant
            result = self.engine.respond_to_threat(alert, has_warrant=True)
            self.assertTrue(result)
        else:
            # No warrant needed
            result = self.engine.respond_to_threat(alert)
            self.assertTrue(result)


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
