"""
Freedom Firewall - Threat Detection Module
Advanced detection capabilities for network and infrastructure threats
"""

import hashlib
import statistics
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class NetworkFlow:
    """Represents a network connection flow"""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration_seconds: float
    timestamp: str
    flags: List[str]


@dataclass
class DetectionPattern:
    """Represents a threat detection pattern"""
    pattern_id: str
    name: str
    description: str
    confidence_weight: float
    pattern_rules: Dict
    threat_category: str


class NetworkAnomalyDetector:
    """
    Detects anomalous network behavior through statistical analysis
    and machine learning approaches
    """
    
    def __init__(self, baseline_window_hours: int = 24):
        self.baseline_window = baseline_window_hours
        self.flow_baselines = defaultdict(dict)
        self.current_flows = []
        self.historical_flows = []
        
    def establish_baseline(self, historical_flows: List[NetworkFlow]):
        """Establish baseline network behavior from historical data"""
        for flow in historical_flows:
            key = f"{flow.source_ip}_{flow.dest_ip}"
            
            if key not in self.flow_baselines:
                self.flow_baselines[key] = {
                    'avg_packet_count': 0,
                    'avg_byte_count': 0,
                    'avg_duration': 0,
                    'flow_frequency': 0,
                }
            
            baseline = self.flow_baselines[key]
            baseline['avg_packet_count'] = statistics.mean([
                flow.packet_count for flow in historical_flows if f"{flow.source_ip}_{flow.dest_ip}" == key
            ])
            baseline['avg_byte_count'] = statistics.mean([
                flow.byte_count for flow in historical_flows if f"{flow.source_ip}_{flow.dest_ip}" == key
            ])
            baseline['avg_duration'] = statistics.mean([
                flow.duration_seconds for flow in historical_flows if f"{flow.source_ip}_{flow.dest_ip}" == key
            ])
            baseline['flow_frequency'] = len([
                flow for flow in historical_flows if f"{flow.source_ip}_{flow.dest_ip}" == key
            ])
        
        self.historical_flows = historical_flows
    
    def detect_anomalies(self, current_flows: List[NetworkFlow]) -> List[Tuple[NetworkFlow, float]]:
        """
        Detect anomalous flows compared to baseline
        
        Returns: List of (flow, anomaly_score) tuples where score is 0-1
        """
        anomalies = []
        
        for flow in current_flows:
            key = f"{flow.source_ip}_{flow.dest_ip}"
            
            if key not in self.flow_baselines:
                # New flow pattern - treat with caution
                anomaly_score = 0.3  # Moderate suspicion for new patterns
            else:
                baseline = self.flow_baselines[key]
                anomaly_score = self._calculate_anomaly_score(flow, baseline)
            
            if anomaly_score > 0.6:  # Threshold for anomaly
                anomalies.append((flow, anomaly_score))
        
        return anomalies
    
    def _calculate_anomaly_score(self, flow: NetworkFlow, baseline: Dict) -> float:
        """Calculate anomaly score for a flow"""
        deviations = []
        
        # Packet count deviation
        if baseline['avg_packet_count'] > 0:
            packet_deviation = abs(flow.packet_count - baseline['avg_packet_count']) / baseline['avg_packet_count']
            deviations.append(min(packet_deviation, 1.0))
        
        # Byte count deviation
        if baseline['avg_byte_count'] > 0:
            byte_deviation = abs(flow.byte_count - baseline['avg_byte_count']) / baseline['avg_byte_count']
            deviations.append(min(byte_deviation, 1.0))
        
        # Duration deviation
        if baseline['avg_duration'] > 0:
            duration_deviation = abs(flow.duration_seconds - baseline['avg_duration']) / baseline['avg_duration']
            deviations.append(min(duration_deviation, 1.0))
        
        return statistics.mean(deviations) if deviations else 0.0


class MalwareSignatureDetector:
    """
    Detects known malware and intrusion signatures
    """
    
    def __init__(self):
        self.signatures = self._load_threat_signatures()
    
    def _load_threat_signatures(self) -> List[DetectionPattern]:
        """Load known threat signatures"""
        return [
            DetectionPattern(
                pattern_id="SQL_001",
                name="SQL Injection",
                description="SQL injection attack pattern",
                confidence_weight=0.85,
                pattern_rules={
                    'indicators': ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "exec("],
                    'ports': [3306, 1433, 5432],
                },
                threat_category="web_attack"
            ),
            DetectionPattern(
                pattern_id="XSS_001",
                name="Cross-Site Scripting",
                description="XSS attack pattern",
                confidence_weight=0.8,
                pattern_rules={
                    'indicators': ["<script>", "javascript:", "onerror=", "onclick="],
                    'ports': [80, 443, 8080],
                },
                threat_category="web_attack"
            ),
            DetectionPattern(
                pattern_id="DDOS_001",
                name="Volumetric DDoS",
                description="Distributed denial of service attack",
                confidence_weight=0.9,
                pattern_rules={
                    'indicators': ["high_packet_rate", "high_bandwidth"],
                    'flow_characteristics': {'packet_rate': '>10000pps', 'source_diversity': 'high'},
                },
                threat_category="volumetric"
            ),
            DetectionPattern(
                pattern_id="BOT_001",
                name="Botnet C2 Communication",
                description="Bot command and control communication",
                confidence_weight=0.87,
                pattern_rules={
                    'indicators': ["heartbeat_pattern", "encoded_payload"],
                    'ports': [6667, 8888, 9999],
                },
                threat_category="malware"
            ),
            DetectionPattern(
                pattern_id="RAN_001",
                name="Ransomware Activity",
                description="File encryption and exfiltration pattern",
                confidence_weight=0.92,
                pattern_rules={
                    'indicators': ["file_enumeration", "bulk_encryption", "ransom_note"],
                    'file_extensions': ['.encrypted', '.locked', '.payloadID'],
                },
                threat_category="malware"
            ),
        ]
    
    def detect_signature(self, payload: str, destination_port: int) -> Optional[Tuple[DetectionPattern, float]]:
        """
        Detect known threat signatures in network payload
        
        Returns: (DetectionPattern, confidence_score) or None
        """
        for signature in self.signatures:
            if destination_port in signature.pattern_rules.get('ports', []):
                match_count = 0
                for indicator in signature.pattern_rules.get('indicators', []):
                    if indicator.lower() in payload.lower():
                        match_count += 1
                
                if match_count > 0:
                    # Calculate confidence based on number of indicators matched
                    indicator_count = len(signature.pattern_rules.get('indicators', []))
                    confidence = signature.confidence_weight * (match_count / indicator_count)
                    return (signature, confidence)
        
        return None


class IntrusionDetectionSystem:
    """
    Full intrusion detection system combining multiple detection methods
    """
    
    def __init__(self):
        self.anomaly_detector = NetworkAnomalyDetector()
        self.signature_detector = MalwareSignatureDetector()
        self.alert_queue = []
        
    def analyze_flow(self, flow: NetworkFlow) -> List[Dict]:
        """
        Comprehensive analysis of a network flow
        
        Returns: List of alerts generated
        """
        alerts = []
        
        # Check against signatures
        signature_result = self.signature_detector.detect_signature(
            payload=f"{flow.source_ip}:{flow.source_port}",
            destination_port=flow.dest_port
        )
        
        if signature_result:
            pattern, confidence = signature_result
            alerts.append({
                'alert_type': 'signature_match',
                'pattern_name': pattern.name,
                'threat_category': pattern.threat_category,
                'confidence': confidence,
                'flow': flow,
                'timestamp': datetime.utcnow().isoformat(),
            })
        
        return alerts
    
    def bulk_analyze(self, flows: List[NetworkFlow]) -> List[Dict]:
        """Analyze multiple flows and return all alerts"""
        all_alerts = []
        self.anomaly_detector.establish_baseline(flows[:len(flows)//2])
        
        current_flows = flows[len(flows)//2:]
        
        # Anomaly detection
        anomalies = self.anomaly_detector.detect_anomalies(current_flows)
        for flow, score in anomalies:
            all_alerts.append({
                'alert_type': 'anomaly_detected',
                'anomaly_score': score,
                'flow': flow,
                'timestamp': datetime.utcnow().isoformat(),
            })
        
        # Signature detection
        for flow in current_flows:
            alerts = self.analyze_flow(flow)
            all_alerts.extend(alerts)
        
        return all_alerts


class ThreatIntelligenceIntegrator:
    """
    Integrates external threat intelligence into detection
    """
    
    def __init__(self):
        self.known_malicious_ips = set()
        self.known_malicious_domains = set()
        self.threat_feeds = []
    
    def add_threat_feed(self, feed_data: List[str]):
        """Add threat intelligence from external feeds"""
        self.threat_feeds.extend(feed_data)
        self._parse_threat_feed(feed_data)
    
    def _parse_threat_feed(self, feed_data: List[str]):
        """Parse threat feed data"""
        for item in feed_data:
            if self._is_ip(item):
                self.known_malicious_ips.add(item)
            elif self._is_domain(item):
                self.known_malicious_domains.add(item)
    
    def check_ip_reputation(self, ip_address: str) -> bool:
        """Check if IP is known malicious"""
        return ip_address in self.known_malicious_ips
    
    def check_domain_reputation(self, domain: str) -> bool:
        """Check if domain is known malicious"""
        return domain in self.known_malicious_domains
    
    @staticmethod
    def _is_ip(value: str) -> bool:
        """Check if value is an IP address"""
        parts = value.split('.')
        return len(parts) == 4 and all(part.isdigit() for part in parts)
    
    @staticmethod
    def _is_domain(value: str) -> bool:
        """Check if value is a domain"""
        return '.' in value and not value.split('.')[0].isdigit()


# Example usage
if __name__ == "__main__":
    # Create sample flows
    sample_flows = [
        NetworkFlow(
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            source_port=54321,
            dest_port=3306,
            protocol="TCP",
            packet_count=150,
            byte_count=45000,
            duration_seconds=120,
            timestamp=datetime.utcnow().isoformat(),
            flags=["SYN", "ACK"]
        ),
    ]
    
    # Initialize IDS
    ids = IntrusionDetectionSystem()
    alerts = ids.bulk_analyze(sample_flows)
    
    print(f"Generated {len(alerts)} alerts")
    for alert in alerts:
        print(f"  - {alert['alert_type']}: {alert}")
