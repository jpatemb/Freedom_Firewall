# Freedom Firewall - API Documentation

## Base URL
```
https://api.freedom-firewall.gov/api/v1
```

All API endpoints require:
- TLS 1.3 encryption
- mTLS client certificate authentication
- OAuth2 bearer token
- Valid agency credentials

---

## Authentication

### mTLS Certificate Setup
```bash
# Generate client certificate
openssl genrsa -out client.key 4096
openssl req -new -x509 -key client.key -out client.crt -days 365
```

### OAuth2 Token Acquisition
```bash
curl -X POST https://api.freedom-firewall.gov/auth/token \
  --cert client.crt --key client.key \
  -d "grant_type=client_credentials&client_id=FBI&client_secret=***"
```

---

## Endpoints

### 1. Health Check
**GET** `/health`

**Authorization**: None required

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

---

### 2. Report Security Alert
**POST** `/alerts/report`

**Authorization**: Bearer token + agency in FBI/DHS/NSA

**Request Body**:
```json
{
  "alert_id": "ALERT_20240115_001",
  "alert_type": "malware_detected",
  "severity": "high",
  "source_ip": "192.0.2.100",
  "target_resource": "mail-server-01.agency.gov",
  "description": "Trojan horse malware detected in email attachment",
  "timestamp": "2024-01-15T10:25:00Z",
  "action_taken": "quarantine"
}
```

**Response**:
```json
{
  "status": "received",
  "alert_id": "ALERT_20240115_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "audit_trail_id": "AUD_20240115_542",
  "message": "Alert successfully ingested and logged"
}
```

---

### 3. List Alerts
**GET** `/alerts/list`

**Authorization**: Bearer token + agency with alerts access

**Query Parameters**:
- `limit`: Max results (default: 100, max: 1000)
- `severity`: Filter by critical|high|medium|low
- `start_date`: ISO 8601 timestamp
- `end_date`: ISO 8601 timestamp

**Response**:
```json
{
  "total": 245,
  "returned": 100,
  "alerts": [
    {
      "alert_id": "ALERT_20240115_001",
      "alert_type": "malware_detected",
      "severity": "high",
      "source_ip": "192.0.2.100",
      "target_resource": "mail-server-01.agency.gov",
      "timestamp": "2024-01-15T10:25:00Z",
      "action_taken": "quarantine"
    }
  ]
}
```

---

### 4. Report Incident
**POST** `/incidents/report`

**Authorization**: Bearer token + agency with incident access

**Request Body**:
```json
{
  "incident_id": "INC_2024_001",
  "title": "Ransomware Campaign - Operation Darkside",
  "description": "Coordinated ransomware attack on federal infrastructure",
  "severity": "critical",
  "affected_systems": ["SERVER_01", "SERVER_02", "NETWORK_SEGMENT_A"],
  "alerts": [
    {
      "alert_id": "ALERT_20240115_001",
      "alert_type": "ransomware_detected",
      "severity": "critical"
    }
  ],
  "indicators": [
    {
      "indicator_type": "ip",
      "value": "203.0.113.42",
      "threat_level": "critical",
      "source": "FBI",
      "confidence": 0.95
    }
  ],
  "requires_warrant": true
}
```

**Response**:
```json
{
  "status": "received",
  "incident_id": "INC_2024_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "distribution": "limited_to_authorized_agencies",
  "agencies_notified": ["FBI", "DHS", "CISA", "NSA"]
}
```

---

### 5. Share Threat Indicators
**POST** `/indicators/share`

**Authorization**: Bearer token + NSA or FBI

**Request Body**:
```json
{
  "indicators": [
    {
      "indicator_type": "ip",
      "value": "203.0.113.42",
      "threat_level": "critical",
      "source": "FBI",
      "confidence": 0.95,
      "timestamp": "2024-01-15T10:25:00Z"
    },
    {
      "indicator_type": "domain",
      "value": "malicious.ru",
      "threat_level": "high",
      "source": "NSA",
      "confidence": 0.87
    },
    {
      "indicator_type": "hash",
      "value": "5d41402abc4b2a76b9719d911017c592",
      "threat_level": "high",
      "source": "FBI",
      "confidence": 0.92
    }
  ]
}
```

**Response**:
```json
{
  "status": "ingested",
  "count": 3,
  "timestamp": "2024-01-15T10:30:00Z",
  "distribution_list": ["FBI", "DHS", "CISA", "NSA", "EPA"]
}
```

---

### 6. Coordinate Incident Response
**POST** `/incident-response/coordinate`

**Authorization**: Bearer token + FBI or DHS

**Request Body**:
```json
{
  "incident_id": "INC_2024_001",
  "response_action": "network_isolation",
  "affected_agencies": ["FBI", "DHS", "CISA"],
  "urgency": "immediate"
}
```

**Response**:
```json
{
  "status": "coordinated",
  "incident_id": "INC_2024_001",
  "action": "network_isolation",
  "agencies_notified": ["FBI", "DHS", "CISA"],
  "estimated_coordination_time": "15 minutes",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### 7. Get Compliance Report
**GET** `/compliance/report`

**Authorization**: Bearer token + DHS/Inspector General

**Query Parameters**:
- `period`: current_quarter|current_year|custom
- `start_date`: ISO 8601 (if custom)
- `end_date`: ISO 8601 (if custom)

**Response**:
```json
{
  "reporting_period": "Q1_2024",
  "timestamp": "2024-01-15T10:30:00Z",
  "metrics": {
    "total_alerts_generated": 1245,
    "alerts_requiring_warrant": 87,
    "warrants_obtained": 87,
    "warrants_denied": 0,
    "constitutional_violations": 0,
    "data_destroyed_records": 2341,
    "audit_trail_entries": 45892,
    "avg_detection_time_minutes": 4.2,
    "avg_response_time_minutes": 12.5
  },
  "compliance_status": "PASS",
  "violations": [],
  "recommendations": []
}
```

---

### 8. Access Audit Log
**GET** `/audit/log`

**Authorization**: Bearer token + Inspector General/NSA only

**Query Parameters**:
- `limit`: Max results (default: 1000)
- `action_type`: Filter by action type
- `start_date`: ISO 8601
- `end_date`: ISO 8601
- `agency_filter`: Specific agency

**Response**:
```json
{
  "total": 45892,
  "returned": 1000,
  "audit_entries": [
    {
      "timestamp": "2024-01-15T10:25:00Z",
      "action": "alert_received",
      "agency": "FBI",
      "resource": "ALERT_20240115_001",
      "result": "success",
      "details": {
        "alert_type": "malware_detected",
        "severity": "high",
        "ip": "192.0.2.100"
      }
    }
  ]
}
```

---

## Error Responses

### 401 Unauthorized
```json
{
  "error": "Invalid agency credentials",
  "status_code": 401,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 403 Forbidden
```json
{
  "error": "Agency not authorized for this endpoint",
  "status_code": 403,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 429 Rate Limited
```json
{
  "error": "Rate limit exceeded: 100 requests per minute",
  "status_code": 429,
  "retry_after": 45,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "status_code": 500,
  "error_id": "ERR_20240115_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "support": "support@freedom-firewall.gov"
}
```

---

## Rate Limits

| Agency | Endpoint | Limit |
|--------|----------|-------|
| FBI | All endpoints | 1000 req/min |
| DHS | All endpoints | 500 req/min |
| NSA | Intelligence endpoints | 2000 req/min |
| Local LEA | Public endpoints | 100 req/min |

---

## Webhook Notifications

For authorized agencies, real-time webhooks available:

```bash
# Register webhook
curl -X POST https://api.freedom-firewall.gov/webhooks/register \
  --cert client.crt --key client.key \
  -d '{
    "url": "https://agency.gov/webhook/incidents",
    "events": ["critical_alert", "incident_detected"],
    "ssl_verify": true
  }'
```

Webhook payload example:
```json
{
  "event": "critical_alert",
  "timestamp": "2024-01-15T10:25:00Z",
  "data": {
    "alert_id": "ALERT_20240115_001",
    "severity": "critical",
    "action": "automatic_response_initiated"
  }
}
```

---

## SDK Examples

### Python
```python
import requests
from requests.auth import HTTPBearerAuth

# Initialize
api_url = "https://api.freedom-firewall.gov/api/v1"
token = "your_oauth2_token"
cert = ("client.crt", "client.key")

# Report alert
alert = {
    "alert_id": "ALERT_001",
    "alert_type": "malware",
    "severity": "high"
}

response = requests.post(
    f"{api_url}/alerts/report",
    json=alert,
    auth=HTTPBearerAuth(token),
    cert=cert,
    verify=True
)
```

### Go
```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// Load certificate
	cert, _ := tls.LoadX509KeyPair("client.crt", "client.key")
	
	// Create client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	
	// Make request
	req, _ := http.NewRequest("GET", "https://api.freedom-firewall.gov/api/v1/health", nil)
	resp, _ := client.Do(req)
	defer resp.Body.Close()
}
```

---

## Support

**Technical Support**: support@freedom-firewall.gov
**Security Issues**: security@freedom-firewall.gov
**Legal/Compliance**: legal@freedom-firewall.gov

