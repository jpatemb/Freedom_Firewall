"""
Freedom Firewall - Configuration Module
Centralized configuration management for all components
"""

import os
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class DatabaseConfig:
    """Database configuration"""
    host: str = os.getenv("DB_HOST", "localhost")
    port: int = int(os.getenv("DB_PORT", "5432"))
    username: str = os.getenv("DB_USER", "freedom_firewall")
    password: str = os.getenv("DB_PASSWORD", "")
    database: str = os.getenv("DB_NAME", "freedom_firewall")
    ssl: bool = os.getenv("DB_SSL", "true").lower() == "true"
    pool_size: int = int(os.getenv("DB_POOL_SIZE", "20"))
    
    def get_connection_string(self) -> str:
        """Generate connection string"""
        protocol = "postgresql+psycopg2"
        return (f"{protocol}://{self.username}:{self.password}@"
                f"{self.host}:{self.port}/{self.database}?sslmode=require")


@dataclass
class ElasticsearchConfig:
    """Elasticsearch configuration"""
    hosts: list = None
    index_prefix: str = os.getenv("ES_INDEX_PREFIX", "freedom-firewall")
    port: int = int(os.getenv("ES_PORT", "9200"))
    username: str = os.getenv("ES_USER", "elastic")
    password: str = os.getenv("ES_PASSWORD", "")
    ssl: bool = os.getenv("ES_SSL", "true").lower() == "true"
    
    def __post_init__(self):
        if self.hosts is None:
            self.hosts = os.getenv("ES_HOSTS", "localhost").split(",")


@dataclass
class KafkaConfig:
    """Kafka streaming configuration"""
    bootstrap_servers: list = None
    topic_alerts: str = "threat-alerts"
    topic_incidents: str = "security-incidents"
    topic_audit: str = "audit-trail"
    consumer_group: str = "freedom-firewall-consumers"
    auto_offset_reset: str = "earliest"
    
    def __post_init__(self):
        if self.bootstrap_servers is None:
            servers = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
            self.bootstrap_servers = servers.split(",")


@dataclass
class SecurityConfig:
    """Security configuration"""
    jwt_secret: str = os.getenv("JWT_SECRET", "")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    tls_cert_path: str = os.getenv("TLS_CERT", "/etc/ssl/certs/server.crt")
    tls_key_path: str = os.getenv("TLS_KEY", "/etc/ssl/private/server.key")
    tls_version: str = os.getenv("TLS_VERSION", "1.3")
    require_client_cert: bool = os.getenv("REQUIRE_CLIENT_CERT", "true").lower() == "true"
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PM", "1000"))
    encryption_key: str = os.getenv("ENCRYPTION_KEY", "")


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = os.getenv("LOG_LEVEL", "INFO")
    format: str = "%(asctime)s - %(name)s - %(levelname)s - [%(module)s] %(message)s"
    log_file: str = os.getenv("LOG_FILE", "/var/log/freedom-firewall/app.log")
    audit_log_file: str = os.getenv("AUDIT_LOG", "/var/log/freedom-firewall/audit.log")
    max_bytes: int = 10485760  # 10MB
    backup_count: int = 10
    syslog_enabled: bool = os.getenv("SYSLOG_ENABLED", "true").lower() == "true"


@dataclass
class AppConfig:
    """Application configuration"""
    environment: str = os.getenv("ENVIRONMENT", "development")
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    api_version: str = "1.0.0"
    port: int = int(os.getenv("PORT", "8443"))
    workers: int = int(os.getenv("WORKERS", "4"))
    timeout: int = int(os.getenv("TIMEOUT", "30"))
    
    # Feature flags
    enable_ml_detection: bool = os.getenv("ENABLE_ML", "true").lower() == "true"
    enable_public_dashboard: bool = os.getenv("ENABLE_DASHBOARD", "false").lower() == "true"
    enable_incident_response: bool = os.getenv("ENABLE_IR", "true").lower() == "true"
    
    # Compliance settings
    warrant_require_judicial_review: bool = True
    enable_compliance_checks: bool = True
    data_retention_days: int = int(os.getenv("RETENTION_DAYS", "365"))
    auto_data_destruction: bool = True


class FreedomFirewallConfig:
    """
    Master configuration class
    Aggregates all component configurations
    """
    
    def __init__(self):
        self.app = AppConfig()
        self.database = DatabaseConfig()
        self.elasticsearch = ElasticsearchConfig()
        self.kafka = KafkaConfig()
        self.security = SecurityConfig()
        self.logging_cfg = LoggingConfig()
    
    def validate(self) -> bool:
        """Validate all configuration settings"""
        errors = []
        
        # Check required fields
        if not self.security.jwt_secret:
            errors.append("JWT_SECRET not set")
        
        if not self.security.encryption_key:
            errors.append("ENCRYPTION_KEY not set")
        
        if self.app.environment not in ["development", "staging", "production"]:
            errors.append(f"Invalid ENVIRONMENT: {self.app.environment}")
        
        if self.database.port < 1 or self.database.port > 65535:
            errors.append(f"Invalid DB_PORT: {self.database.port}")
        
        if self.app.port < 1 or self.app.port > 65535:
            errors.append(f"Invalid PORT: {self.app.port}")
        
        if errors:
            for error in errors:
                print(f"CONFIG ERROR: {error}")
            return False
        
        return True
    
    def get_settings_dict(self) -> Dict:
        """Export configuration as dictionary"""
        return {
            "environment": self.app.environment,
            "debug": self.app.debug,
            "database": {
                "host": self.database.host,
                "port": self.database.port,
                "database": self.database.database,
            },
            "security": {
                "tls_version": self.security.tls_version,
                "jwt_algorithm": self.security.jwt_algorithm,
                "rate_limit": self.security.rate_limit_per_minute,
            },
            "compliance": {
                "warrant_review_required": self.app.warrant_require_judicial_review,
                "compliance_checks_enabled": self.app.enable_compliance_checks,
                "data_retention_days": self.app.data_retention_days,
                "auto_destruction": self.app.auto_data_destruction,
            }
        }


# Global configuration instance
config = FreedomFirewallConfig()


# Export configuration for use throughout application
__all__ = ["config", "FreedomFirewallConfig", "AppConfig", "DatabaseConfig", 
           "ElasticsearchConfig", "KafkaConfig", "SecurityConfig", "LoggingConfig"]
