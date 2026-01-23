"""
Configuration Examples for ZIMRA FDMS SDK
Demonstrates various ways to configure the SDK
"""

from zimra_fdms.config import (
    ConfigLoader,
    ConfigValidator,
    FdmsConfig,
    FdmsEnvironment,
)


# =============================================================================
# Example 1: Programmatic Configuration
# =============================================================================

def programmatic_config_example() -> FdmsConfig:
    """Configure SDK programmatically with all options"""
    loader = ConfigLoader()
    
    config = loader.load(
        config={
            # Required device information
            "device_id": "12345",
            "device_serial_no": "SN-2024-001",
            "activation_key": "your-activation-key-from-zimra",
            "device_model_name": "MyPOS-Terminal",
            "device_model_version": "1.0.0",
            
            # Certificate configuration
            "certificate": "/path/to/device-certificate.pem",
            "private_key": "/path/to/private-key.pem",
            "private_key_password": "optional-key-password",
            
            # Environment settings
            "environment": FdmsEnvironment.TEST,  # Use PRODUCTION for live
            "timeout": 30000,
            "retry_attempts": 3,
            "retry_delay": 1000,
            
            # Audit logging
            "enable_audit_log": True,
            "audit_log_path": "./logs/fdms-audit.log",
            
            # State persistence
            "state_store_path": "./data/fiscal-state.json",
        }
    )
    
    return config


# =============================================================================
# Example 2: File-based Configuration
# =============================================================================

def file_config_example() -> FdmsConfig:
    """Load configuration from JSON file"""
    loader = ConfigLoader()
    
    # Load from JSON file (see fdms_config.example.json)
    return loader.load(
        file="./config/fdms_config.json",
        env=True,  # Also check environment variables (can override file)
    )


# =============================================================================
# Example 3: Environment Variables Configuration
# =============================================================================

def env_config_example() -> FdmsConfig:
    """
    Load configuration from environment variables
    
    Set these environment variables before running:
    
    export FDMS_DEVICE_ID="12345"
    export FDMS_DEVICE_SERIAL_NO="SN-2024-001"
    export FDMS_ACTIVATION_KEY="your-activation-key"
    export FDMS_DEVICE_MODEL_NAME="MyPOS-Terminal"
    export FDMS_DEVICE_MODEL_VERSION="1.0.0"
    export FDMS_CERTIFICATE="/path/to/cert.pem"
    export FDMS_PRIVATE_KEY="/path/to/key.pem"
    export FDMS_ENVIRONMENT="test"
    export FDMS_ENABLE_AUDIT_LOG="true"
    """
    loader = ConfigLoader()
    return loader.load(env=True)


# =============================================================================
# Example 4: Merged Configuration (File + Environment + Programmatic)
# =============================================================================

def merged_config_example() -> FdmsConfig:
    """
    Merge configuration from multiple sources
    Priority: programmatic > environment > file
    """
    loader = ConfigLoader()
    
    # This allows base settings in file, overrides via env vars,
    # and runtime-specific settings programmatically
    return loader.load(
        file="./config/fdms_config.json",
        env=True,
        config={
            # Override specific settings at runtime
            "timeout": 60000,  # Longer timeout for slow connections
        },
    )


# =============================================================================
# Example 5: Inline Certificate Content
# =============================================================================

def inline_certificate_example() -> FdmsConfig:
    """Use inline PEM certificate content instead of file paths"""
    loader = ConfigLoader()
    
    certificate_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpEgcMFvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNlZDAeFw0yNDAxMjMwMDAwMDBaFw0yNTAxMjMwMDAwMDBaMBExDzANBgNVBAMM
BnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5lKUH7MN7z1A2Z5lBz0lM
W0KqTNZL6j8P9DxC0Z5dV5FGZuDQB5+x1qH7BqIrL7t3AFn6eH0vDq6LqL1ZbE0t
AgMBAAGjUzBRMB0GA1UdDgQWBBRj1Hv2J5t3A6L7y8d3zJpvVqzMqTAfBgNVHSME
GDAWgBRj1Hv2J5t3A6L7y8d3zJpvVqzMqTAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAjQ7lGzXf8Z2mKl7cYl8v5y0fCIo2H6qL8bL9k3L5F3l2zUlG
-----END CERTIFICATE-----"""
    
    private_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALmUpQfsw3vPUDZnmUHPSUxbQqpM1kvqPw/0PELRnl1XkUZm4NAH
n7HWofsGoiovu3cAWfp4fS8OrouovVlsTS0CAwEAAQJAYJl8W8gXk2P5t3J5y8W7
Z8n5J6k8S8K9F9l9K3H7Y8K9F9l9K3H7Y8K9F9l9K3H7Y8K9F9l9K3H7Y8K9F9l9
-----END RSA PRIVATE KEY-----"""
    
    return loader.load(
        config={
            "device_id": "12345",
            "device_serial_no": "SN-2024-001",
            "activation_key": "your-activation-key",
            "device_model_name": "MyPOS-Terminal",
            "device_model_version": "1.0.0",
            
            # Inline certificate and key content
            "certificate": certificate_pem,
            "private_key": private_key_pem,
            
            "environment": FdmsEnvironment.TEST,
        }
    )


# =============================================================================
# Example 6: Creating a Configuration Template
# =============================================================================

def create_config_template_example() -> None:
    """Create a template configuration file"""
    loader = ConfigLoader()
    
    # Create a template configuration file
    loader.create_template("./config/fdms_config.template.json")
    
    print("Configuration template created at ./config/fdms_config.template.json")


# =============================================================================
# Example 7: Configuration Validation
# =============================================================================

def validation_example() -> None:
    """Validate configuration before use"""
    validator = ConfigValidator()
    
    partial_config = {
        "device_id": "12345",
        # Missing required fields...
    }
    
    result = validator.validate(partial_config)
    
    if not result.valid:
        print("Configuration validation failed:")
        for error in result.errors:
            print(f"  - {error.field}: {error.message}")


# =============================================================================
# Run Examples
# =============================================================================

if __name__ == "__main__":
    print("=== ZIMRA FDMS Configuration Examples ===\n")
    
    # Example 7: Validation
    print("7. Configuration Validation:")
    validation_example()
    print()
    
    # Example 6: Create template
    print("6. Create Configuration Template:")
    create_config_template_example()
