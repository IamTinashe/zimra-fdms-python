"""
ZIMRA FDMS Configuration Types and Schema
Type-safe configuration objects for the FDMS SDK
"""

from enum import Enum
from typing import Optional, Union
from pathlib import Path
from pydantic import BaseModel, Field, field_validator, model_validator


class FdmsEnvironment(str, Enum):
    """FDMS Environment types"""
    TEST = "test"
    PRODUCTION = "production"


# Base URLs for FDMS environments
FDMS_BASE_URLS = {
    FdmsEnvironment.TEST: "https://fdmsapitest.zimra.co.zw",
    FdmsEnvironment.PRODUCTION: "https://fdmsapi.zimra.co.zw",
}


class ConfigDefaults:
    """Default configuration values"""
    ENVIRONMENT = FdmsEnvironment.TEST
    TIMEOUT = 30000
    RETRY_ATTEMPTS = 3
    RETRY_DELAY = 1000
    ENABLE_AUDIT_LOG = True


# Environment variable mapping
ENV_VAR_MAPPING = {
    "FDMS_DEVICE_ID": "device_id",
    "FDMS_DEVICE_SERIAL_NO": "device_serial_no",
    "FDMS_ACTIVATION_KEY": "activation_key",
    "FDMS_DEVICE_MODEL_NAME": "device_model_name",
    "FDMS_DEVICE_MODEL_VERSION": "device_model_version",
    "FDMS_CERTIFICATE": "certificate",
    "FDMS_PRIVATE_KEY": "private_key",
    "FDMS_PRIVATE_KEY_PASSWORD": "private_key_password",
    "FDMS_ENVIRONMENT": "environment",
    "FDMS_BASE_URL": "base_url",
    "FDMS_TIMEOUT": "timeout",
    "FDMS_RETRY_ATTEMPTS": "retry_attempts",
    "FDMS_RETRY_DELAY": "retry_delay",
    "FDMS_ENABLE_AUDIT_LOG": "enable_audit_log",
    "FDMS_AUDIT_LOG_PATH": "audit_log_path",
    "FDMS_STATE_STORE_PATH": "state_store_path",
}


class FdmsConfig(BaseModel):
    """
    Main FDMS Configuration class
    Defines all configuration options for the FDMS SDK
    """
    
    # Required - Device identification
    device_id: str = Field(
        ...,
        description="Device ID assigned by ZIMRA",
        min_length=1
    )
    device_serial_no: str = Field(
        ...,
        description="Manufacturer serial number",
        min_length=1
    )
    activation_key: str = Field(
        ...,
        description="Activation key from ZIMRA registration portal",
        min_length=1
    )
    device_model_name: str = Field(
        ...,
        description="Device model name registered with ZIMRA",
        min_length=1
    )
    device_model_version: str = Field(
        ...,
        description="Device model version registered with ZIMRA",
        min_length=1
    )
    
    # Required - Certificate configuration
    certificate: Union[str, bytes] = Field(
        ...,
        description="X.509 certificate (PEM/DER format) - file path or content"
    )
    private_key: Union[str, bytes] = Field(
        ...,
        description="RSA private key (PEM/DER format) - file path or content"
    )
    private_key_password: Optional[str] = Field(
        default=None,
        description="Password for encrypted private key (optional)"
    )
    
    # Optional - Environment settings
    environment: FdmsEnvironment = Field(
        default=FdmsEnvironment.TEST,
        description="Environment: 'test' or 'production'"
    )
    base_url: Optional[str] = Field(
        default=None,
        description="Override default base URL"
    )
    timeout: int = Field(
        default=ConfigDefaults.TIMEOUT,
        description="Request timeout in milliseconds",
        ge=1000,
        le=300000
    )
    retry_attempts: int = Field(
        default=ConfigDefaults.RETRY_ATTEMPTS,
        description="Number of retry attempts",
        ge=0,
        le=10
    )
    retry_delay: int = Field(
        default=ConfigDefaults.RETRY_DELAY,
        description="Base delay between retries in milliseconds",
        ge=1,
        le=60000
    )
    
    # Optional - Audit logging
    enable_audit_log: bool = Field(
        default=ConfigDefaults.ENABLE_AUDIT_LOG,
        description="Enable audit logging"
    )
    audit_log_path: Optional[str] = Field(
        default=None,
        description="File path for audit logs"
    )
    
    # Optional - State persistence
    state_store_path: Optional[str] = Field(
        default=None,
        description="Path to store fiscal state/counters"
    )
    
    model_config = {
        "str_strip_whitespace": True,
        "validate_assignment": True,
    }
    
    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, v: str) -> str:
        """Validate device_id is numeric"""
        if not v.isdigit():
            raise ValueError("device_id must be a numeric value")
        return v
    
    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate base_url is a valid URL"""
        if v is not None and v != "":
            if not v.startswith(("http://", "https://")):
                raise ValueError("base_url must be a valid HTTP/HTTPS URL")
        return v
    
    @field_validator("certificate", "private_key")
    @classmethod
    def validate_cert_or_key(cls, v: Union[str, bytes]) -> Union[str, bytes]:
        """Validate certificate/key is file path, PEM content, or bytes"""
        if isinstance(v, bytes):
            return v
        
        if isinstance(v, str):
            # Check if it's PEM content
            if "-----BEGIN" in v:
                return v
            
            # Check if it's a valid file extension
            valid_extensions = (".pem", ".crt", ".cer", ".der", ".key")
            if v.lower().endswith(valid_extensions):
                return v
            
            # If short string and not matching above, likely invalid
            if len(v) < 100:
                raise ValueError(
                    "Must be a valid file path (.pem, .crt, .cer, .der, .key) "
                    "or PEM-encoded content"
                )
        
        return v
    
    @model_validator(mode="after")
    def set_default_base_url(self) -> "FdmsConfig":
        """Set default base_url based on environment if not provided"""
        if self.base_url is None:
            self.base_url = FDMS_BASE_URLS[self.environment]
        return self
    
    def get_resolved_base_url(self) -> str:
        """Get the resolved base URL"""
        return self.base_url or FDMS_BASE_URLS[self.environment]


class PartialFdmsConfig(BaseModel):
    """
    Partial configuration for merging from multiple sources
    All fields are optional to allow partial configuration
    """
    
    device_id: Optional[str] = None
    device_serial_no: Optional[str] = None
    activation_key: Optional[str] = None
    device_model_name: Optional[str] = None
    device_model_version: Optional[str] = None
    certificate: Optional[Union[str, bytes]] = None
    private_key: Optional[Union[str, bytes]] = None
    private_key_password: Optional[str] = None
    environment: Optional[FdmsEnvironment] = None
    base_url: Optional[str] = None
    timeout: Optional[int] = None
    retry_attempts: Optional[int] = None
    retry_delay: Optional[int] = None
    enable_audit_log: Optional[bool] = None
    audit_log_path: Optional[str] = None
    state_store_path: Optional[str] = None
    
    model_config = {
        "str_strip_whitespace": True,
    }
