"""
Configuration Validator
Validates FDMS configuration with clear error messages
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from zimra_fdms.config.fdms_config import FdmsEnvironment


@dataclass
class ValidationErrorDetail:
    """Validation error detail"""
    field: str
    message: str
    value: Optional[Any] = None


@dataclass
class ValidationResult:
    """Validation result"""
    valid: bool
    errors: List[ValidationErrorDetail] = field(default_factory=list)


class ConfigValidator:
    """
    ConfigValidator class
    Provides comprehensive validation for FDMS configuration
    """
    
    def __init__(self) -> None:
        self._errors: List[ValidationErrorDetail] = []
    
    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        """
        Validate the entire configuration dictionary
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            ValidationResult with any errors
        """
        self._errors = []
        
        # Validate required fields
        self._validate_required(config)
        
        # Validate field formats
        self._validate_formats(config)
        
        # Validate numeric ranges
        self._validate_ranges(config)
        
        # Validate environment
        self._validate_environment(config)
        
        # Validate certificate configuration
        self._validate_certificate_config(config)
        
        return ValidationResult(
            valid=len(self._errors) == 0,
            errors=self._errors.copy()
        )
    
    def validate_or_raise(self, config: Dict[str, Any]) -> None:
        """
        Validate and raise if invalid
        
        Args:
            config: Configuration dictionary to validate
            
        Raises:
            ValueError: If configuration is invalid
        """
        from zimra_fdms.exceptions import ValidationError
        
        result = self.validate(config)
        if not result.valid:
            error_messages = "; ".join(
                f"{e.field}: {e.message}" for e in result.errors
            )
            raise ValidationError(f"Configuration validation failed: {error_messages}")
    
    def _validate_required(self, config: Dict[str, Any]) -> None:
        """Validate required fields are present and non-empty"""
        required_fields = [
            "device_id",
            "device_serial_no",
            "activation_key",
            "device_model_name",
            "device_model_version",
            "certificate",
            "private_key",
        ]
        
        for field_name in required_fields:
            value = config.get(field_name)
            if value is None:
                self._errors.append(ValidationErrorDetail(
                    field=field_name,
                    message=f"{field_name} is required"
                ))
            elif isinstance(value, str) and value.strip() == "":
                self._errors.append(ValidationErrorDetail(
                    field=field_name,
                    message=f"{field_name} cannot be empty",
                    value=value
                ))
    
    def _validate_formats(self, config: Dict[str, Any]) -> None:
        """Validate field formats"""
        # Device ID should be numeric
        device_id = config.get("device_id")
        if device_id is not None:
            device_id_str = str(device_id)
            if not device_id_str.isdigit():
                self._errors.append(ValidationErrorDetail(
                    field="device_id",
                    message="device_id must be a numeric value",
                    value=device_id
                ))
        
        # Validate URL format if base_url is provided
        base_url = config.get("base_url")
        if base_url is not None and base_url != "":
            if not base_url.startswith(("http://", "https://")):
                self._errors.append(ValidationErrorDetail(
                    field="base_url",
                    message="base_url must be a valid HTTP/HTTPS URL",
                    value=base_url
                ))
        
        # Validate path fields
        for path_field in ["audit_log_path", "state_store_path"]:
            path_value = config.get(path_field)
            if path_value is not None and path_value != "":
                if not isinstance(path_value, str):
                    self._errors.append(ValidationErrorDetail(
                        field=path_field,
                        message=f"{path_field} must be a string",
                        value=path_value
                    ))
    
    def _validate_ranges(self, config: Dict[str, Any]) -> None:
        """Validate numeric ranges"""
        # Timeout validation
        timeout = config.get("timeout")
        if timeout is not None:
            if not isinstance(timeout, (int, float)) or timeout <= 0:
                self._errors.append(ValidationErrorDetail(
                    field="timeout",
                    message="timeout must be a positive number (milliseconds)",
                    value=timeout
                ))
            elif timeout < 1000:
                self._errors.append(ValidationErrorDetail(
                    field="timeout",
                    message="timeout should be at least 1000ms for reliable operation",
                    value=timeout
                ))
            elif timeout > 300000:
                self._errors.append(ValidationErrorDetail(
                    field="timeout",
                    message="timeout should not exceed 300000ms (5 minutes)",
                    value=timeout
                ))
        
        # Retry attempts validation
        retry_attempts = config.get("retry_attempts")
        if retry_attempts is not None:
            if not isinstance(retry_attempts, int) or retry_attempts < 0:
                self._errors.append(ValidationErrorDetail(
                    field="retry_attempts",
                    message="retry_attempts must be a non-negative integer",
                    value=retry_attempts
                ))
            elif retry_attempts > 10:
                self._errors.append(ValidationErrorDetail(
                    field="retry_attempts",
                    message="retry_attempts should not exceed 10",
                    value=retry_attempts
                ))
        
        # Retry delay validation
        retry_delay = config.get("retry_delay")
        if retry_delay is not None:
            if not isinstance(retry_delay, (int, float)) or retry_delay <= 0:
                self._errors.append(ValidationErrorDetail(
                    field="retry_delay",
                    message="retry_delay must be a positive number (milliseconds)",
                    value=retry_delay
                ))
            elif retry_delay > 60000:
                self._errors.append(ValidationErrorDetail(
                    field="retry_delay",
                    message="retry_delay should not exceed 60000ms (1 minute)",
                    value=retry_delay
                ))
    
    def _validate_environment(self, config: Dict[str, Any]) -> None:
        """Validate environment setting"""
        environment = config.get("environment")
        if environment is not None:
            valid_environments = [e.value for e in FdmsEnvironment]
            env_value = environment.value if isinstance(environment, FdmsEnvironment) else environment
            if env_value not in valid_environments:
                self._errors.append(ValidationErrorDetail(
                    field="environment",
                    message=f"environment must be one of: {', '.join(valid_environments)}",
                    value=environment
                ))
    
    def _validate_certificate_config(self, config: Dict[str, Any]) -> None:
        """Validate certificate configuration"""
        valid_cert_extensions = (".pem", ".crt", ".cer", ".der")
        valid_key_extensions = (".pem", ".key", ".der")
        
        # Certificate validation
        certificate = config.get("certificate")
        if certificate is not None and isinstance(certificate, str):
            is_pem = "-----BEGIN" in certificate
            is_file_path = certificate.lower().endswith(valid_cert_extensions)
            
            if not is_pem and not is_file_path and len(certificate) < 100:
                self._errors.append(ValidationErrorDetail(
                    field="certificate",
                    message=(
                        "certificate must be a valid file path "
                        f"({', '.join(valid_cert_extensions)}) or PEM-encoded content"
                    ),
                    value=f"{certificate[:50]}..."
                ))
        
        # Private key validation
        private_key = config.get("private_key")
        if private_key is not None and isinstance(private_key, str):
            is_pem = "-----BEGIN" in private_key
            is_file_path = private_key.lower().endswith(valid_key_extensions)
            
            if not is_pem and not is_file_path and len(private_key) < 100:
                self._errors.append(ValidationErrorDetail(
                    field="private_key",
                    message=(
                        "private_key must be a valid file path "
                        f"({', '.join(valid_key_extensions)}) or PEM-encoded content"
                    ),
                    value="[REDACTED]"
                ))
