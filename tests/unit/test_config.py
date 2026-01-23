"""
Configuration Module Unit Tests
"""

import os
import json
import tempfile
from pathlib import Path
import pytest

from zimra_fdms.config import (
    FdmsConfig,
    FdmsEnvironment,
    ConfigLoader,
    ConfigValidator,
    ConfigDefaults,
    FDMS_BASE_URLS,
)
from zimra_fdms.exceptions import ValidationError


class TestConfigValidator:
    """Tests for ConfigValidator"""
    
    @pytest.fixture
    def validator(self) -> ConfigValidator:
        return ConfigValidator()
    
    @pytest.fixture
    def valid_config(self) -> dict:
        return {
            "device_id": "12345",
            "device_serial_no": "SN-001",
            "activation_key": "test-key",
            "device_model_name": "TestModel",
            "device_model_version": "1.0.0",
            "certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
        }
    
    def test_validate_valid_config(self, validator: ConfigValidator, valid_config: dict):
        """Should pass with valid configuration"""
        result = validator.validate(valid_config)
        assert result.valid is True
        assert len(result.errors) == 0
    
    def test_validate_missing_device_id(self, validator: ConfigValidator, valid_config: dict):
        """Should fail when device_id is missing"""
        del valid_config["device_id"]
        result = validator.validate(valid_config)
        assert result.valid is False
        assert any(e.field == "device_id" for e in result.errors)
    
    def test_validate_empty_device_id(self, validator: ConfigValidator, valid_config: dict):
        """Should fail when device_id is empty"""
        valid_config["device_id"] = ""
        result = validator.validate(valid_config)
        assert result.valid is False
        assert any(
            e.field == "device_id" and "empty" in e.message
            for e in result.errors
        )
    
    def test_validate_non_numeric_device_id(self, validator: ConfigValidator, valid_config: dict):
        """Should fail when device_id is not numeric"""
        valid_config["device_id"] = "abc123"
        result = validator.validate(valid_config)
        assert result.valid is False
        assert any(
            e.field == "device_id" and "numeric" in e.message
            for e in result.errors
        )
    
    def test_validate_invalid_environment(self, validator: ConfigValidator, valid_config: dict):
        """Should fail with invalid environment"""
        valid_config["environment"] = "invalid"
        result = validator.validate(valid_config)
        assert result.valid is False
        assert any(e.field == "environment" for e in result.errors)
    
    def test_validate_invalid_timeout(self, validator: ConfigValidator, valid_config: dict):
        """Should fail with negative timeout"""
        valid_config["timeout"] = -1000
        result = validator.validate(valid_config)
        assert result.valid is False
        assert any(e.field == "timeout" for e in result.errors)
    
    def test_validate_timeout_too_low(self, validator: ConfigValidator, valid_config: dict):
        """Should fail with timeout too low"""
        valid_config["timeout"] = 100
        result = validator.validate(valid_config)
        assert result.valid is False
        assert any(
            e.field == "timeout" and "1000ms" in e.message
            for e in result.errors
        )
    
    def test_validate_invalid_base_url(self, validator: ConfigValidator, valid_config: dict):
        """Should fail with invalid base_url"""
        valid_config["base_url"] = "not-a-url"
        result = validator.validate(valid_config)
        assert result.valid is False
        assert any(e.field == "base_url" for e in result.errors)
    
    def test_validate_valid_base_url(self, validator: ConfigValidator, valid_config: dict):
        """Should accept valid base_url"""
        valid_config["base_url"] = "https://example.com"
        result = validator.validate(valid_config)
        assert result.valid is True
    
    def test_validate_certificate_as_file_path(self, validator: ConfigValidator, valid_config: dict):
        """Should accept certificate as file path"""
        valid_config["certificate"] = "/path/to/cert.pem"
        result = validator.validate(valid_config)
        assert result.valid is True
    
    def test_validate_or_raise_invalid(self, validator: ConfigValidator, valid_config: dict):
        """Should raise ValidationError with invalid configuration"""
        del valid_config["device_id"]
        with pytest.raises(ValidationError):
            validator.validate_or_raise(valid_config)


class TestConfigLoader:
    """Tests for ConfigLoader"""
    
    @pytest.fixture
    def loader(self) -> ConfigLoader:
        return ConfigLoader()
    
    @pytest.fixture
    def valid_config(self) -> dict:
        return {
            "device_id": "12345",
            "device_serial_no": "SN-001",
            "activation_key": "test-key",
            "device_model_name": "TestModel",
            "device_model_version": "1.0.0",
            "certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
        }
    
    def test_from_dict(self, loader: ConfigLoader, valid_config: dict):
        """Should return a copy of the configuration"""
        result = loader.from_dict(valid_config)
        assert result == valid_config
        assert result is not valid_config
    
    def test_from_environment(self, loader: ConfigLoader, monkeypatch):
        """Should load configuration from environment variables"""
        monkeypatch.setenv("FDMS_DEVICE_ID", "67890")
        monkeypatch.setenv("FDMS_DEVICE_SERIAL_NO", "SN-ENV")
        monkeypatch.setenv("FDMS_ENVIRONMENT", "production")
        monkeypatch.setenv("FDMS_TIMEOUT", "60000")
        monkeypatch.setenv("FDMS_ENABLE_AUDIT_LOG", "false")
        
        result = loader.from_environment()
        
        assert result["device_id"] == "67890"
        assert result["device_serial_no"] == "SN-ENV"
        assert result["environment"] == FdmsEnvironment.PRODUCTION
        assert result["timeout"] == 60000
        assert result["enable_audit_log"] is False
    
    def test_from_environment_boolean_parsing(self, loader: ConfigLoader, monkeypatch):
        """Should parse boolean values correctly"""
        monkeypatch.setenv("FDMS_ENABLE_AUDIT_LOG", "true")
        result = loader.from_environment()
        assert result["enable_audit_log"] is True
        
        monkeypatch.setenv("FDMS_ENABLE_AUDIT_LOG", "1")
        result = loader.from_environment()
        assert result["enable_audit_log"] is True
        
        monkeypatch.setenv("FDMS_ENABLE_AUDIT_LOG", "false")
        result = loader.from_environment()
        assert result["enable_audit_log"] is False
    
    def test_merge(self, loader: ConfigLoader):
        """Should merge multiple configurations with priority"""
        base = {"device_id": "111", "device_serial_no": "SN-BASE"}
        override = {"device_id": "222", "timeout": 5000}
        
        result = loader.merge(base, override)
        
        assert result["device_id"] == "222"
        assert result["device_serial_no"] == "SN-BASE"
        assert result["timeout"] == 5000
    
    def test_merge_filters_none(self, loader: ConfigLoader):
        """Should not include None values from overrides"""
        base = {"device_id": "111", "timeout": 30000}
        override = {"device_id": "222", "timeout": None}
        
        result = loader.merge(base, override)
        
        assert result["device_id"] == "222"
        assert result["timeout"] == 30000
    
    def test_resolve_applies_defaults(self, loader: ConfigLoader, valid_config: dict):
        """Should apply default values"""
        result = loader.resolve(valid_config)
        
        assert result.environment == FdmsEnvironment.TEST
        assert result.timeout == ConfigDefaults.TIMEOUT
        assert result.retry_attempts == ConfigDefaults.RETRY_ATTEMPTS
        assert result.retry_delay == ConfigDefaults.RETRY_DELAY
        assert result.enable_audit_log == ConfigDefaults.ENABLE_AUDIT_LOG
    
    def test_resolve_sets_base_url_from_environment(self, loader: ConfigLoader, valid_config: dict):
        """Should set base_url based on environment"""
        valid_config["environment"] = FdmsEnvironment.TEST
        result = loader.resolve(valid_config)
        assert result.base_url == FDMS_BASE_URLS[FdmsEnvironment.TEST]
        
        valid_config["environment"] = FdmsEnvironment.PRODUCTION
        result = loader.resolve(valid_config)
        assert result.base_url == FDMS_BASE_URLS[FdmsEnvironment.PRODUCTION]
    
    def test_resolve_allows_custom_base_url(self, loader: ConfigLoader, valid_config: dict):
        """Should allow custom base_url"""
        valid_config["base_url"] = "https://custom.example.com"
        result = loader.resolve(valid_config)
        assert result.base_url == "https://custom.example.com"
    
    def test_from_file(self, loader: ConfigLoader, valid_config: dict):
        """Should load configuration from JSON file"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(valid_config, f)
            f.flush()
            
            try:
                result = loader.from_file(f.name)
                assert result["device_id"] == valid_config["device_id"]
            finally:
                os.unlink(f.name)
    
    def test_from_file_not_found(self, loader: ConfigLoader):
        """Should raise error for missing file"""
        from zimra_fdms.exceptions import FdmsError
        
        with pytest.raises(FdmsError) as exc_info:
            loader.from_file("/nonexistent/path.json")
        
        assert "CONFIG_FILE_NOT_FOUND" in str(exc_info.value.code)
    
    def test_load_from_config(self, loader: ConfigLoader, valid_config: dict):
        """Should load and resolve configuration from dict"""
        result = loader.load(config=valid_config, env=False)
        
        assert result.device_id == valid_config["device_id"]
        assert result.environment == FdmsEnvironment.TEST
        assert result.base_url == FDMS_BASE_URLS[FdmsEnvironment.TEST]
    
    def test_create_template(self, loader: ConfigLoader):
        """Should create template configuration file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            template_path = Path(tmpdir) / "config" / "template.json"
            loader.create_template(template_path)
            
            assert template_path.exists()
            
            with open(template_path) as f:
                template = json.load(f)
            
            assert "device_id" in template
            assert "certificate" in template
            assert "environment" in template


class TestFdmsConfig:
    """Tests for FdmsConfig Pydantic model"""
    
    @pytest.fixture
    def valid_data(self) -> dict:
        return {
            "device_id": "12345",
            "device_serial_no": "SN-001",
            "activation_key": "test-key",
            "device_model_name": "TestModel",
            "device_model_version": "1.0.0",
            "certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
        }
    
    def test_create_valid_config(self, valid_data: dict):
        """Should create config with valid data"""
        config = FdmsConfig(**valid_data)
        assert config.device_id == "12345"
        assert config.environment == FdmsEnvironment.TEST
    
    def test_default_base_url(self, valid_data: dict):
        """Should set default base_url from environment"""
        config = FdmsConfig(**valid_data)
        assert config.base_url == FDMS_BASE_URLS[FdmsEnvironment.TEST]
    
    def test_invalid_device_id(self, valid_data: dict):
        """Should reject non-numeric device_id"""
        valid_data["device_id"] = "abc"
        with pytest.raises(ValueError):
            FdmsConfig(**valid_data)
    
    def test_invalid_base_url(self, valid_data: dict):
        """Should reject invalid base_url"""
        valid_data["base_url"] = "not-a-url"
        with pytest.raises(ValueError):
            FdmsConfig(**valid_data)
