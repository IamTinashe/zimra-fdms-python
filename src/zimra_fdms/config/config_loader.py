"""
Configuration Loader
Loads FDMS configuration from various sources
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union

from zimra_fdms.config.fdms_config import (
    FdmsConfig,
    PartialFdmsConfig,
    FdmsEnvironment,
    ENV_VAR_MAPPING,
    ConfigDefaults,
)
from zimra_fdms.config.config_validator import ConfigValidator
from zimra_fdms.exceptions import FdmsError


class ConfigLoader:
    """
    ConfigLoader class
    Provides multiple ways to load and merge configuration
    """
    
    def __init__(self) -> None:
        self._validator = ConfigValidator()
    
    def from_file(self, path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load configuration from a JSON file
        
        Args:
            path: Path to JSON configuration file
            
        Returns:
            Loaded configuration dictionary
            
        Raises:
            FdmsError: If file not found or invalid JSON
        """
        file_path = Path(path).resolve()
        
        if not file_path.exists():
            raise FdmsError(
                f"Configuration file not found: {file_path}",
                code="CONFIG_FILE_NOT_FOUND"
            )
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            return self._process_certificate_paths(config, file_path.parent)
        except json.JSONDecodeError as e:
            raise FdmsError(
                f"Invalid JSON in configuration file: {file_path}",
                code="CONFIG_PARSE_ERROR"
            ) from e
    
    def from_environment(self) -> Dict[str, Any]:
        """
        Load configuration from environment variables
        
        Returns:
            Configuration dictionary from environment variables
        """
        config: Dict[str, Any] = {}
        
        for env_var, config_key in ENV_VAR_MAPPING.items():
            value = os.environ.get(env_var)
            if value is not None and value != "":
                config[config_key] = self._parse_env_value(config_key, value)
        
        return config
    
    def from_dict(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Load configuration from a dictionary
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Copy of configuration dictionary
        """
        return config.copy()
    
    def merge(self, *sources: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge multiple configuration sources
        Priority: later sources override earlier sources
        
        Args:
            sources: Configuration dictionaries in order of increasing priority
            
        Returns:
            Merged configuration dictionary
        """
        merged: Dict[str, Any] = {}
        
        for source in sources:
            filtered = self._filter_none(source)
            merged.update(filtered)
        
        return merged
    
    def resolve(self, config: Dict[str, Any]) -> FdmsConfig:
        """
        Resolve configuration with defaults and validation
        
        Args:
            config: Partial configuration dictionary
            
        Returns:
            Fully resolved FdmsConfig object
            
        Raises:
            ValidationError: If configuration is invalid
        """
        # Validate before resolving
        self._validator.validate_or_raise(config)
        
        # Create FdmsConfig (Pydantic handles defaults)
        return FdmsConfig(**config)
    
    def load(
        self,
        file: Optional[Union[str, Path]] = None,
        env: bool = True,
        config: Optional[Dict[str, Any]] = None,
    ) -> FdmsConfig:
        """
        Load, merge, and resolve configuration from multiple sources
        
        Args:
            file: Path to JSON configuration file (optional)
            env: Whether to load from environment variables (default: True)
            config: Programmatic configuration dictionary (optional)
            
        Returns:
            Fully resolved FdmsConfig object
        """
        sources: list[Dict[str, Any]] = []
        
        # Load from file if specified
        if file is not None:
            sources.append(self.from_file(file))
        
        # Load from environment if enabled
        if env:
            sources.append(self.from_environment())
        
        # Add programmatic config
        if config is not None:
            sources.append(config)
        
        # Merge and resolve
        merged = self.merge(*sources)
        return self.resolve(merged)
    
    def create_template(self, path: Union[str, Path]) -> None:
        """
        Create a configuration template file
        
        Args:
            path: Path to write template
        """
        template = {
            "device_id": "YOUR_DEVICE_ID",
            "device_serial_no": "YOUR_SERIAL_NUMBER",
            "activation_key": "YOUR_ACTIVATION_KEY",
            "device_model_name": "YOUR_MODEL_NAME",
            "device_model_version": "1.0.0",
            "certificate": "./certs/device.pem",
            "private_key": "./certs/device.key",
            "private_key_password": "",
            "environment": "test",
            "timeout": 30000,
            "retry_attempts": 3,
            "retry_delay": 1000,
            "enable_audit_log": True,
            "audit_log_path": "./logs/audit.log",
            "state_store_path": "./data/fiscal-state.json",
        }
        
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(template, f, indent=2)
    
    def _parse_env_value(self, key: str, value: str) -> Any:
        """Parse environment variable value to appropriate type"""
        # Boolean fields
        if key == "enable_audit_log":
            return value.lower() in ("true", "1", "yes")
        
        # Numeric fields
        if key in ("timeout", "retry_attempts", "retry_delay"):
            try:
                return int(value)
            except ValueError:
                return value
        
        # Environment field
        if key == "environment":
            try:
                return FdmsEnvironment(value.lower())
            except ValueError:
                return value
        
        return value
    
    def _process_certificate_paths(
        self, config: Dict[str, Any], base_path: Path
    ) -> Dict[str, Any]:
        """Process certificate paths relative to config file"""
        processed = config.copy()
        
        # Resolve certificate path if it's a relative path
        cert = processed.get("certificate")
        if isinstance(cert, str) and "-----BEGIN" not in cert:
            cert_path = Path(cert)
            if not cert_path.is_absolute():
                processed["certificate"] = str(base_path / cert_path)
        
        # Resolve private key path if it's a relative path
        key = processed.get("private_key")
        if isinstance(key, str) and "-----BEGIN" not in key:
            key_path = Path(key)
            if not key_path.is_absolute():
                processed["private_key"] = str(base_path / key_path)
        
        return processed
    
    def _filter_none(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Filter out None values from config dictionary"""
        return {k: v for k, v in config.items() if v is not None}
