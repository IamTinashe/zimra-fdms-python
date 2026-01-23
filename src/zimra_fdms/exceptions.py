"""Exception classes for ZIMRA FDMS SDK"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class FdmsErrorCategory(str, Enum):
    """FDMS Error category codes"""
    DEVICE = "DEV"
    VALIDATION = "VAL"
    AUTH = "AUTH"
    NETWORK = "NET"
    CRYPTO = "CRYPTO"
    CONFIG = "CONFIG"
    UNKNOWN = "UNKNOWN"


class FdmsError(Exception):
    """
    Base exception for FDMS errors
    
    All errors in the SDK extend from this class.
    Provides consistent error handling and categorization.
    """
    
    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        cause: Optional[Exception] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.cause = cause
        self.details = details
        self.timestamp = datetime.utcnow()
        self.category = self._determine_category(code)

    def _determine_category(self, code: Optional[str]) -> FdmsErrorCategory:
        """Determine error category from code"""
        if not code:
            return FdmsErrorCategory.UNKNOWN
        
        if code.startswith("DEV"):
            return FdmsErrorCategory.DEVICE
        if code.startswith("VAL"):
            return FdmsErrorCategory.VALIDATION
        if code.startswith("AUTH"):
            return FdmsErrorCategory.AUTH
        if code.startswith("NET"):
            return FdmsErrorCategory.NETWORK
        if code.startswith("CRYPTO"):
            return FdmsErrorCategory.CRYPTO
        if code.startswith("CONFIG"):
            return FdmsErrorCategory.CONFIG
        
        return FdmsErrorCategory.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary"""
        return {
            "name": self.__class__.__name__,
            "message": str(self),
            "code": self.code,
            "status_code": self.status_code,
            "category": self.category.value,
            "timestamp": self.timestamp.isoformat() + "Z",
            "details": self.details,
        }

    def has_code(self, code: str) -> bool:
        """Check if error has a specific code"""
        return self.code == code

    def is_category(self, category: FdmsErrorCategory) -> bool:
        """Check if error belongs to a category"""
        return self.category == category

    def get_description(self) -> str:
        """Get human-readable error description"""
        parts = [str(self)]
        
        if self.code:
            parts.insert(0, f"[{self.code}]")
        
        if self.status_code:
            parts.append(f"(HTTP {self.status_code})")
        
        return " ".join(parts)


class ValidationError(FdmsError):
    """Validation error"""
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="VALIDATION_ERROR", details=details)
        self.field = field


class NetworkError(FdmsError):
    """
    Network error for HTTP transport layer failures
    """
    
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        network_code: str = "NET10",
        retryable: bool = True,
    ) -> None:
        super().__init__(message, code=network_code, status_code=status_code)
        self.network_code = network_code
        self.retryable = retryable

    @classmethod
    def timeout(cls, message: str = "Request timed out") -> "NetworkError":
        """Create a timeout error"""
        return cls(message, status_code=408, network_code="NET01", retryable=True)

    @classmethod
    def connection_refused(
        cls, message: str = "Connection refused"
    ) -> "NetworkError":
        """Create a connection refused error"""
        return cls(message, network_code="NET02", retryable=True)

    @classmethod
    def circuit_breaker_open(cls, retry_after_seconds: int) -> "NetworkError":
        """Create a circuit breaker open error"""
        return cls(
            f"Circuit breaker is open. Retry after {retry_after_seconds} seconds",
            status_code=503,
            network_code="NET05",
            retryable=False,
        )

    @classmethod
    def ssl_error(cls, message: str = "SSL/TLS error") -> "NetworkError":
        """Create an SSL error"""
        return cls(message, network_code="NET04", retryable=False)


class CryptoError(FdmsError):
    """Cryptographic operation error"""
    
    def __init__(
        self,
        message: str,
        code: str = "CRYPTO01",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ConfigError(FdmsError):
    """Configuration error"""
    
    def __init__(
        self,
        message: str,
        code: str = "CONFIG01",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
