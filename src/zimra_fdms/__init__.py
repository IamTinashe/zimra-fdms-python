"""
ZIMRA FDMS Integration SDK for Python

Main entry point for the SDK
"""

from zimra_fdms.client import FdmsClient
from zimra_fdms.exceptions import (
    FdmsError,
    FdmsErrorCategory,
    ValidationError,
    NetworkError,
    CryptoError,
    ConfigError,
)

# HTTP Client
from zimra_fdms.client import (
    HttpClient,
    HttpMethod,
    HttpRequestOptions,
    HttpResponse,
    HttpAuditEntry,
    CircuitState,
    CircuitBreakerConfig,
    NetworkErrorCode,
)

# Configuration
from zimra_fdms.config import (
    FdmsConfig,
    PartialFdmsConfig,
    FdmsEnvironment,
    ConfigLoader,
    ConfigValidator,
    FDMS_BASE_URLS,
    ENV_VAR_MAPPING,
    ConfigDefaults,
)

# Models
from zimra_fdms.models import (
    Device,
    Receipt,
    ReceiptLineItem,
    ReceiptTax,
    ReceiptPayment,
    BuyerData,
    FiscalDay,
    FiscalDayCounters,
    FiscalDayTotals,
    TaxRate,
)

__version__ = "0.1.0"

__all__ = [
    # Client
    "FdmsClient",
    # HTTP Client
    "HttpClient",
    "HttpMethod",
    "HttpRequestOptions",
    "HttpResponse",
    "HttpAuditEntry",
    "CircuitState",
    "CircuitBreakerConfig",
    "NetworkErrorCode",
    # Exceptions
    "FdmsError",
    "FdmsErrorCategory",
    "ValidationError",
    "NetworkError",
    "CryptoError",
    "ConfigError",
    # Configuration
    "FdmsConfig",
    "PartialFdmsConfig",
    "FdmsEnvironment",
    "ConfigLoader",
    "ConfigValidator",
    "FDMS_BASE_URLS",
    "ENV_VAR_MAPPING",
    "ConfigDefaults",
    # Models
    "Device",
    "Receipt",
    "ReceiptLineItem",
    "ReceiptTax",
    "ReceiptPayment",
    "BuyerData",
    "FiscalDay",
    "FiscalDayCounters",
    "FiscalDayTotals",
    "TaxRate",
]
