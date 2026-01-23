"""
ZIMRA FDMS Integration SDK for Python

Main entry point for the SDK
"""

from zimra_fdms.client import FdmsClient
from zimra_fdms.exceptions import (
    FdmsError,
    ValidationError,
    NetworkError,
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
    "FdmsClient",
    "FdmsError",
    "ValidationError",
    "NetworkError",
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
