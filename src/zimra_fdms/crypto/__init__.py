"""Cryptography module initialization

This module provides cryptographic services for ZIMRA FDMS integration:
- CertificateManager: X.509 certificate handling
- KeyStore: Secure key storage
- SignatureService: Digital signatures
"""

from zimra_fdms.crypto.signature import (
    SignatureService,
    SignatureServiceOptions,
    SignatureResult,
    VerificationResult as SignatureVerificationResult,
    ReceiptSignatureData,
    ReceiptLineItemData,
    ReceiptTaxData,
    ReceiptPaymentData,
    FiscalDayReportData,
    TaxRateTotalData,
)
from zimra_fdms.crypto.certificate import (
    CertificateManager,
    CertificateInfo,
    CertificateSubject,
    CsrOptions,
    KeyPairOptions,
    ValidationResult,
    CertificateDefaults,
)
from zimra_fdms.crypto.keystore import (
    KeyStore,
    KeyStoreEntry,
    KeyStoreOptions,
    KeyStoreDefaults,
)

__all__ = [
    # Certificate Management
    "CertificateManager",
    "CertificateInfo",
    "CertificateSubject",
    "CsrOptions",
    "KeyPairOptions",
    "ValidationResult",
    "CertificateDefaults",
    # Key Store
    "KeyStore",
    "KeyStoreEntry",
    "KeyStoreOptions",
    "KeyStoreDefaults",
    # Signature Service
    "SignatureService",
    "SignatureServiceOptions",
    "SignatureResult",
    "SignatureVerificationResult",
    "ReceiptSignatureData",
    "ReceiptLineItemData",
    "ReceiptTaxData",
    "ReceiptPaymentData",
    "FiscalDayReportData",
    "TaxRateTotalData",
]
