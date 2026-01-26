"""Cryptography module initialization

This module provides cryptographic services for ZIMRA FDMS integration:
- CertificateManager: X.509 certificate handling
- KeyStore: Secure key storage
- SignatureService: Digital signatures (Phase 3.2)
"""

from zimra_fdms.crypto.signature import SignatureService
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
    # Signature Service (Phase 3.2)
    "SignatureService",
]
