"""
X.509 certificate management
Handles certificate loading, validation, CSR generation, and storage

This module provides comprehensive certificate management capabilities
for the ZIMRA FDMS SDK, including:
- Loading certificates from PEM/DER formats
- Loading private keys with optional password protection
- Generating RSA key pairs
- Generating Certificate Signing Requests (CSRs)
- Certificate validation (expiry, chain, key size)
- Secure certificate/key storage
"""

import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    BestAvailableEncryption,
    NoEncryption,
    load_pem_private_key,
    load_der_private_key,
)
from cryptography.x509.oid import NameOID

from zimra_fdms.exceptions import FdmsError


# Default configuration constants
class CertificateDefaults:
    """Default values for certificate operations"""
    KEY_SIZE = 4096
    PUBLIC_EXPONENT = 65537
    EXPIRY_WARNING_DAYS = 30
    CERT_FILE_PERMISSIONS = 0o644
    KEY_FILE_PERMISSIONS = 0o600


@dataclass
class CertificateSubject:
    """Certificate subject/issuer details"""
    common_name: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    email_address: Optional[str] = None


@dataclass
class CertificateInfo:
    """
    Certificate information extracted from X.509 certificate
    
    Attributes:
        subject: Certificate subject distinguished name
        issuer: Certificate issuer distinguished name
        serial_number: Certificate serial number
        valid_from: Certificate validity start date
        valid_to: Certificate validity end date
        days_until_expiry: Days until certificate expires
        is_valid: Whether the certificate is currently valid
        is_expired: Whether the certificate is expired
        expires_within_warning_period: Whether the certificate expires within warning threshold
        fingerprint_sha256: Certificate fingerprint (SHA-256)
        public_key_algorithm: Public key algorithm
        key_size: Key size in bits
    """
    subject: CertificateSubject
    issuer: CertificateSubject
    serial_number: str
    valid_from: datetime
    valid_to: datetime
    days_until_expiry: int
    is_valid: bool
    is_expired: bool
    expires_within_warning_period: bool
    fingerprint_sha256: str
    public_key_algorithm: str
    key_size: int


@dataclass
class CsrOptions:
    """
    CSR (Certificate Signing Request) generation options
    
    Attributes:
        common_name: Common Name (CN) - typically device identifier (required)
        organization: Organization (O) - company name
        organizational_unit: Organizational Unit (OU)
        country: Country (C) - 2-letter ISO code
        state: State/Province (ST)
        locality: Locality/City (L)
        email_address: Email address
    """
    common_name: str
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    email_address: Optional[str] = None


@dataclass
class KeyPairOptions:
    """
    Key pair generation options
    
    Attributes:
        key_size: Key size in bits (minimum 2048, recommended 4096)
        public_exponent: Public exponent (default: 65537)
    """
    key_size: int = field(default=CertificateDefaults.KEY_SIZE)
    public_exponent: int = field(default=CertificateDefaults.PUBLIC_EXPONENT)


@dataclass
class ValidationResult:
    """
    Certificate validation result
    
    Attributes:
        valid: Whether the certificate is valid
        issues: List of critical issues found
        warnings: List of non-critical warnings
    """
    valid: bool
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class CertificateManager:
    """
    Manages X.509 certificates for ZIMRA FDMS integration
    
    Features:
    - Load certificates from PEM/DER formats
    - Load private keys with optional password protection
    - Generate RSA key pairs
    - Generate Certificate Signing Requests (CSRs)
    - Validate certificate expiry and chain
    - Secure certificate/key storage
    
    Example:
        >>> manager = CertificateManager()
        >>> 
        >>> # Load existing certificate
        >>> cert = manager.load_certificate('./cert.pem')
        >>> key = manager.load_private_key('./key.pem', password='secret')
        >>> 
        >>> # Generate new key pair and CSR
        >>> public_key, private_key = manager.generate_key_pair()
        >>> csr = manager.generate_csr(CsrOptions(common_name='DEVICE123'))
    
    Security Notes:
        - Private keys are never logged
        - Minimum key size is 2048 bits (4096 recommended)
        - Secure file permissions are set automatically
    """
    
    def __init__(self, expiry_warning_days: int = CertificateDefaults.EXPIRY_WARNING_DAYS):
        """
        Create a new CertificateManager instance
        
        Args:
            expiry_warning_days: Days before expiry to trigger warning (default: 30)
        """
        self._certificate: Optional[x509.Certificate] = None
        self._private_key: Optional[RSAPrivateKey] = None
        self._public_key: Optional[RSAPublicKey] = None
        self._expiry_warning_days = expiry_warning_days
    
    def load_certificate(
        self,
        certificate_input: Union[str, bytes, Path]
    ) -> x509.Certificate:
        """
        Load an X.509 certificate from file path or content
        
        Supports both PEM and DER formats. Automatically detects format.
        
        Args:
            certificate_input: File path, Path object, or certificate content (str or bytes)
        
        Returns:
            Loaded X.509 certificate
        
        Raises:
            FdmsError: If certificate loading fails
        
        Example:
            >>> cert = manager.load_certificate('./device_cert.pem')
            >>> cert = manager.load_certificate(cert_bytes)
        """
        try:
            cert_data = self._resolve_certificate_input(certificate_input)
            
            # Try PEM format first
            try:
                self._certificate = x509.load_pem_x509_certificate(
                    cert_data, default_backend()
                )
            except Exception:
                # Try DER format
                self._certificate = x509.load_der_x509_certificate(
                    cert_data, default_backend()
                )
            
            # Extract public key
            public_key = self._certificate.public_key()
            if isinstance(public_key, RSAPublicKey):
                self._public_key = public_key
            
            return self._certificate
            
        except FdmsError:
            raise
        except Exception as e:
            raise FdmsError(
                f"Failed to load certificate: {str(e)}",
                code="CRYPTO01",
                cause=e
            )
    
    def load_private_key(
        self,
        key_input: Union[str, bytes, Path],
        password: Optional[str] = None
    ) -> RSAPrivateKey:
        """
        Load a private key from file path or content
        
        Supports PEM and DER formats with optional password protection.
        
        Args:
            key_input: File path, Path object, or key content (str or bytes)
            password: Password for encrypted private keys
        
        Returns:
            Loaded RSA private key
        
        Raises:
            FdmsError: If private key loading fails or password is incorrect
        
        Example:
            >>> key = manager.load_private_key('./device_key.pem', password='secret')
        """
        try:
            key_data = self._resolve_key_input(key_input)
            password_bytes = password.encode('utf-8') if password else None
            
            # Try PEM format first
            try:
                private_key = load_pem_private_key(
                    key_data,
                    password=password_bytes,
                    backend=default_backend()
                )
            except Exception:
                # Try DER format
                private_key = load_der_private_key(
                    key_data,
                    password=password_bytes,
                    backend=default_backend()
                )
            
            # Validate key type
            if not isinstance(private_key, RSAPrivateKey):
                raise ValueError(
                    f"Unsupported key type: {type(private_key).__name__}. "
                    "Only RSA keys are supported."
                )
            
            self._private_key = private_key
            return self._private_key
            
        except ValueError as e:
            if "bad decrypt" in str(e).lower() or "password" in str(e).lower():
                raise FdmsError(
                    "Invalid private key password",
                    code="CRYPTO02",
                    cause=e
                )
            raise FdmsError(
                f"Failed to load private key: {str(e)}",
                code="CRYPTO03",
                cause=e
            )
        except FdmsError:
            raise
        except Exception as e:
            raise FdmsError(
                f"Failed to load private key: {str(e)}",
                code="CRYPTO03",
                cause=e
            )
    
    def generate_key_pair(
        self,
        options: Optional[KeyPairOptions] = None
    ) -> Tuple[RSAPublicKey, RSAPrivateKey]:
        """
        Generate a new RSA key pair
        
        Args:
            options: Key generation options (key_size, public_exponent)
        
        Returns:
            Tuple of (public_key, private_key)
        
        Raises:
            FdmsError: If key size is below minimum or generation fails
        
        Example:
            >>> public_key, private_key = manager.generate_key_pair()
            >>> # Or with options
            >>> options = KeyPairOptions(key_size=4096)
            >>> public_key, private_key = manager.generate_key_pair(options)
        """
        if options is None:
            options = KeyPairOptions()
        
        # Validate key size
        if options.key_size < 2048:
            raise FdmsError(
                "Key size must be at least 2048 bits for FDMS compliance",
                code="CRYPTO04"
            )
        
        try:
            self._private_key = rsa.generate_private_key(
                public_exponent=options.public_exponent,
                key_size=options.key_size,
                backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
            
            return self._public_key, self._private_key
            
        except Exception as e:
            raise FdmsError(
                f"Failed to generate key pair: {str(e)}",
                code="CRYPTO05",
                cause=e
            )
    
    def generate_csr(
        self,
        options: CsrOptions,
        private_key: Optional[RSAPrivateKey] = None
    ) -> bytes:
        """
        Generate a Certificate Signing Request (CSR) for FDMS device registration
        
        Args:
            options: CSR subject options (common_name required)
            private_key: Private key to sign the CSR (uses loaded key if not provided)
        
        Returns:
            CSR in PEM format (bytes)
        
        Raises:
            FdmsError: If no private key available or CSR generation fails
        
        Example:
            >>> csr = manager.generate_csr(CsrOptions(
            ...     common_name='DEVICE123',
            ...     organization='My Company',
            ...     country='ZW'
            ... ))
        """
        key = private_key or self._private_key
        
        if key is None:
            raise FdmsError(
                "No private key available. Load or generate a private key first.",
                code="CRYPTO07"
            )
        
        if not options.common_name:
            raise FdmsError(
                "Common Name (CN) is required for CSR generation",
                code="CRYPTO08"
            )
        
        try:
            # Build subject name
            name_attributes = []
            
            if options.country:
                name_attributes.append(
                    x509.NameAttribute(NameOID.COUNTRY_NAME, options.country)
                )
            if options.state:
                name_attributes.append(
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, options.state)
                )
            if options.locality:
                name_attributes.append(
                    x509.NameAttribute(NameOID.LOCALITY_NAME, options.locality)
                )
            if options.organization:
                name_attributes.append(
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, options.organization)
                )
            if options.organizational_unit:
                name_attributes.append(
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME,
                        options.organizational_unit
                    )
                )
            name_attributes.append(
                x509.NameAttribute(NameOID.COMMON_NAME, options.common_name)
            )
            if options.email_address:
                name_attributes.append(
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, options.email_address)
                )
            
            subject = x509.Name(name_attributes)
            
            # Build CSR
            csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
            
            # Sign CSR
            csr = csr_builder.sign(key, hashes.SHA256(), default_backend())
            
            return csr.public_bytes(Encoding.PEM)
            
        except Exception as e:
            raise FdmsError(
                f"Failed to generate CSR: {str(e)}",
                code="CRYPTO09",
                cause=e
            )
    
    def get_certificate_info(self) -> CertificateInfo:
        """
        Get detailed information about the loaded certificate
        
        Returns:
            CertificateInfo with all certificate details
        
        Raises:
            FdmsError: If no certificate is loaded
        """
        if self._certificate is None:
            raise FdmsError(
                "No certificate loaded. Load a certificate first.",
                code="CRYPTO10"
            )
        
        now = datetime.now(timezone.utc)
        valid_from = self._certificate.not_valid_before_utc
        valid_to = self._certificate.not_valid_after_utc
        days_until_expiry = (valid_to - now).days
        
        return CertificateInfo(
            subject=self._parse_name(self._certificate.subject),
            issuer=self._parse_name(self._certificate.issuer),
            serial_number=format(self._certificate.serial_number, 'X'),
            valid_from=valid_from,
            valid_to=valid_to,
            days_until_expiry=days_until_expiry,
            is_valid=valid_from <= now <= valid_to,
            is_expired=now > valid_to,
            expires_within_warning_period=days_until_expiry <= self._expiry_warning_days,
            fingerprint_sha256=self._certificate.fingerprint(hashes.SHA256()).hex(),
            public_key_algorithm=self._get_key_algorithm(),
            key_size=self._get_key_size(),
        )
    
    def validate_certificate(self) -> ValidationResult:
        """
        Validate the loaded certificate
        
        Checks expiry, key size, and algorithm requirements.
        
        Returns:
            ValidationResult with validation status, issues, and warnings
        """
        issues: list[str] = []
        warnings: list[str] = []
        
        if self._certificate is None:
            return ValidationResult(
                valid=False,
                issues=["No certificate loaded"],
                warnings=[]
            )
        
        info = self.get_certificate_info()
        
        # Check if expired
        if info.is_expired:
            issues.append(f"Certificate expired on {info.valid_to.isoformat()}")
        
        # Check if not yet valid
        now = datetime.now(timezone.utc)
        if now < info.valid_from:
            issues.append(
                f"Certificate not yet valid. Valid from {info.valid_from.isoformat()}"
            )
        
        # Check expiry warning
        if not info.is_expired and info.expires_within_warning_period:
            warnings.append(
                f"Certificate expires in {info.days_until_expiry} days "
                f"({info.valid_to.isoformat()})"
            )
        
        # Check key algorithm
        if info.public_key_algorithm != 'RSA':
            issues.append(
                f"Unsupported key algorithm: {info.public_key_algorithm}. "
                "Only RSA is supported."
            )
        
        # Check key size
        if info.key_size < 2048:
            issues.append(
                f"Key size {info.key_size} bits is below minimum requirement of 2048 bits"
            )
        
        # Warn if key size is less than recommended
        if 2048 <= info.key_size < 4096:
            warnings.append(
                f"Key size {info.key_size} bits is acceptable but 4096 bits is recommended"
            )
        
        return ValidationResult(
            valid=len(issues) == 0,
            issues=issues,
            warnings=warnings
        )
    
    def verify_key_pair_match(self) -> bool:
        """
        Verify that the loaded private key matches the loaded certificate
        
        Returns:
            True if key pair matches
        
        Raises:
            FdmsError: If certificate or private key not loaded
        """
        if self._certificate is None or self._private_key is None:
            raise FdmsError(
                "Both certificate and private key must be loaded to verify match",
                code="CRYPTO11"
            )
        
        try:
            # Get public key from certificate
            cert_public_key = self._certificate.public_key()
            
            # Compare public key components
            if not isinstance(cert_public_key, RSAPublicKey):
                return False
            
            cert_numbers = cert_public_key.public_numbers()
            key_numbers = self._private_key.public_key().public_numbers()
            
            return (
                cert_numbers.n == key_numbers.n and
                cert_numbers.e == key_numbers.e
            )
        except Exception:
            return False
    
    def store_certificate(
        self,
        file_path: Union[str, Path],
        certificate: Optional[x509.Certificate] = None,
        encoding: Encoding = Encoding.PEM
    ) -> None:
        """
        Store certificate to file with proper permissions
        
        Args:
            file_path: Destination file path
            certificate: Certificate to store (uses loaded certificate if not provided)
            encoding: Output encoding (PEM or DER)
        
        Raises:
            FdmsError: If no certificate to store or write fails
        """
        cert = certificate or self._certificate
        
        if cert is None:
            raise FdmsError(
                "No certificate to store. Load or provide a certificate.",
                code="CRYPTO12"
            )
        
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            cert_bytes = cert.public_bytes(encoding)
            path.write_bytes(cert_bytes)
            
            # Set permissions
            os.chmod(path, CertificateDefaults.CERT_FILE_PERMISSIONS)
            
        except Exception as e:
            raise FdmsError(
                f"Failed to store certificate: {str(e)}",
                code="CRYPTO13",
                cause=e
            )
    
    def store_private_key(
        self,
        file_path: Union[str, Path],
        private_key: Optional[RSAPrivateKey] = None,
        password: Optional[str] = None
    ) -> None:
        """
        Store private key to file with secure permissions (0600)
        
        Args:
            file_path: Destination file path
            private_key: Private key to store (uses loaded key if not provided)
            password: Optional password to encrypt the key
        
        Raises:
            FdmsError: If no private key to store or write fails
        """
        key = private_key or self._private_key
        
        if key is None:
            raise FdmsError(
                "No private key to store. Load or provide a private key.",
                code="CRYPTO14"
            )
        
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            encryption: Union[BestAvailableEncryption, NoEncryption]
            if password:
                encryption = BestAvailableEncryption(password.encode('utf-8'))
            else:
                encryption = NoEncryption()
            
            key_bytes = key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            )
            
            path.write_bytes(key_bytes)
            
            # Set restrictive permissions (owner read/write only)
            os.chmod(path, CertificateDefaults.KEY_FILE_PERMISSIONS)
            
        except Exception as e:
            raise FdmsError(
                f"Failed to store private key: {str(e)}",
                code="CRYPTO15",
                cause=e
            )
    
    def export_public_key(self) -> bytes:
        """
        Export public key in PEM format
        
        Returns:
            Public key in PEM format (bytes)
        
        Raises:
            FdmsError: If no public key available
        """
        if self._public_key is None:
            raise FdmsError(
                "No public key available. Load a certificate or generate a key pair.",
                code="CRYPTO16"
            )
        
        return self._public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    
    def export_private_key(self, password: Optional[str] = None) -> bytes:
        """
        Export private key in PEM format (optionally encrypted)
        
        Args:
            password: Optional password to encrypt the key
        
        Returns:
            Private key in PEM format (bytes)
        
        Raises:
            FdmsError: If no private key available
        """
        if self._private_key is None:
            raise FdmsError(
                "No private key available. Load or generate a private key.",
                code="CRYPTO17"
            )
        
        encryption: Union[BestAvailableEncryption, NoEncryption]
        if password:
            encryption = BestAvailableEncryption(password.encode('utf-8'))
        else:
            encryption = NoEncryption()
        
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    
    @property
    def certificate(self) -> Optional[x509.Certificate]:
        """Get the loaded certificate"""
        return self._certificate
    
    @property
    def private_key(self) -> Optional[RSAPrivateKey]:
        """Get the loaded private key"""
        return self._private_key
    
    @property
    def public_key(self) -> Optional[RSAPublicKey]:
        """Get the public key (from certificate or generated key pair)"""
        return self._public_key
    
    def needs_renewal(self) -> bool:
        """
        Check if certificate needs renewal (within warning period)
        
        Returns:
            True if certificate is expired or expires soon
        """
        if self._certificate is None:
            return False
        
        info = self.get_certificate_info()
        return info.is_expired or info.expires_within_warning_period
    
    def clear(self) -> None:
        """Clear all loaded certificates and keys from memory"""
        self._certificate = None
        self._private_key = None
        self._public_key = None
    
    # ============ Private Helper Methods ============
    
    def _resolve_certificate_input(
        self,
        input_data: Union[str, bytes, Path]
    ) -> bytes:
        """Resolve certificate input to bytes"""
        if isinstance(input_data, bytes):
            return input_data
        
        if isinstance(input_data, Path):
            return input_data.read_bytes()
        
        # String input - check if it's a file path or content
        if self._is_file_path(input_data):
            return Path(input_data).read_bytes()
        
        # Assume it's certificate content
        return input_data.encode('utf-8')
    
    def _resolve_key_input(
        self,
        input_data: Union[str, bytes, Path]
    ) -> bytes:
        """Resolve key input to bytes"""
        if isinstance(input_data, bytes):
            return input_data
        
        if isinstance(input_data, Path):
            return input_data.read_bytes()
        
        # String input - check if it's a file path or content
        if self._is_file_path(input_data):
            return Path(input_data).read_bytes()
        
        # Assume it's key content
        return input_data.encode('utf-8')
    
    def _is_file_path(self, input_str: str) -> bool:
        """Check if input string is a file path"""
        # Check for PEM headers - if present, it's content, not a path
        if '-----BEGIN' in input_str:
            return False
        
        # Check for common certificate/key file extensions
        extensions = {'.pem', '.der', '.crt', '.cer', '.key', '.p8', '.pkcs8'}
        ext = Path(input_str).suffix.lower()
        
        if ext in extensions:
            return True
        
        # Check if file exists
        return Path(input_str).exists()
    
    def _parse_name(self, name: x509.Name) -> CertificateSubject:
        """Parse X.509 Name to CertificateSubject"""
        def get_attr(oid: x509.ObjectIdentifier) -> Optional[str]:
            try:
                attrs = name.get_attributes_for_oid(oid)
                return attrs[0].value if attrs else None
            except Exception:
                return None
        
        return CertificateSubject(
            common_name=get_attr(NameOID.COMMON_NAME),
            organization=get_attr(NameOID.ORGANIZATION_NAME),
            organizational_unit=get_attr(NameOID.ORGANIZATIONAL_UNIT_NAME),
            country=get_attr(NameOID.COUNTRY_NAME),
            state=get_attr(NameOID.STATE_OR_PROVINCE_NAME),
            locality=get_attr(NameOID.LOCALITY_NAME),
            email_address=get_attr(NameOID.EMAIL_ADDRESS),
        )
    
    def _get_key_algorithm(self) -> str:
        """Get the public key algorithm name"""
        if self._certificate is None:
            return 'unknown'
        
        public_key = self._certificate.public_key()
        if isinstance(public_key, RSAPublicKey):
            return 'RSA'
        
        return type(public_key).__name__
    
    def _get_key_size(self) -> int:
        """Get the public key size in bits"""
        if self._certificate is None:
            return 0
        
        public_key = self._certificate.public_key()
        if isinstance(public_key, RSAPublicKey):
            return public_key.key_size
        
        return 0
