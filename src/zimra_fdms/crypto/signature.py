"""
Digital Signature Service
Handles receipt and fiscal day report signing per ZIMRA FDMS specification

This module provides RSA-SHA256 digital signature capabilities for:
- Receipt signing (required for all receipt submissions)
- Fiscal day report signing (required for day close operations)
- Signature verification (for testing and validation)
"""

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509 import load_pem_x509_certificate

from zimra_fdms.exceptions import FdmsError


@dataclass
class ReceiptLineItemData:
    """Line item data for signature generation"""
    line_no: int
    line_description: str
    line_quantity: float
    line_unit_price: float
    line_tax_percent: float
    line_total: float
    hs_code: Optional[str] = None


@dataclass
class ReceiptTaxData:
    """Tax data for signature generation"""
    tax_code: str
    tax_percent: float
    tax_amount: float
    sales_amount_with_tax: float


@dataclass
class ReceiptPaymentData:
    """Payment data for signature generation"""
    money_type_code: int
    payment_amount: float


@dataclass
class ReceiptSignatureData:
    """Receipt data for signature generation"""
    device_id: int
    receipt_type: str
    receipt_currency: str
    receipt_counter: int
    receipt_global_no: int
    invoice_no: str
    receipt_date: str
    receipt_line_items: List[ReceiptLineItemData]
    receipt_taxes: List[ReceiptTaxData]
    receipt_payments: List[ReceiptPaymentData]
    receipt_total: float


@dataclass
class TaxRateTotalData:
    """Tax rate total data for fiscal day signature"""
    tax_percent: float
    tax_amount: float
    sales_amount: Optional[float] = None


@dataclass
class FiscalDayReportData:
    """Fiscal day report data for signature generation"""
    device_id: int
    fiscal_day_no: int
    fiscal_day_opened: str
    receipt_counter: int
    receipt_counter_by_type: Dict[str, int]
    total_amount: float
    total_tax: float
    totals_by_tax_rate: List[TaxRateTotalData]


@dataclass
class SignatureResult:
    """Signature result containing the signature and metadata"""
    signature: str
    data_string: str
    hash: str
    timestamp: datetime
    algorithm: str = "RSA-SHA256"


@dataclass
class VerificationResult:
    """Signature verification result"""
    valid: bool
    error: Optional[str] = None
    data_string: Optional[str] = None


@dataclass
class SignatureServiceOptions:
    """
    Signature service configuration options
    
    Attributes:
        private_key: Private key in PEM format (str or bytes)
        private_key_password: Password for encrypted private key
        public_key: Public key or certificate for verification (optional)
        enable_cache: Enable signature caching to avoid re-signing identical data
        max_cache_size: Maximum cache size (default: 1000)
    """
    private_key: Optional[Union[str, bytes]] = None
    private_key_password: Optional[str] = None
    public_key: Optional[Union[str, bytes]] = None
    enable_cache: bool = False
    max_cache_size: int = 1000


class SignatureService:
    """
    Digital Signature Service for ZIMRA FDMS
    
    Provides RSA-SHA256 digital signature generation and verification
    for receipts and fiscal day reports according to ZIMRA FDMS specification.
    
    Example:
        >>> service = SignatureService(SignatureServiceOptions(
        ...     private_key=open('./device-key.pem').read(),
        ...     private_key_password='key-password'
        ... ))
        >>> 
        >>> # Sign a receipt
        >>> result = service.sign_receipt(ReceiptSignatureData(
        ...     device_id=12345,
        ...     receipt_type='FiscalInvoice',
        ...     receipt_currency='USD',
        ...     receipt_counter=1,
        ...     receipt_global_no=100,
        ...     invoice_no='INV-001',
        ...     receipt_date='2025-01-26T10:00:00Z',
        ...     receipt_line_items=[...],
        ...     receipt_taxes=[...],
        ...     receipt_payments=[...],
        ...     receipt_total=1150.00
        ... ))
        >>> 
        >>> print('Signature:', result.signature)
    """
    
    def __init__(self, options: SignatureServiceOptions):
        """
        Create a new SignatureService instance
        
        Args:
            options: Configuration options
            
        Raises:
            FdmsError: If private key cannot be loaded
        """
        self._private_key: Optional[RSAPrivateKey] = None
        self._public_key: Optional[RSAPublicKey] = None
        self._cache: Dict[str, SignatureResult] = {}
        self._enable_cache = options.enable_cache
        self._max_cache_size = options.max_cache_size
        
        # Load private key
        if options.private_key:
            self.load_private_key(options.private_key, options.private_key_password)
        
        # Load public key if provided
        if options.public_key:
            self.load_public_key(options.public_key)
    
    def load_private_key(
        self,
        key: Union[str, bytes],
        password: Optional[str] = None
    ) -> None:
        """
        Load a private key for signing
        
        Args:
            key: Private key in PEM format
            password: Password for encrypted keys
            
        Raises:
            FdmsError: If key cannot be loaded
        """
        try:
            key_data = key.encode('utf-8') if isinstance(key, str) else key
            password_bytes = password.encode('utf-8') if password else None
            
            self._private_key = serialization.load_pem_private_key(
                key_data,
                password=password_bytes,
                backend=default_backend()
            )
            
            # Extract public key from private key for verification
            self._public_key = self._private_key.public_key()
            
        except Exception as e:
            raise FdmsError(
                f"Failed to load private key: {str(e)}",
                code="CRYPTO30"
            )
    
    def load_public_key(self, key: Union[str, bytes]) -> None:
        """
        Load a public key or certificate for verification
        
        Args:
            key: Public key or certificate in PEM format
            
        Raises:
            FdmsError: If key cannot be loaded
        """
        try:
            key_data = key.encode('utf-8') if isinstance(key, str) else key
            
            # Check if it's a certificate or public key
            if b'CERTIFICATE' in key_data:
                cert = load_pem_x509_certificate(key_data, default_backend())
                self._public_key = cert.public_key()
            else:
                self._public_key = serialization.load_pem_public_key(
                    key_data,
                    backend=default_backend()
                )
                
        except Exception as e:
            raise FdmsError(
                f"Failed to load public key: {str(e)}",
                code="CRYPTO31"
            )
    
    def sign_receipt(self, data: ReceiptSignatureData) -> SignatureResult:
        """
        Sign receipt data according to ZIMRA FDMS specification
        
        The signature is generated by:
        1. Preparing a data string with all receipt fields in specific order
        2. Computing SHA-256 hash of the data string
        3. Signing the hash with RSA private key
        4. Encoding the signature as Base64
        
        Args:
            data: Receipt data to sign
            
        Returns:
            Signature result with Base64-encoded signature
            
        Raises:
            FdmsError: If signing fails
        """
        if not self._private_key:
            raise FdmsError("Private key not loaded", code="CRYPTO32")
        
        # Prepare data string
        data_string = self.prepare_receipt_data_string(data)
        
        # Check cache
        if self._enable_cache and data_string in self._cache:
            return self._cache[data_string]
        
        # Sign the data
        result = self._sign(data_string)
        
        # Cache result
        if self._enable_cache:
            self._add_to_cache(data_string, result)
        
        return result
    
    def sign_fiscal_day_report(self, data: FiscalDayReportData) -> SignatureResult:
        """
        Sign fiscal day report data according to ZIMRA FDMS specification
        
        Args:
            data: Fiscal day report data to sign
            
        Returns:
            Signature result with Base64-encoded signature
            
        Raises:
            FdmsError: If signing fails
        """
        if not self._private_key:
            raise FdmsError("Private key not loaded", code="CRYPTO32")
        
        # Prepare data string
        data_string = self.prepare_fiscal_day_data_string(data)
        
        # Check cache
        if self._enable_cache and data_string in self._cache:
            return self._cache[data_string]
        
        # Sign the data
        result = self._sign(data_string)
        
        # Cache result
        if self._enable_cache:
            self._add_to_cache(data_string, result)
        
        return result
    
    def sign_data(self, data_string: str) -> SignatureResult:
        """
        Sign arbitrary data string
        
        Args:
            data_string: Data string to sign
            
        Returns:
            Signature result
            
        Raises:
            FdmsError: If signing fails
        """
        if not self._private_key:
            raise FdmsError("Private key not loaded", code="CRYPTO32")
        
        return self._sign(data_string)
    
    def verify_receipt_signature(
        self,
        data: ReceiptSignatureData,
        signature: str
    ) -> VerificationResult:
        """
        Verify a receipt signature
        
        Args:
            data: Receipt data that was signed
            signature: Base64-encoded signature to verify
            
        Returns:
            Verification result
        """
        data_string = self.prepare_receipt_data_string(data)
        return self._verify(data_string, signature)
    
    def verify_fiscal_day_signature(
        self,
        data: FiscalDayReportData,
        signature: str
    ) -> VerificationResult:
        """
        Verify a fiscal day report signature
        
        Args:
            data: Fiscal day report data that was signed
            signature: Base64-encoded signature to verify
            
        Returns:
            Verification result
        """
        data_string = self.prepare_fiscal_day_data_string(data)
        return self._verify(data_string, signature)
    
    def verify_signature(
        self,
        data_string: str,
        signature: str
    ) -> VerificationResult:
        """
        Verify a signature against arbitrary data
        
        Args:
            data_string: Data string that was signed
            signature: Base64-encoded signature to verify
            
        Returns:
            Verification result
        """
        return self._verify(data_string, signature)
    
    def prepare_receipt_data_string(self, data: ReceiptSignatureData) -> str:
        """
        Prepare the data string for receipt signing
        
        The data string is constructed by concatenating receipt fields
        in a specific order with newline separators, as specified by ZIMRA.
        
        Args:
            data: Receipt data
            
        Returns:
            Prepared data string
        """
        parts: List[str] = []
        
        # Device identification
        parts.append(str(data.device_id))
        parts.append(data.receipt_type)
        parts.append(data.receipt_currency)
        parts.append(str(data.receipt_counter))
        parts.append(str(data.receipt_global_no))
        parts.append(data.invoice_no)
        parts.append(data.receipt_date)
        
        # Line items (sorted by line number)
        sorted_items = sorted(data.receipt_line_items, key=lambda x: x.line_no)
        for item in sorted_items:
            parts.append(self._format_line_item(item))
        
        # Tax summaries (sorted by tax code)
        sorted_taxes = sorted(data.receipt_taxes, key=lambda x: x.tax_code)
        for tax in sorted_taxes:
            parts.append(self._format_tax(tax))
        
        # Payments (sorted by money type code)
        sorted_payments = sorted(data.receipt_payments, key=lambda x: x.money_type_code)
        for payment in sorted_payments:
            parts.append(self._format_payment(payment))
        
        # Total
        parts.append(self._format_amount(data.receipt_total))
        
        return '\n'.join(parts)
    
    def prepare_fiscal_day_data_string(self, data: FiscalDayReportData) -> str:
        """
        Prepare the data string for fiscal day report signing
        
        Args:
            data: Fiscal day report data
            
        Returns:
            Prepared data string
        """
        parts: List[str] = []
        
        # Device and day identification
        parts.append(str(data.device_id))
        parts.append(str(data.fiscal_day_no))
        parts.append(data.fiscal_day_opened)
        
        # Counters
        parts.append(str(data.receipt_counter))
        
        # Receipt counters by type (sorted by type name)
        sorted_types = sorted(data.receipt_counter_by_type.items())
        for type_name, count in sorted_types:
            parts.append(f"{type_name}:{count}")
        
        # Totals
        parts.append(self._format_amount(data.total_amount))
        parts.append(self._format_amount(data.total_tax))
        
        # Tax rate totals (sorted by tax percent)
        sorted_rates = sorted(data.totals_by_tax_rate, key=lambda x: x.tax_percent)
        for rate in sorted_rates:
            parts.append(f"{self._format_amount(rate.tax_percent)}:{self._format_amount(rate.tax_amount)}")
        
        return '\n'.join(parts)
    
    def get_data_hash(self, data_string: str) -> str:
        """
        Get the hash of a data string (for debugging/verification)
        
        Args:
            data_string: Data string to hash
            
        Returns:
            SHA-256 hash in hexadecimal format
        """
        return hashlib.sha256(data_string.encode('utf-8')).hexdigest()
    
    def clear_cache(self) -> None:
        """Clear the signature cache"""
        self._cache.clear()
    
    def get_cache_size(self) -> int:
        """Get current cache size"""
        return len(self._cache)
    
    def has_private_key(self) -> bool:
        """Check if the service has a private key loaded"""
        return self._private_key is not None
    
    def has_public_key(self) -> bool:
        """Check if the service has a public key loaded"""
        return self._public_key is not None
    
    # Private methods
    
    def _sign(self, data_string: str) -> SignatureResult:
        """Perform the actual signing operation"""
        try:
            # Sign with RSA-SHA256
            signature_bytes = self._private_key.sign(
                data_string.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Encode as Base64
            signature = base64.b64encode(signature_bytes).decode('utf-8')
            
            # Compute hash for reference
            hash_hex = self.get_data_hash(data_string)
            
            return SignatureResult(
                signature=signature,
                data_string=data_string,
                hash=hash_hex,
                timestamp=datetime.now(),
                algorithm="RSA-SHA256"
            )
            
        except Exception as e:
            raise FdmsError(
                f"Failed to sign data: {str(e)}",
                code="CRYPTO33"
            )
    
    def _verify(self, data_string: str, signature: str) -> VerificationResult:
        """Perform signature verification"""
        if not self._public_key:
            return VerificationResult(
                valid=False,
                error="Public key not loaded for verification"
            )
        
        try:
            # Decode signature from Base64
            signature_bytes = base64.b64decode(signature)
            
            # Verify with RSA-SHA256
            self._public_key.verify(
                signature_bytes,
                data_string.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return VerificationResult(
                valid=True,
                data_string=data_string
            )
            
        except Exception as e:
            return VerificationResult(
                valid=False,
                error=f"Verification failed: {str(e)}",
                data_string=data_string
            )
    
    def _add_to_cache(self, key: str, result: SignatureResult) -> None:
        """Add result to cache with LRU eviction"""
        # Evict oldest entries if cache is full
        if len(self._cache) >= self._max_cache_size:
            # Remove first item (oldest)
            first_key = next(iter(self._cache))
            del self._cache[first_key]
        
        self._cache[key] = result
    
    def _format_line_item(self, item: ReceiptLineItemData) -> str:
        """Format a line item for the data string"""
        parts = [
            str(item.line_no),
            item.line_description,
            self._format_quantity(item.line_quantity),
            self._format_amount(item.line_unit_price),
            self._format_amount(item.line_tax_percent),
            self._format_amount(item.line_total)
        ]
        
        if item.hs_code:
            parts.append(item.hs_code)
        
        return '|'.join(parts)
    
    def _format_tax(self, tax: ReceiptTaxData) -> str:
        """Format a tax entry for the data string"""
        return '|'.join([
            tax.tax_code,
            self._format_amount(tax.tax_percent),
            self._format_amount(tax.tax_amount),
            self._format_amount(tax.sales_amount_with_tax)
        ])
    
    def _format_payment(self, payment: ReceiptPaymentData) -> str:
        """Format a payment entry for the data string"""
        return '|'.join([
            str(payment.money_type_code),
            self._format_amount(payment.payment_amount)
        ])
    
    def _format_amount(self, amount: float) -> str:
        """Format amount with consistent decimal places"""
        return f"{amount:.2f}"
    
    def _format_quantity(self, quantity: float) -> str:
        """Format quantity with appropriate decimal places"""
        # Use up to 4 decimal places for quantity, removing trailing zeros
        formatted = f"{quantity:.4f}".rstrip('0').rstrip('.')
        return formatted if formatted else "0"
