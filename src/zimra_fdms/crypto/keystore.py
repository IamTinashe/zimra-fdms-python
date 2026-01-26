"""
Secure key storage
Manages private keys with proper security practices

This module provides secure storage for private keys and certificates
using industry-standard encryption (AES-256-GCM) and key derivation (PBKDF2).
"""

import json
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from zimra_fdms.exceptions import FdmsError


# Default configuration constants
class KeyStoreDefaults:
    """Default values for key store operations"""
    VERSION = 1
    ITERATIONS = 100000
    KEY_LENGTH = 32
    SALT_LENGTH = 32
    NONCE_LENGTH = 12
    FILE_PERMISSIONS = 0o600


@dataclass
class KeyStoreEntry:
    """
    Key store entry metadata
    
    Attributes:
        alias: Unique alias for the key
        entry_type: Type of entry (private_key, certificate, or keypair)
        created_at: Creation timestamp
        modified_at: Last modified timestamp
        common_name: Certificate subject CN if available
        expiry_date: Certificate expiry date if available
    """
    alias: str
    entry_type: str  # 'private_key', 'certificate', 'keypair'
    created_at: datetime
    modified_at: datetime
    common_name: Optional[str] = None
    expiry_date: Optional[datetime] = None


@dataclass
class KeyStoreOptions:
    """
    Key store configuration options
    
    Attributes:
        store_path: Path to the key store file
        password: Password to encrypt/decrypt the key store
        iterations: Key derivation iterations (default: 100000)
        auto_save: Auto-save on changes (default: True)
    """
    store_path: Union[str, Path]
    password: str
    iterations: int = KeyStoreDefaults.ITERATIONS
    auto_save: bool = True


class KeyStore:
    """
    Secure storage for private keys and certificates
    
    Features:
    - AES-256-GCM encryption for private keys
    - PBKDF2 key derivation with configurable iterations
    - Secure file permissions (0600)
    - Atomic file writes to prevent corruption
    - Support for multiple key aliases
    
    Security Notes:
    - Private keys are encrypted at rest
    - Certificates are stored unencrypted (public data)
    - Master password is never stored
    - Salt is unique per key store
    
    Example:
        >>> keystore = KeyStore(KeyStoreOptions(
        ...     store_path='./keystore.json',
        ...     password='secure-password'
        ... ))
        >>> await keystore.load()
        >>> await keystore.set_key_pair('device-123', private_key, certificate)
        >>> await keystore.save()
    """
    
    def __init__(self, options: KeyStoreOptions):
        """
        Create a new KeyStore instance
        
        Args:
            options: Key store configuration options
        
        Raises:
            FdmsError: If required options are missing or invalid
        """
        if not options.store_path:
            raise FdmsError("Key store path is required", code="CRYPTO20")
        if not options.password:
            raise FdmsError("Key store password is required", code="CRYPTO21")
        if len(options.password) < 8:
            raise FdmsError(
                "Key store password must be at least 8 characters",
                code="CRYPTO22"
            )
        
        self._store_path = Path(options.store_path).resolve()
        self._password = options.password
        self._iterations = options.iterations
        self._auto_save = options.auto_save
        self._data: Dict = {}
        self._derived_key: Optional[bytes] = None
        self._is_loaded = False
    
    def load(self) -> None:
        """
        Load an existing key store or create a new one
        
        Raises:
            FdmsError: If key store cannot be loaded or decrypted
        """
        try:
            if self._store_path.exists():
                content = self._store_path.read_text('utf-8')
                self._data = json.loads(content)
                
                # Validate version
                if self._data.get('version') != KeyStoreDefaults.VERSION:
                    raise ValueError(
                        f"Unsupported key store version: {self._data.get('version')}"
                    )
                
                # Derive encryption key from password and stored salt
                self._derived_key = self._derive_key(
                    self._password,
                    bytes.fromhex(self._data['salt'])
                )
            else:
                # Create new key store
                salt = secrets.token_bytes(KeyStoreDefaults.SALT_LENGTH)
                self._derived_key = self._derive_key(self._password, salt)
                
                self._data = {
                    'version': KeyStoreDefaults.VERSION,
                    'salt': salt.hex(),
                    'entries': {}
                }
                
                if self._auto_save:
                    self.save()
            
            self._is_loaded = True
            
        except FdmsError:
            raise
        except Exception as e:
            raise FdmsError(
                f"Failed to load key store: {str(e)}",
                code="CRYPTO23",
                cause=e
            )
    
    def save(self) -> None:
        """
        Save the key store to disk
        
        Uses atomic write to prevent corruption.
        
        Raises:
            FdmsError: If save fails
        """
        if self._data is None:
            raise FdmsError(
                "Key store not initialized. Call load() first.",
                code="CRYPTO24"
            )
        
        try:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Atomic write: write to temp file, then rename
            temp_path = self._store_path.with_suffix('.tmp')
            content = json.dumps(self._data, indent=2)
            
            temp_path.write_text(content, 'utf-8')
            os.chmod(temp_path, KeyStoreDefaults.FILE_PERMISSIONS)
            temp_path.replace(self._store_path)
            
        except Exception as e:
            raise FdmsError(
                f"Failed to save key store: {str(e)}",
                code="CRYPTO25",
                cause=e
            )
    
    def set_private_key(
        self,
        alias: str,
        private_key: RSAPrivateKey,
        overwrite: bool = False
    ) -> None:
        """
        Store a private key in the key store
        
        Args:
            alias: Unique identifier for the key
            private_key: Private key to store
            overwrite: Whether to overwrite existing entry (default: False)
        
        Raises:
            FdmsError: If entry exists and overwrite is False
        """
        self._ensure_loaded()
        
        if not overwrite and alias in self._data['entries']:
            raise FdmsError(
                f"Entry with alias '{alias}' already exists. "
                "Set overwrite=True to replace.",
                code="CRYPTO26"
            )
        
        encrypted = self._encrypt_private_key(private_key)
        now = datetime.now(timezone.utc).isoformat()
        
        existing = self._data['entries'].get(alias, {})
        
        self._data['entries'][alias] = {
            'encrypted_private_key': encrypted['ciphertext'],
            'private_key_nonce': encrypted['nonce'],
            'certificate': existing.get('certificate'),
            'metadata': {
                'alias': alias,
                'type': 'keypair' if existing.get('certificate') else 'private_key',
                'created_at': existing.get('metadata', {}).get('created_at', now),
                'modified_at': now,
                'common_name': existing.get('metadata', {}).get('common_name'),
                'expiry_date': existing.get('metadata', {}).get('expiry_date'),
            }
        }
        
        if self._auto_save:
            self.save()
    
    def set_certificate(
        self,
        alias: str,
        certificate: x509.Certificate,
        overwrite: bool = False
    ) -> None:
        """
        Store a certificate in the key store
        
        Args:
            alias: Unique identifier for the certificate
            certificate: X.509 certificate to store
            overwrite: Whether to overwrite existing entry (default: False)
        
        Raises:
            FdmsError: If certificate exists and overwrite is False
        """
        self._ensure_loaded()
        
        existing = self._data['entries'].get(alias, {})
        if not overwrite and existing.get('certificate'):
            raise FdmsError(
                f"Certificate with alias '{alias}' already exists. "
                "Set overwrite=True to replace.",
                code="CRYPTO27"
            )
        
        now = datetime.now(timezone.utc).isoformat()
        cert_info = self._extract_certificate_info(certificate)
        
        self._data['entries'][alias] = {
            'encrypted_private_key': existing.get('encrypted_private_key'),
            'private_key_nonce': existing.get('private_key_nonce'),
            'certificate': certificate.public_bytes(Encoding.PEM).decode('utf-8'),
            'metadata': {
                'alias': alias,
                'type': 'keypair' if existing.get('encrypted_private_key') else 'certificate',
                'created_at': existing.get('metadata', {}).get('created_at', now),
                'modified_at': now,
                'common_name': cert_info['common_name'],
                'expiry_date': cert_info['expiry_date'],
            }
        }
        
        if self._auto_save:
            self.save()
    
    def set_key_pair(
        self,
        alias: str,
        private_key: RSAPrivateKey,
        certificate: x509.Certificate,
        overwrite: bool = False
    ) -> None:
        """
        Store both private key and certificate together
        
        Args:
            alias: Unique identifier for the key pair
            private_key: Private key to store
            certificate: X.509 certificate to store
            overwrite: Whether to overwrite existing entry (default: False)
        
        Raises:
            FdmsError: If entry exists and overwrite is False
        """
        self._ensure_loaded()
        
        if not overwrite and alias in self._data['entries']:
            raise FdmsError(
                f"Entry with alias '{alias}' already exists. "
                "Set overwrite=True to replace.",
                code="CRYPTO28"
            )
        
        encrypted = self._encrypt_private_key(private_key)
        cert_info = self._extract_certificate_info(certificate)
        now = datetime.now(timezone.utc).isoformat()
        
        self._data['entries'][alias] = {
            'encrypted_private_key': encrypted['ciphertext'],
            'private_key_nonce': encrypted['nonce'],
            'certificate': certificate.public_bytes(Encoding.PEM).decode('utf-8'),
            'metadata': {
                'alias': alias,
                'type': 'keypair',
                'created_at': now,
                'modified_at': now,
                'common_name': cert_info['common_name'],
                'expiry_date': cert_info['expiry_date'],
            }
        }
        
        if self._auto_save:
            self.save()
    
    def get_private_key(self, alias: str) -> RSAPrivateKey:
        """
        Retrieve a private key from the key store
        
        Args:
            alias: Alias of the key to retrieve
        
        Returns:
            Decrypted private key
        
        Raises:
            FdmsError: If key not found or decryption fails
        """
        self._ensure_loaded()
        
        entry = self._data['entries'].get(alias)
        if not entry or not entry.get('encrypted_private_key'):
            raise FdmsError(
                f"Private key not found for alias '{alias}'",
                code="CRYPTO29"
            )
        
        return self._decrypt_private_key(
            entry['encrypted_private_key'],
            entry['private_key_nonce']
        )
    
    def get_certificate(self, alias: str) -> x509.Certificate:
        """
        Retrieve a certificate from the key store
        
        Args:
            alias: Alias of the certificate to retrieve
        
        Returns:
            X.509 certificate
        
        Raises:
            FdmsError: If certificate not found
        """
        self._ensure_loaded()
        
        entry = self._data['entries'].get(alias)
        if not entry or not entry.get('certificate'):
            raise FdmsError(
                f"Certificate not found for alias '{alias}'",
                code="CRYPTO30"
            )
        
        return x509.load_pem_x509_certificate(
            entry['certificate'].encode('utf-8'),
            default_backend()
        )
    
    def has_entry(self, alias: str) -> bool:
        """Check if an entry exists in the key store"""
        self._ensure_loaded()
        return alias in self._data['entries']
    
    def has_private_key(self, alias: str) -> bool:
        """Check if a private key exists for the given alias"""
        self._ensure_loaded()
        entry = self._data['entries'].get(alias)
        return bool(entry and entry.get('encrypted_private_key'))
    
    def has_certificate(self, alias: str) -> bool:
        """Check if a certificate exists for the given alias"""
        self._ensure_loaded()
        entry = self._data['entries'].get(alias)
        return bool(entry and entry.get('certificate'))
    
    def delete_entry(self, alias: str) -> bool:
        """
        Delete an entry from the key store
        
        Args:
            alias: Alias of the entry to delete
        
        Returns:
            True if entry was deleted, False if not found
        """
        self._ensure_loaded()
        
        if alias not in self._data['entries']:
            return False
        
        del self._data['entries'][alias]
        
        if self._auto_save:
            self.save()
        
        return True
    
    def list_entries(self) -> List[KeyStoreEntry]:
        """
        List all entries in the key store
        
        Returns:
            List of entry metadata
        """
        self._ensure_loaded()
        
        entries = []
        for entry_data in self._data['entries'].values():
            metadata = entry_data['metadata']
            entries.append(KeyStoreEntry(
                alias=metadata['alias'],
                entry_type=metadata['type'],
                created_at=datetime.fromisoformat(metadata['created_at']),
                modified_at=datetime.fromisoformat(metadata['modified_at']),
                common_name=metadata.get('common_name'),
                expiry_date=datetime.fromisoformat(metadata['expiry_date']) 
                    if metadata.get('expiry_date') else None,
            ))
        
        return entries
    
    def get_expiring_entries(self, days: int) -> List[KeyStoreEntry]:
        """
        Get entries that will expire within the specified number of days
        
        Args:
            days: Number of days to check
        
        Returns:
            List of entries expiring soon
        """
        now = datetime.now(timezone.utc)
        threshold = now.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        # Add days
        from datetime import timedelta
        threshold = threshold + timedelta(days=days)
        
        return [
            entry for entry in self.list_entries()
            if entry.expiry_date and entry.expiry_date <= threshold
        ]
    
    def change_password(self, new_password: str) -> None:
        """
        Change the key store password
        
        Re-encrypts all private keys with the new password.
        
        Args:
            new_password: New password (minimum 8 characters)
        
        Raises:
            FdmsError: If new password is too short
        """
        self._ensure_loaded()
        
        if len(new_password) < 8:
            raise FdmsError(
                "New password must be at least 8 characters",
                code="CRYPTO31"
            )
        
        # Decrypt all private keys with old password
        decrypted_keys: Dict[str, RSAPrivateKey] = {}
        for alias, entry in self._data['entries'].items():
            if entry.get('encrypted_private_key'):
                decrypted_keys[alias] = self._decrypt_private_key(
                    entry['encrypted_private_key'],
                    entry['private_key_nonce']
                )
        
        # Generate new salt and derive new key
        new_salt = secrets.token_bytes(KeyStoreDefaults.SALT_LENGTH)
        self._derived_key = self._derive_key(new_password, new_salt)
        self._data['salt'] = new_salt.hex()
        
        # Re-encrypt all private keys with new password
        for alias, private_key in decrypted_keys.items():
            encrypted = self._encrypt_private_key(private_key)
            self._data['entries'][alias]['encrypted_private_key'] = encrypted['ciphertext']
            self._data['entries'][alias]['private_key_nonce'] = encrypted['nonce']
        
        self.save()
    
    def export(
        self,
        export_path: Union[str, Path],
        new_password: Optional[str] = None
    ) -> None:
        """
        Export the key store to a new location
        
        Args:
            export_path: Path to export to
            new_password: Optional new password for the export
        """
        self._ensure_loaded()
        
        export_path = Path(export_path)
        
        if new_password:
            # Create a temporary key store with new password
            temp_store = KeyStore(KeyStoreOptions(
                store_path=export_path,
                password=new_password,
                iterations=self._iterations,
                auto_save=False
            ))
            
            # Initialize with new salt
            salt = secrets.token_bytes(KeyStoreDefaults.SALT_LENGTH)
            temp_store._derived_key = self._derive_key(new_password, salt)
            temp_store._data = {
                'version': KeyStoreDefaults.VERSION,
                'salt': salt.hex(),
                'entries': {}
            }
            temp_store._is_loaded = True
            
            # Copy and re-encrypt entries
            for alias, entry in self._data['entries'].items():
                if entry.get('encrypted_private_key'):
                    private_key = self._decrypt_private_key(
                        entry['encrypted_private_key'],
                        entry['private_key_nonce']
                    )
                    encrypted = temp_store._encrypt_private_key(private_key)
                    temp_store._data['entries'][alias] = {
                        **entry,
                        'encrypted_private_key': encrypted['ciphertext'],
                        'private_key_nonce': encrypted['nonce'],
                    }
                else:
                    temp_store._data['entries'][alias] = dict(entry)
            
            temp_store.save()
        else:
            # Simple copy with same password
            export_path.parent.mkdir(parents=True, exist_ok=True)
            content = json.dumps(self._data, indent=2)
            export_path.write_text(content, 'utf-8')
            os.chmod(export_path, KeyStoreDefaults.FILE_PERMISSIONS)
    
    def clear(self) -> None:
        """Clear all entries from the key store"""
        self._ensure_loaded()
        self._data['entries'] = {}
        
        if self._auto_save:
            self.save()
    
    @property
    def size(self) -> int:
        """Get the number of entries in the key store"""
        if self._data is None:
            return 0
        return len(self._data['entries'])
    
    @property
    def loaded(self) -> bool:
        """Check if the key store has been loaded"""
        return self._is_loaded
    
    # ============ Private Helper Methods ============
    
    def _ensure_loaded(self) -> None:
        """Ensure the key store is loaded before operations"""
        if not self._is_loaded or self._data is None or self._derived_key is None:
            raise FdmsError(
                "Key store not loaded. Call load() first.",
                code="CRYPTO32"
            )
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=KeyStoreDefaults.KEY_LENGTH,
            salt=salt,
            iterations=self._iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _encrypt_private_key(self, private_key: RSAPrivateKey) -> Dict[str, str]:
        """Encrypt a private key using AES-256-GCM"""
        if self._derived_key is None:
            raise FdmsError("Encryption key not available", code="CRYPTO34")
        
        # Export private key to PEM format
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        # Generate random nonce
        nonce = secrets.token_bytes(KeyStoreDefaults.NONCE_LENGTH)
        
        # Encrypt using AES-256-GCM
        aesgcm = AESGCM(self._derived_key)
        ciphertext = aesgcm.encrypt(nonce, key_pem, None)
        
        return {
            'ciphertext': ciphertext.hex(),
            'nonce': nonce.hex(),
        }
    
    def _decrypt_private_key(
        self,
        ciphertext: str,
        nonce: str
    ) -> RSAPrivateKey:
        """Decrypt a private key using AES-256-GCM"""
        if self._derived_key is None:
            raise FdmsError("Decryption key not available", code="CRYPTO35")
        
        try:
            aesgcm = AESGCM(self._derived_key)
            decrypted = aesgcm.decrypt(
                bytes.fromhex(nonce),
                bytes.fromhex(ciphertext),
                None
            )
            
            private_key = load_pem_private_key(
                decrypted,
                password=None,
                backend=default_backend()
            )
            
            if not isinstance(private_key, RSAPrivateKey):
                raise ValueError("Decrypted key is not an RSA key")
            
            return private_key
            
        except Exception as e:
            raise FdmsError(
                "Failed to decrypt private key. Invalid password or corrupted data.",
                code="CRYPTO36",
                cause=e
            )
    
    def _extract_certificate_info(
        self,
        certificate: x509.Certificate
    ) -> Dict[str, Optional[str]]:
        """Extract basic info from a certificate"""
        common_name = None
        try:
            cn_attrs = certificate.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            if cn_attrs:
                common_name = cn_attrs[0].value
        except Exception:
            pass
        
        expiry_date = certificate.not_valid_after_utc.isoformat()
        
        return {
            'common_name': common_name,
            'expiry_date': expiry_date,
        }
