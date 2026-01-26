# ZIMRA FDMS Integration SDK for Python

[![CI](https://github.com/yourusername/zimra-fdms-python/workflows/CI/badge.svg)](https://github.com/yourusername/zimra-fdms-python/actions)
[![PyPI version](https://badge.fury.io/py/zimra-fdms.svg)](https://pypi.org/project/zimra-fdms/)
[![codecov](https://codecov.io/gh/yourusername/zimra-fdms-python/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/zimra-fdms-python)
[![Python Version](https://img.shields.io/pypi/pyversions/zimra-fdms.svg)](https://pypi.org/project/zimra-fdms/)

Production-grade SDK for integrating with Zimbabwe Revenue Authority's (ZIMRA) Fiscalisation Data Management System (FDMS) API.

## Features

- ✅ Full ZIMRA FDMS API v7.2 compliance
- 🔐 Security-first cryptographic operations
- � X.509 certificate management with CSR generation
- 🔒 Secure encrypted key storage (AES-256-GCM)
- �📝 Complete audit logging
- 🔄 Automatic retry and offline queue
- 📊 Real-time fiscal day management
- 🧾 Receipt signing and QR code generation
- 🐍 Fully type-annotated with Pydantic models

## Installation

```bash
pip install zimra-fdms
```

## Quick Start

```python
from zimra_fdms import FdmsClient

client = FdmsClient(
    device_id="YOUR_DEVICE_ID",
    device_serial_no="YOUR_SERIAL_NO",
    activation_key="YOUR_ACTIVATION_KEY",
    device_model_name="YOUR_MODEL_NAME",
    device_model_version="YOUR_MODEL_VERSION",
    certificate="./path/to/cert.pem",
    private_key="./path/to/key.pem",
    environment="test"
)

# Initialize device
client.initialize()

# Open fiscal day
client.open_fiscal_day()

# Submit receipt
receipt = client.submit_receipt({
    # receipt data
})

# Close fiscal day
client.close_fiscal_day()
```

## Certificate Management

The SDK provides comprehensive X.509 certificate management:

```python
from zimra_fdms.crypto import CertificateManager, KeyStore, KeyStoreOptions, CsrOptions

# Certificate Manager
cert_manager = CertificateManager()

# Load existing certificate and key
cert = cert_manager.load_certificate('./device-cert.pem')
private_key = cert_manager.load_private_key('./device-key.pem', password='password')

# Generate new RSA key pair (4096-bit recommended)
key_pair = cert_manager.generate_key_pair(key_size=4096)

# Generate CSR for device registration
csr = cert_manager.generate_csr(
    private_key=key_pair['private_key'],
    options=CsrOptions(
        common_name='DEVICE-12345',
        organization_name='My Company',
        country_name='ZW'
    )
)

# Validate certificate
validation = cert_manager.validate_certificate(cert)
if not validation.valid:
    print('Certificate issues:', validation.errors)

# Secure Key Storage
key_store = KeyStore(KeyStoreOptions(
    store_path='./keystore.json',
    password='secure-password'
))

key_store.load()
key_store.set_key_pair('device-key', private_key, cert)
key_store.save()

# Retrieve later
stored_key = key_store.get_private_key('device-key')
stored_cert = key_store.get_certificate('device-key')
```

## Documentation

- [Installation Guide](./docs/guides/installation.md)
- [Configuration Guide](./docs/guides/configuration.md)
- [API Reference](./docs/api/README.md)
- [Examples](./examples/)

## Requirements

- Python >= 3.9
- ZIMRA device credentials

## Development

```bash
# Clone repository
git clone https://github.com/yourusername/zimra-fdms-python.git
cd zimra-fdms-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
pylint src/zimra_fdms
black src tests
isort src tests
mypy src/zimra_fdms
```

## License

MIT

## Support

For issues and questions, please open an issue on [GitHub](https://github.com/yourusername/zimra-fdms-python/issues).
