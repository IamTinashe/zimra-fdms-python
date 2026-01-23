# ZIMRA FDMS Integration SDK for Python

[![CI](https://github.com/yourusername/zimra-fdms-python/workflows/CI/badge.svg)](https://github.com/yourusername/zimra-fdms-python/actions)
[![PyPI version](https://badge.fury.io/py/zimra-fdms.svg)](https://pypi.org/project/zimra-fdms/)
[![codecov](https://codecov.io/gh/yourusername/zimra-fdms-python/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/zimra-fdms-python)
[![Python Version](https://img.shields.io/pypi/pyversions/zimra-fdms.svg)](https://pypi.org/project/zimra-fdms/)

Production-grade SDK for integrating with Zimbabwe Revenue Authority's (ZIMRA) Fiscalisation Data Management System (FDMS) API.

## Features

- ✅ Full ZIMRA FDMS API v7.2 compliance
- 🔐 Security-first cryptographic operations
- 📝 Complete audit logging
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
