"""Exception classes for ZIMRA FDMS SDK"""


class FdmsError(Exception):
    """Base exception for FDMS errors"""
    
    def __init__(
        self,
        message: str,
        code: str = None,
        status_code: int = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class ValidationError(FdmsError):
    """Validation error"""
    
    def __init__(self, message: str, field: str = None) -> None:
        super().__init__(message, code="VALIDATION_ERROR")
        self.field = field


class NetworkError(FdmsError):
    """Network error"""
    
    def __init__(self, message: str, status_code: int = None) -> None:
        super().__init__(message, code="NETWORK_ERROR", status_code=status_code)
