"""
HTTP transport layer for FDMS API
Handles all HTTP communication with retry logic, interceptors,
circuit breaker pattern, and connection pooling
"""

import time
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    TypeVar,
    Union,
)

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from zimra_fdms.config.fdms_config import FdmsConfig
from zimra_fdms.exceptions import FdmsError, NetworkError


# Type variable for generic response
T = TypeVar("T")

# Logger for this module
logger = logging.getLogger(__name__)


class HttpMethod(str, Enum):
    """HTTP method types supported"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class CircuitState(str, Enum):
    """Circuit breaker states"""
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class NetworkErrorCode(str, Enum):
    """Network error codes"""
    TIMEOUT = "NET01"
    CONNECTION_REFUSED = "NET02"
    DNS_LOOKUP_FAILED = "NET03"
    SSL_ERROR = "NET04"
    CIRCUIT_BREAKER_OPEN = "NET05"
    NO_RESPONSE = "NET06"
    REQUEST_ABORTED = "NET07"
    UNKNOWN = "NET10"


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: int = 30000  # milliseconds
    success_threshold: int = 3


@dataclass
class HttpRequestOptions:
    """Request options for HTTP client"""
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Union[str, int, bool]]] = None
    timeout: Optional[int] = None  # milliseconds
    skip_retry: bool = False
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class HttpResponse(Generic[T]):
    """HTTP response wrapper"""
    data: T
    status: int
    headers: Dict[str, str]
    duration: int  # milliseconds
    request_id: str


@dataclass
class HttpAuditEntry:
    """Audit log entry for HTTP requests"""
    timestamp: str
    request_id: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[Any] = None
    response: Optional[Dict[str, Any]] = None
    duration: int = 0
    success: bool = False
    error: Optional[str] = None
    retry_attempt: Optional[int] = None


# Sensitive fields that should be redacted in logs
SENSITIVE_FIELDS = [
    "authorization",
    "x-api-key",
    "privatekey",
    "private_key",
    "password",
    "activationkey",
    "activation_key",
    "certificate",
]


# Request interceptor type
RequestInterceptor = Callable[[requests.PreparedRequest], requests.PreparedRequest]

# Response interceptor type
ResponseInterceptor = Callable[[requests.Response], requests.Response]


class HttpClient:
    """
    HTTP Client for ZIMRA FDMS API
    
    Features:
    - Automatic retry with exponential backoff
    - Circuit breaker pattern for resilience
    - Request/response interceptors
    - Request ID generation for traceability
    - Comprehensive audit logging
    - Connection keep-alive via session pooling
    
    Example:
        >>> config = FdmsConfig(...)
        >>> client = HttpClient(config)
        >>> response = client.get("/api/Device/123/v1/GetStatus")
        >>> print(response.data)
    """

    def __init__(
        self,
        config: FdmsConfig,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
    ) -> None:
        """
        Create a new HTTP client instance
        
        Args:
            config: Resolved FDMS configuration
            circuit_breaker_config: Optional circuit breaker configuration
        """
        self.config = config
        self.circuit_config = circuit_breaker_config or CircuitBreakerConfig()
        
        # Circuit breaker state
        self._circuit_state = CircuitState.CLOSED
        self._circuit_failure_count = 0
        self._circuit_success_count = 0
        self._circuit_open_time = 0.0
        
        # Custom interceptors
        self._request_interceptors: List[RequestInterceptor] = []
        self._response_interceptors: List[ResponseInterceptor] = []
        
        # Audit logging callback
        self._audit_log_callback: Optional[Callable[[HttpAuditEntry], None]] = None
        
        # Create session with connection pooling
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create requests session with connection pooling and retry adapter"""
        session = requests.Session()
        
        # Set default headers
        session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "DeviceModelName": self.config.device_model_name,
            "DeviceModelVersionNo": self.config.device_model_version,
        })
        
        # Configure connection pooling adapter
        # Note: We handle retry logic ourselves for more control
        adapter = HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=0,  # We handle retries manually
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session

    def _generate_request_id(self) -> str:
        """Generate unique request ID for traceability"""
        timestamp = hex(int(time.time() * 1000))[2:]
        unique_id = uuid.uuid4().hex[:8]
        return f"fdms-{timestamp}-{unique_id}"

    def _redact_sensitive_data(self, obj: Any) -> Any:
        """Redact sensitive data from object for logging"""
        if obj is None:
            return obj
        
        if isinstance(obj, str):
            return obj
        
        if isinstance(obj, list):
            return [self._redact_sensitive_data(item) for item in obj]
        
        if isinstance(obj, dict):
            redacted = {}
            for key, value in obj.items():
                lower_key = key.lower()
                is_sensitive = any(
                    field in lower_key for field in SENSITIVE_FIELDS
                )
                
                if is_sensitive:
                    redacted[key] = "[REDACTED]"
                elif isinstance(value, (dict, list)):
                    redacted[key] = self._redact_sensitive_data(value)
                else:
                    redacted[key] = value
            return redacted
        
        return obj

    def _check_circuit_breaker(self) -> None:
        """Check circuit breaker state and raise if open"""
        if self._circuit_state == CircuitState.OPEN:
            time_since_open = (time.time() * 1000) - self._circuit_open_time
            
            if time_since_open >= self.circuit_config.recovery_timeout:
                # Transition to half-open state
                self._circuit_state = CircuitState.HALF_OPEN
                self._circuit_success_count = 0
                logger.info("Circuit breaker transitioning to HALF_OPEN state")
            else:
                retry_after = int(
                    (self.circuit_config.recovery_timeout - time_since_open) / 1000
                )
                raise NetworkError(
                    f"Circuit breaker is open. Retry after {retry_after} seconds",
                    status_code=503,
                )

    def _record_circuit_success(self) -> None:
        """Record circuit breaker success"""
        if self._circuit_state == CircuitState.HALF_OPEN:
            self._circuit_success_count += 1
            
            if self._circuit_success_count >= self.circuit_config.success_threshold:
                # Close the circuit
                self._circuit_state = CircuitState.CLOSED
                self._circuit_failure_count = 0
                self._circuit_success_count = 0
                logger.info("Circuit breaker CLOSED after successful recovery")
        elif self._circuit_state == CircuitState.CLOSED:
            # Reset failure count on success
            self._circuit_failure_count = 0

    def _record_circuit_failure(self) -> None:
        """Record circuit breaker failure"""
        if self._circuit_state == CircuitState.HALF_OPEN:
            # Failed while half-open, reopen circuit
            self._circuit_state = CircuitState.OPEN
            self._circuit_open_time = time.time() * 1000
            logger.warning("Circuit breaker REOPENED after failure in half-open state")
        elif self._circuit_state == CircuitState.CLOSED:
            self._circuit_failure_count += 1
            
            if self._circuit_failure_count >= self.circuit_config.failure_threshold:
                # Open the circuit
                self._circuit_state = CircuitState.OPEN
                self._circuit_open_time = time.time() * 1000
                logger.warning(
                    f"Circuit breaker OPENED after {self._circuit_failure_count} failures"
                )

    def _calculate_retry_delay(self, attempt: int) -> float:
        """
        Calculate retry delay with exponential backoff
        
        Args:
            attempt: Current attempt number (0-based)
            
        Returns:
            Delay in seconds
        """
        # Exponential backoff: baseDelay * 2^attempt
        # Max delay capped at 16 seconds
        delay_ms = self.config.retry_delay * (2 ** attempt)
        delay_ms = min(delay_ms, 16000)
        return delay_ms / 1000.0  # Convert to seconds

    def _is_retryable_error(self, error: Exception) -> bool:
        """Determine if error is retryable"""
        if isinstance(error, NetworkError):
            return True
        
        if isinstance(error, FdmsError) and error.status_code:
            # Retry on 5xx errors and specific 4xx errors
            retryable_statuses = [408, 429, 500, 502, 503, 504]
            return error.status_code in retryable_statuses
        
        if isinstance(error, requests.exceptions.RequestException):
            return True
        
        return False

    def _normalize_error(
        self, error: Exception, response: Optional[requests.Response] = None
    ) -> Union[FdmsError, NetworkError]:
        """Normalize error from various sources into FdmsError"""
        if isinstance(error, requests.exceptions.Timeout):
            return NetworkError("Request timed out", status_code=408)
        
        if isinstance(error, requests.exceptions.ConnectionError):
            return NetworkError(
                f"Connection error: {str(error)}", status_code=None
            )
        
        if isinstance(error, requests.exceptions.HTTPError) and response is not None:
            try:
                data = response.json()
                error_code = data.get("code") or (
                    data.get("errors", [{}])[0].get("code")
                )
                error_message = data.get("message") or (
                    data.get("errors", [{}])[0].get("message")
                ) or str(error)
                return FdmsError(
                    error_message, code=error_code, status_code=response.status_code
                )
            except (ValueError, KeyError, IndexError):
                return FdmsError(
                    str(error), status_code=response.status_code
                )
        
        if isinstance(error, (FdmsError, NetworkError)):
            return error
        
        return FdmsError(f"Request error: {str(error)}")

    def _create_audit_entry(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[Any],
        request_id: str,
        start_time: float,
        response: Optional[requests.Response] = None,
        error: Optional[Exception] = None,
        retry_attempt: Optional[int] = None,
    ) -> HttpAuditEntry:
        """Create audit log entry"""
        duration = int((time.time() - start_time) * 1000)
        
        response_data = None
        if response is not None:
            try:
                response_body = response.json()
            except ValueError:
                response_body = response.text[:500] if response.text else None
            
            response_data = {
                "statusCode": response.status_code,
                "body": self._redact_sensitive_data(response_body),
            }
        
        return HttpAuditEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            request_id=request_id,
            method=method,
            url=url,
            headers=self._redact_sensitive_data(dict(headers)),
            body=self._redact_sensitive_data(body),
            response=response_data,
            duration=duration,
            success=error is None,
            error=str(error) if error else None,
            retry_attempt=retry_attempt,
        )

    def _log_audit(self, entry: HttpAuditEntry) -> None:
        """Log audit entry"""
        if self.config.enable_audit_log and self._audit_log_callback:
            self._audit_log_callback(entry)

    def add_request_interceptor(self, interceptor: RequestInterceptor) -> None:
        """Add a custom request interceptor"""
        self._request_interceptors.append(interceptor)

    def add_response_interceptor(self, interceptor: ResponseInterceptor) -> None:
        """Add a custom response interceptor"""
        self._response_interceptors.append(interceptor)

    def set_audit_log_callback(
        self, callback: Callable[[HttpAuditEntry], None]
    ) -> None:
        """Set audit log callback"""
        self._audit_log_callback = callback

    def _apply_request_interceptors(
        self, prepared: requests.PreparedRequest
    ) -> requests.PreparedRequest:
        """Apply custom request interceptors"""
        for interceptor in self._request_interceptors:
            prepared = interceptor(prepared)
        return prepared

    def _apply_response_interceptors(
        self, response: requests.Response
    ) -> requests.Response:
        """Apply custom response interceptors"""
        for interceptor in self._response_interceptors:
            response = interceptor(response)
        return response

    def _execute_with_retry(
        self,
        method: HttpMethod,
        url: str,
        data: Optional[Any] = None,
        options: Optional[HttpRequestOptions] = None,
    ) -> HttpResponse[Any]:
        """Execute HTTP request with retry logic"""
        options = options or HttpRequestOptions()
        
        # Check circuit breaker before making request
        self._check_circuit_breaker()
        
        max_attempts = 1 if options.skip_retry else self.config.retry_attempts + 1
        last_error: Optional[Exception] = None
        
        # Build full URL
        full_url = f"{self.config.get_resolved_base_url()}{url}"
        
        # Calculate timeout in seconds
        timeout_seconds = (options.timeout or self.config.timeout) / 1000.0
        
        for attempt in range(max_attempts):
            start_time = time.time()
            request_id = self._generate_request_id()
            
            # Prepare headers
            headers = dict(self._session.headers)
            headers["X-Request-ID"] = request_id
            if options.headers:
                headers.update(options.headers)
            
            response: Optional[requests.Response] = None
            
            try:
                # Prepare the request
                request = requests.Request(
                    method=method.value,
                    url=full_url,
                    headers=headers,
                    params=options.params,
                    json=data if data else None,
                )
                prepared = self._session.prepare_request(request)
                
                # Apply request interceptors
                prepared = self._apply_request_interceptors(prepared)
                
                # Send request
                response = self._session.send(
                    prepared,
                    timeout=timeout_seconds,
                )
                
                # Apply response interceptors
                response = self._apply_response_interceptors(response)
                
                # Raise for HTTP errors
                response.raise_for_status()
                
                # Record success for circuit breaker
                self._record_circuit_success()
                
                # Create audit entry
                audit_entry = self._create_audit_entry(
                    method=method.value,
                    url=full_url,
                    headers=headers,
                    body=data,
                    request_id=request_id,
                    start_time=start_time,
                    response=response,
                    retry_attempt=attempt if attempt > 0 else None,
                )
                self._log_audit(audit_entry)
                
                # Parse response
                try:
                    response_data = response.json()
                except ValueError:
                    response_data = response.text
                
                duration = int((time.time() - start_time) * 1000)
                
                return HttpResponse(
                    data=response_data,
                    status=response.status_code,
                    headers=dict(response.headers),
                    duration=duration,
                    request_id=request_id,
                )
                
            except Exception as e:
                last_error = e
                
                # Record failure for circuit breaker
                self._record_circuit_failure()
                
                # Log audit entry for failed attempt
                audit_entry = self._create_audit_entry(
                    method=method.value,
                    url=full_url,
                    headers=headers,
                    body=data,
                    request_id=request_id,
                    start_time=start_time,
                    response=response,
                    error=e,
                    retry_attempt=attempt,
                )
                self._log_audit(audit_entry)
                
                # Check if we should retry
                if attempt < max_attempts - 1 and self._is_retryable_error(e):
                    delay = self._calculate_retry_delay(attempt)
                    logger.warning(
                        f"Request failed (attempt {attempt + 1}/{max_attempts}), "
                        f"retrying in {delay:.2f}s: {e}"
                    )
                    time.sleep(delay)
                    continue
                
                raise self._normalize_error(e, response)
        
        # Should not reach here, but just in case
        if last_error:
            raise self._normalize_error(last_error)
        raise FdmsError("Unknown error occurred")

    def get(
        self,
        url: str,
        options: Optional[HttpRequestOptions] = None,
    ) -> HttpResponse[Any]:
        """
        Perform GET request
        
        Args:
            url: Request URL (relative to base URL)
            options: Optional request options
            
        Returns:
            HTTP response wrapper
        """
        return self._execute_with_retry(HttpMethod.GET, url, None, options)

    def post(
        self,
        url: str,
        data: Optional[Any] = None,
        options: Optional[HttpRequestOptions] = None,
    ) -> HttpResponse[Any]:
        """
        Perform POST request
        
        Args:
            url: Request URL (relative to base URL)
            data: Request body data
            options: Optional request options
            
        Returns:
            HTTP response wrapper
        """
        return self._execute_with_retry(HttpMethod.POST, url, data, options)

    def put(
        self,
        url: str,
        data: Optional[Any] = None,
        options: Optional[HttpRequestOptions] = None,
    ) -> HttpResponse[Any]:
        """
        Perform PUT request
        
        Args:
            url: Request URL (relative to base URL)
            data: Request body data
            options: Optional request options
            
        Returns:
            HTTP response wrapper
        """
        return self._execute_with_retry(HttpMethod.PUT, url, data, options)

    def delete(
        self,
        url: str,
        options: Optional[HttpRequestOptions] = None,
    ) -> HttpResponse[Any]:
        """
        Perform DELETE request
        
        Args:
            url: Request URL (relative to base URL)
            options: Optional request options
            
        Returns:
            HTTP response wrapper
        """
        return self._execute_with_retry(HttpMethod.DELETE, url, None, options)

    def patch(
        self,
        url: str,
        data: Optional[Any] = None,
        options: Optional[HttpRequestOptions] = None,
    ) -> HttpResponse[Any]:
        """
        Perform PATCH request
        
        Args:
            url: Request URL (relative to base URL)
            data: Request body data
            options: Optional request options
            
        Returns:
            HTTP response wrapper
        """
        return self._execute_with_retry(HttpMethod.PATCH, url, data, options)

    @property
    def circuit_state(self) -> CircuitState:
        """Get current circuit breaker state"""
        return self._circuit_state

    def reset_circuit_breaker(self) -> None:
        """Reset circuit breaker to closed state"""
        self._circuit_state = CircuitState.CLOSED
        self._circuit_failure_count = 0
        self._circuit_success_count = 0
        self._circuit_open_time = 0.0
        logger.info("Circuit breaker manually reset to CLOSED state")

    @property
    def base_url(self) -> str:
        """Get base URL"""
        return self.config.get_resolved_base_url()

    @property
    def device_id(self) -> str:
        """Get device ID from config"""
        return self.config.device_id

    def close(self) -> None:
        """Close the HTTP session"""
        self._session.close()

    def __enter__(self) -> "HttpClient":
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit"""
        self.close()
