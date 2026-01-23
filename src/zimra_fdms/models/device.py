"""Device model"""

from typing import Literal
from pydantic import BaseModel, Field


class Device(BaseModel):
    """Device model"""
    
    device_id: str = Field(..., description="Device ID assigned by ZIMRA")
    device_serial_no: str = Field(..., description="Manufacturer serial number")
    device_model_name: str = Field(..., description="Device model name")
    device_model_version: str = Field(..., description="Device model version")
    status: Literal["Registered", "Active", "Suspended", "Deactivated"] = Field(
        ..., description="Device status"
    )
