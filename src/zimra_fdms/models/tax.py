"""Tax rate model"""

from pydantic import BaseModel, Field


class TaxRate(BaseModel):
    """Tax rate model"""
    
    tax_code: str = Field(..., description="Tax code")
    tax_name: str = Field(..., description="Tax name")
    tax_percent: float = Field(..., description="Tax percentage")
