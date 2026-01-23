"""Fiscal day models"""

from typing import Literal, Dict, List
from pydantic import BaseModel, Field


class FiscalDayCounters(BaseModel):
    """Fiscal day counters"""
    
    receipt_counter: int = Field(..., description="Total receipt counter")
    receipt_counter_by_type: Dict[str, int] = Field(
        ..., description="Receipt counters by type"
    )


class FiscalDayTotals(BaseModel):
    """Fiscal day totals"""
    
    total_amount: float = Field(..., description="Total amount")
    total_tax: float = Field(..., description="Total tax")
    totals_by_tax_rate: List[Dict[str, float]] = Field(
        ..., description="Totals by tax rate"
    )


class FiscalDay(BaseModel):
    """Fiscal day model"""
    
    fiscal_day_no: int = Field(..., description="Fiscal day number")
    fiscal_day_opened: str = Field(..., description="Date/time fiscal day opened (ISO 8601)")
    fiscal_day_status: Literal["Closed", "Opened", "CloseInitiated", "CloseFailed"] = Field(
        ..., description="Fiscal day status"
    )
