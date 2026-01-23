"""Receipt models"""

from typing import Literal, Optional, List
from pydantic import BaseModel, Field


class BuyerData(BaseModel):
    """Buyer information"""
    
    buyer_register_name: str = Field(..., description="Buyer registered name")
    buyer_trade_name: Optional[str] = Field(None, description="Buyer trade name")
    buyer_tin: Optional[str] = Field(None, description="Buyer TIN")
    buyer_vat_number: Optional[str] = Field(None, description="Buyer VAT number")


class ReceiptLineItem(BaseModel):
    """Receipt line item"""
    
    line_no: int = Field(..., description="Line number")
    line_description: str = Field(..., description="Item description")
    line_quantity: float = Field(..., description="Quantity")
    line_unit_price: float = Field(..., description="Unit price")
    line_tax_percent: float = Field(..., description="Tax percentage")
    line_total: float = Field(..., description="Line total")
    hs_code: Optional[str] = Field(None, description="HS code for inventory items")


class ReceiptTax(BaseModel):
    """Receipt tax summary"""
    
    tax_code: str = Field(..., description="Tax code")
    tax_percent: float = Field(..., description="Tax percentage")
    tax_amount: float = Field(..., description="Tax amount")
    sales_amount_with_tax: float = Field(..., description="Sales amount with tax")


class ReceiptPayment(BaseModel):
    """Receipt payment"""
    
    money_type_code: int = Field(..., description="Payment method code (0=Cash, 1=Card, etc)")
    payment_amount: float = Field(..., description="Payment amount")


class Receipt(BaseModel):
    """Receipt model"""
    
    receipt_type: Literal["FiscalInvoice", "CreditNote", "DebitNote"] = Field(
        ..., description="Receipt type"
    )
    receipt_currency: str = Field(..., description="Currency code (ISO 4217)")
    receipt_counter: int = Field(..., description="Sequential counter within fiscal day")
    receipt_global_no: int = Field(..., description="Global sequential number")
    invoice_no: str = Field(..., description="Business invoice number")
    receipt_date: str = Field(..., description="Receipt date (ISO 8601)")
    buyer_data: Optional[BuyerData] = Field(None, description="Buyer information")
    receipt_line_items: List[ReceiptLineItem] = Field(..., description="Line items")
    receipt_taxes: List[ReceiptTax] = Field(..., description="Tax summary")
    receipt_payments: List[ReceiptPayment] = Field(..., description="Payments")
    receipt_total: float = Field(..., description="Total amount")
    receipt_tax_total: float = Field(..., description="Total tax")
    receipt_signature: str = Field(..., description="Digital signature")
    ref_receipt_id: Optional[int] = Field(None, description="Reference receipt ID (for credit/debit notes)")
    ref_receipt_global_no: Optional[int] = Field(None, description="Reference global receipt number")
