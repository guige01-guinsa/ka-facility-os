from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class InspectionCreate(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    location: str = Field(min_length=1, max_length=120)
    cycle: str = Field(min_length=1, max_length=40)
    inspector: str = Field(min_length=1, max_length=80)
    inspected_at: datetime
    transformer_kva: Optional[float] = None
    voltage_r: Optional[float] = None
    voltage_s: Optional[float] = None
    voltage_t: Optional[float] = None
    current_r: Optional[float] = None
    current_s: Optional[float] = None
    current_t: Optional[float] = None
    winding_temp_c: Optional[float] = None
    grounding_ohm: Optional[float] = None
    insulation_mohm: Optional[float] = None
    notes: str = ""


class InspectionRead(BaseModel):
    id: int
    site: str
    location: str
    cycle: str
    inspector: str
    inspected_at: datetime
    transformer_kva: Optional[float] = None
    voltage_r: Optional[float] = None
    voltage_s: Optional[float] = None
    voltage_t: Optional[float] = None
    current_r: Optional[float] = None
    current_s: Optional[float] = None
    current_t: Optional[float] = None
    winding_temp_c: Optional[float] = None
    grounding_ohm: Optional[float] = None
    insulation_mohm: Optional[float] = None
    notes: str
    risk_level: str
    risk_flags: list[str]
    created_at: datetime
