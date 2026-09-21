"""Local-only facade for the standalone Gmail and BUSINESS workspace."""
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, SecretStr

from api.gmail import _SafeValidationRoute, _safe_errors
from services import workspace_accounts


router = APIRouter(prefix="/workspace", tags=["workspace"], route_class=_SafeValidationRoute)


class OrdinaryImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    data: SecretStr
    registration_status: Literal["unregistered", "registered"] = "unregistered"


@router.post("/ordinary/import")
@_safe_errors
def import_ordinary(body: OrdinaryImportRequest):
    return workspace_accounts.import_ordinary(body.data.get_secret_value(), body.registration_status)


@router.post("/ordinary/import-gmail-bundle")
@_safe_errors
def import_ordinary_gmail_bundle(body: OrdinaryImportRequest):
    return workspace_accounts.import_gmail_bundle(body.data.get_secret_value())


@router.get("/summary")
@_safe_errors
def get_summary():
    return workspace_accounts.summary()
