from fastapi import APIRouter, HTTPException, Depends
from typing import List
from backend.models import AssetCreate, AssetResponse, TargetTypeEnum
from backend.storage import get_persisted_assets, save_persisted_assets
from backend.routers.auth import get_current_user, require_admin

router = APIRouter(prefix="/assets", tags=["Asset Management"])

ASSETS_DB = get_persisted_assets()


@router.get("", response_model=List[AssetResponse])
def list_assets(current_user: dict = Depends(get_current_user)):
    return ASSETS_DB


@router.post("", response_model=AssetResponse)
def create_asset(asset_in: AssetCreate, current_user: dict = Depends(get_current_user)):
    new_asset = {
        "id": f"ast-{len(ASSETS_DB) + 101}",
        "name": asset_in.name,
        "target": asset_in.target,
        "asset_type": asset_in.asset_type,
        "tags": asset_in.tags or ["Asset"],
        "owner": asset_in.owner or "AppSec Team",
        "department": asset_in.department or "Engineering",
        "status": "Active",
        "last_scanned": "Never"
    }
    ASSETS_DB.append(new_asset)
    save_persisted_assets(ASSETS_DB)
    return new_asset


@router.delete("/{asset_id}")
def delete_asset(asset_id: str, current_user: dict = Depends(require_admin)):
    global ASSETS_DB
    initial_len = len(ASSETS_DB)
    ASSETS_DB = [a for a in ASSETS_DB if a.get("id") != asset_id]
    if len(ASSETS_DB) == initial_len:
        raise HTTPException(status_code=404, detail="Asset not found")
    save_persisted_assets(ASSETS_DB)
    return {"message": f"Asset {asset_id} deleted successfully."}
