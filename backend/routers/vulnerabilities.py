from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from typing import List
from backend.models import CveItem, SeverityEnum
from backend.storage import get_persisted_cves, save_persisted_cves
from backend.routers.auth import get_current_user

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Database"])


@router.get("", response_model=List[CveItem])
def search_cves(query: str = "", current_user: dict = Depends(get_current_user)):
    cve_catalog = get_persisted_cves()
    if not query:
        return cve_catalog
    q = query.lower()
    return [c for c in cve_catalog if q in c["cve_id"].lower() or q in c["title"].lower() or q in c["summary"].lower()]


@router.post("", response_model=CveItem)
def add_cve(cve_in: CveItem, current_user: dict = Depends(get_current_user)):
    cve_catalog = get_persisted_cves()
    cve_id_clean = cve_in.cve_id.strip()
    
    for c in cve_catalog:
        if c.get("cve_id", "").strip().lower() == cve_id_clean.lower():
            raise HTTPException(status_code=400, detail=f"CVE ID '{cve_id_clean}' already exists in database.")
    
    cve_dict = cve_in.dict()
    cve_dict["cve_id"] = cve_id_clean
    if not cve_dict.get("published_date"):
        cve_dict["published_date"] = datetime.utcnow().strftime("%Y-%m-%d")
        
    cve_catalog.insert(0, cve_dict) # prepend new CVE to top of list
    save_persisted_cves(cve_catalog)
    return cve_dict


@router.delete("/{cve_id}")
def delete_cve(cve_id: str, current_user: dict = Depends(get_current_user)):
    cve_catalog = get_persisted_cves()
    initial_len = len(cve_catalog)
    updated_catalog = [c for c in cve_catalog if c.get("cve_id") != cve_id]
    if len(updated_catalog) == initial_len:
        raise HTTPException(status_code=404, detail="CVE record not found")
    save_persisted_cves(updated_catalog)
    return {"message": f"CVE record {cve_id} deleted successfully."}
