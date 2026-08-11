from fastapi import APIRouter, HTTPException, Depends
from typing import List
from backend.models import CveItem, SeverityEnum
from backend.storage import get_persisted_cves, save_persisted_cves
from backend.routers.auth import get_current_user, require_admin

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Database"])

CVE_CATALOG = get_persisted_cves()


@router.get("", response_model=List[CveItem])
def search_cves(query: str = "", current_user: dict = Depends(get_current_user)):
    if not query:
        return CVE_CATALOG
    q = query.lower()
    return [c for c in CVE_CATALOG if q in c["cve_id"].lower() or q in c["title"].lower() or q in c["summary"].lower()]


@router.post("", response_model=CveItem)
def add_cve(cve_in: CveItem, current_user: dict = Depends(require_admin)):
    for c in CVE_CATALOG:
        if c["cve_id"] == cve_in.cve_id:
            raise HTTPException(status_code=400, detail="CVE ID already exists")
    cve_dict = cve_in.dict()
    CVE_CATALOG.append(cve_dict)
    save_persisted_cves(CVE_CATALOG)
    return cve_dict


@router.delete("/{cve_id}")
def delete_cve(cve_id: str, current_user: dict = Depends(require_admin)):
    global CVE_CATALOG
    initial_len = len(CVE_CATALOG)
    CVE_CATALOG = [c for c in CVE_CATALOG if c.get("cve_id") != cve_id]
    if len(CVE_CATALOG) == initial_len:
        raise HTTPException(status_code=404, detail="CVE record not found")
    save_persisted_cves(CVE_CATALOG)
    return {"message": f"CVE record {cve_id} deleted successfully."}
