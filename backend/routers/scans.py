# pyrefly: ignore [missing-import]
import time
import uuid
import os
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, UploadFile, File  # type: ignore
from backend.config import settings
from backend.models import (
    ScanCreate, ScanResultResponse, TargetTypeEnum, ScanTypeEnum,
    VulnerabilityItem, SeverityEnum, AIRiskSummary
)
from backend.routers.auth import get_current_user, require_admin
from backend.scanners import (
    run_nmap_scan, run_trivy_scan, run_owasp_zap_scan, run_openvas_scan,
    run_live_port_scan, run_http_security_scan, run_ssl_scan, run_static_code_scan
)
from backend.storage import get_persisted_scans, save_persisted_scans

router = APIRouter(prefix="/scans", tags=["Scan Engine"])

# Initialize SCANS_DB from persistent disk storage so scan HISTORY survives restarts.
SCANS_DB = get_persisted_scans()


def _severity_weight(sev) -> float:
    sev = str(sev)
    return {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0, "Info": 0.0}.get(sev, 1.0)


def generate_ai_analysis(target: str, vulns: List[dict]) -> AIRiskSummary:
    """
    Synthesizes a plain-language, non-technical risk summary from the actual
    discovered findings for this specific scan (not a fixed template) — the
    business impact and recommendations text is generated dynamically based
    on what was really found.
    """
    def sev_of(v):
        return v.get("severity") if isinstance(v, dict) else getattr(v, "severity")

    crit_count = sum(1 for v in vulns if str(sev_of(v)) == "Critical")
    high_count = sum(1 for v in vulns if str(sev_of(v)) == "High")
    med_count = sum(1 for v in vulns if str(sev_of(v)) == "Medium")
    low_count = sum(1 for v in vulns if str(sev_of(v)) == "Low")

    # Weighted score capped at 10 — heavier weight on critical/high findings for accuracy.
    raw_score = crit_count * 3.2 + high_count * 1.8 + med_count * 0.6 + low_count * 0.15
    score = round(min(10.0, raw_score), 1)

    if crit_count > 0:
        business_impact = (
            f"This scan found {crit_count} CRITICAL issue(s) on '{target}'. In plain terms, these are the kind of "
            f"weaknesses that let an outside attacker break in, steal data, or take over the system with relatively "
            f"little effort. This should be treated as an emergency and fixed as soon as possible."
        )
        likelihood = "Very High — critical findings are typically easy for automated attack tools to discover and exploit."
    elif high_count > 0:
        business_impact = (
            f"This scan found {high_count} HIGH severity issue(s) on '{target}'. These significantly increase the "
            f"chance of a security incident (data exposure, service disruption, or unauthorized access) and should "
            f"be scheduled for prompt remediation."
        )
        likelihood = "High — these issues are commonly targeted once discovered, though they may need more effort to exploit than critical findings."
    elif med_count > 0:
        business_impact = (
            f"This scan found {med_count} MEDIUM severity issue(s) on '{target}'. On their own these are less "
            f"urgent, but they weaken the overall security posture and can be combined with other issues by a "
            f"determined attacker."
        )
        likelihood = "Moderate — exploitation typically requires specific conditions or additional weaknesses to be present."
    elif low_count > 0:
        business_impact = (
            f"This scan found only lower-risk, informational issues on '{target}'. There is no urgent threat, but "
            f"addressing these will further strengthen your security posture."
        )
        likelihood = "Low — these findings are unlikely to be exploited on their own."
    else:
        business_impact = f"No security issues were identified on '{target}' during this scan. Keep up regular scanning to catch new risks early."
        likelihood = "Minimal — no exploitable weaknesses were found in this scan."

    technical_impact = (
        f"Findings breakdown for this scan: {crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low. "
        + ("Exploitable vectors include network exposure, injection flaws, missing security headers/encryption, or leaked credentials, depending on the specific findings below." if vulns else "No exploitable technical vectors were identified.")
    )

    recommendations = []
    if crit_count > 0:
        recommendations.append("Fix all Critical findings first — these pose the greatest and most immediate risk.")
    if high_count > 0:
        recommendations.append("Schedule High severity findings for remediation within the next few days.")
    recommendations.append("Re-run this scan after applying fixes to confirm the issues are resolved.")
    recommendations.append("Review the detailed findings below with your technical/IT team for step-by-step fixes.")

    patch_priority = []
    if crit_count > 0:
        patch_priority.append(f"P0: Remediate {crit_count} Critical finding(s) — Within 24 Hours")
    if high_count > 0:
        patch_priority.append(f"P1: Remediate {high_count} High finding(s) — Within 3-5 Days")
    if med_count > 0:
        patch_priority.append(f"P2: Remediate {med_count} Medium finding(s) — Within 30 Days")
    if not patch_priority:
        patch_priority.append("No urgent patches required based on current findings.")

    executive_summary = (
        f"Automated security audit for '{target}' identified {len(vulns)} total finding(s): "
        f"{crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low. "
        + ("Immediate attention is required." if crit_count > 0 else
           "Prompt review is recommended." if high_count > 0 else
           "No urgent action is required, but continued monitoring is advised.")
    )

    return AIRiskSummary(
        overall_risk_score=score,
        business_impact=business_impact,
        technical_impact=technical_impact,
        likelihood=likelihood,
        recommendations=recommendations,
        patch_priority=patch_priority,
        executive_summary=executive_summary
    )


def execute_scan_job(scan_id: str):
    """
    Runs the actual dynamic scan pipeline for a queued scan job. Every scan
    is evaluated live against its specific target — nothing here is a fixed
    canned result; findings depend entirely on what is actually detected for
    THIS target at THIS point in time.
    """
    scan = SCANS_DB.get(scan_id)
    if not scan:
        return

    def log(msg: str):
        scan["logs"].append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}")

    scan["status"] = "Running"
    log("Starting SecureScan AI dynamic scan engine...")
    log(f"Analyzing target fingerprint: {scan['target']}")
    scan["progress"] = 10
    save_persisted_scans(SCANS_DB)
    time.sleep(0.5)

    target_str = str(scan["target"])
    target_type = str(scan.get("target_type", "")).lower()

    discovered_vulns = []
    is_zip_target = "zip" in target_type or "uploaded" in target_str.lower() or target_str.lower().endswith((".zip", ".tar", ".tar.gz", ".gz"))
    is_network_target = "ip" in target_type or "server" in target_type or "cidr" in target_type
    is_web_target = "website" in target_type or "url" in target_type or "domain" in target_type or target_str.startswith("http")

    try:
        if is_zip_target:
            log("Running static source code analysis: secret detection & dependency CVE audit...")
            scan["progress"] = 30
            save_persisted_scans(SCANS_DB)
            archive_path = scan.get("_archive_path")
            if archive_path and os.path.exists(archive_path):
                discovered_vulns.extend(run_static_code_scan(archive_path))
            discovered_vulns.extend(run_trivy_scan(archive_path or target_str))

        elif is_network_target:
            log("Executing live network port scan against target host...")
            scan["progress"] = 30
            save_persisted_scans(SCANS_DB)
            discovered_vulns.extend(run_live_port_scan(target_str))
            discovered_vulns.extend(run_nmap_scan(target_str))

            log("Checking for HTTPS/TLS service exposure...")
            scan["progress"] = 55
            save_persisted_scans(SCANS_DB)
            discovered_vulns.extend(run_ssl_scan(target_str))

        else:
            # Web URL / domain / generic target
            log("Running live HTTP security header & configuration analysis...")
            scan["progress"] = 30
            save_persisted_scans(SCANS_DB)
            discovered_vulns.extend(run_http_security_scan(target_str))

            log("Performing live TLS/SSL certificate & protocol scan...")
            scan["progress"] = 50
            save_persisted_scans(SCANS_DB)
            discovered_vulns.extend(run_ssl_scan(target_str))

            log("Scanning for exposed network ports...")
            scan["progress"] = 65
            save_persisted_scans(SCANS_DB)
            discovered_vulns.extend(run_live_port_scan(target_str))

            discovered_vulns.extend(run_owasp_zap_scan(target_str))

        scan["progress"] = 80
        save_persisted_scans(SCANS_DB)

        # Optional deep-scan tool (only adds a finding if a live GVM daemon is reachable)
        discovered_vulns.extend(run_openvas_scan(target_str))

    except Exception as e:
        log(f"Scan module error: {str(e)}")

    # Assign IDs / affected asset to every finding
    for idx, v in enumerate(discovered_vulns):
        v["id"] = f"vuln-{scan_id[:6]}-{idx + 1}"
        v["affected_asset"] = scan["target"]
        v.setdefault("cve_id", "N/A")
        v.setdefault("owasp_category", "N/A")
        v.setdefault("mitre_attack", "N/A")

    def get_sev_str(v):
        sev = v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")
        if hasattr(sev, "value"):
            sev = sev.value
        return str(sev).strip().lower()

    scan["vulnerabilities"] = discovered_vulns
    scan["total_vulnerabilities"] = len(discovered_vulns)
    scan["critical_count"] = sum(1 for v in discovered_vulns if "crit" in get_sev_str(v))
    scan["high_count"] = sum(1 for v in discovered_vulns if "high" in get_sev_str(v))
    scan["medium_count"] = sum(1 for v in discovered_vulns if "med" in get_sev_str(v))
    scan["low_count"] = sum(1 for v in discovered_vulns if "low" in get_sev_str(v) or "info" in get_sev_str(v))

    log(f"Invoking AI Risk Analysis Engine for target '{scan['target']}'...")
    ai_res = generate_ai_analysis(scan["target"], discovered_vulns).dict()

    # Calculate Remediation Diff if this scan is a rescan of a previous scan
    if scan.get("parent_scan_id") and scan["parent_scan_id"] in SCANS_DB:
        parent = SCANS_DB[scan["parent_scan_id"]]
        parent_vulns = parent.get("vulnerabilities", [])
        new_vuln_titles = set(v.get("title") for v in discovered_vulns)
        
        resolved_vulns = [v for v in parent_vulns if v.get("title") not in new_vuln_titles]
        resolved_count = len(resolved_vulns)
        initial_count = parent.get("total_vulnerabilities", 0)
        remaining_count = len(discovered_vulns)
        
        scan["remediation_diff"] = {
            "parent_scan_id": scan["parent_scan_id"],
            "initial_count": initial_count,
            "resolved_count": resolved_count,
            "remaining_count": remaining_count,
            "resolved_titles": [v.get("title") for v in resolved_vulns]
        }
        
        # Append remediation summary note to AI executive summary
        ai_res["executive_summary"] += (
            f" [RESCAN AUDIT RESULTS]: {resolved_count} out of {initial_count} initial vulnerability finding(s) "
            f"were successfully resolved in this audit! {remaining_count} finding(s) remain."
        )

    scan["ai_analysis"] = ai_res

    scan["progress"] = 100
    scan["status"] = "Completed"
    scan["end_time"] = datetime.utcnow().isoformat() + "Z"
    start_dt = datetime.fromisoformat(scan["start_time"].replace("Z", ""))
    scan["duration_seconds"] = max(1, int((datetime.utcnow() - start_dt).total_seconds()))
    log("Scan completed. Executive report is ready to view.")

    scan.pop("_archive_path", None)
    save_persisted_scans(SCANS_DB)


def _new_scan_record(scan_id: str, target: str, target_type, scan_types, requested_by: str, extra_logs=None) -> dict:
    start_time = datetime.utcnow().isoformat() + "Z"
    return {
        "id": scan_id,
        "target": target,
        "target_type": target_type,
        "scan_types": scan_types,
        "status": "Queued",
        "progress": 0,
        "start_time": start_time,
        "end_time": None,
        "duration_seconds": 0,
        "total_vulnerabilities": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "vulnerabilities": [],
        "ai_analysis": None,
        "requested_by": requested_by,
        "logs": [f"[{datetime.utcnow().strftime('%H:%M:%S')}] Scan request queued for target {target}."] + (extra_logs or [])
    }


@router.post("", response_model=ScanResultResponse)
def create_scan(scan_in: ScanCreate, background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    scan_obj = _new_scan_record(scan_id, scan_in.target, scan_in.target_type, scan_in.scan_types, current_user["username"])

    SCANS_DB[scan_id] = scan_obj
    save_persisted_scans(SCANS_DB)  # persist immediately so it shows up in scan history right away
    background_tasks.add_task(execute_scan_job, scan_id)
    return scan_obj


@router.post("/upload", response_model=ScanResultResponse)
async def upload_project_zip(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    valid_exts = (".zip", ".rar", ".7z", ".tar.gz", ".gz", ".tar")
    if not any(file.filename.lower().endswith(ext) for ext in valid_exts):
        raise HTTPException(status_code=400, detail="Only compressed project archives (.zip, .rar, .7z, .tar.gz) are supported")

    file_location = os.path.join(settings.UPLOAD_DIR, file.filename)
    with open(file_location, "wb+") as file_object:
        file_object.write(await file.read())

    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    scan_obj = _new_scan_record(
        scan_id,
        f"Uploaded Project: {file.filename}",
        TargetTypeEnum.ZIP,
        [ScanTypeEnum.SAST, ScanTypeEnum.DEPENDENCY, ScanTypeEnum.OWASP],
        current_user["username"],
        extra_logs=[f"[{datetime.utcnow().strftime('%H:%M:%S')}] Extraction and static analysis queued."]
    )
    scan_obj["_archive_path"] = file_location

    SCANS_DB[scan_id] = scan_obj
    save_persisted_scans(SCANS_DB)
    background_tasks.add_task(execute_scan_job, scan_id)
    return scan_obj


@router.get("", response_model=List[ScanResultResponse])
def list_scans(current_user: dict = Depends(get_current_user)):
    """Returns user-scoped scan HISTORY (or all for Admin), most recent first."""
    scans_db = get_persisted_scans()
    scans = list(scans_db.values())
    if current_user.get("role") != "Admin":
        scans = [s for s in scans if s.get("requested_by") == current_user.get("username")]
    return sorted(scans, key=lambda s: s.get("start_time", ""), reverse=True)


@router.get("/{scan_id}", response_model=ScanResultResponse)
def get_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    scans_db = get_persisted_scans()
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return scans_db[scan_id]


@router.post("/{scan_id}/rescan", response_model=ScanResultResponse)
def rescan_target(scan_id: str, background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    """Initiates a fresh live security audit on a previously scanned target to verify bug fixes."""
    scans_db = get_persisted_scans()
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Original scan record not found")

    parent_scan = scans_db[scan_id]
    new_scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    scan_obj = _new_scan_record(
        new_scan_id,
        parent_scan["target"],
        parent_scan["target_type"],
        parent_scan["scan_types"],
        current_user["username"],
        extra_logs=[f"[{datetime.utcnow().strftime('%H:%M:%S')}] Rescan audit initiated for previous scan '{scan_id}'."]
    )
    scan_obj["parent_scan_id"] = scan_id

    scans_db[new_scan_id] = scan_obj
    save_persisted_scans(scans_db)
    background_tasks.add_task(execute_scan_job, new_scan_id)
    return scan_obj


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, current_user: dict = Depends(require_admin)):
    scans_db = get_persisted_scans()
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan record not found")
    del scans_db[scan_id]
    save_persisted_scans(scans_db)
    return {"message": f"Scan record {scan_id} deleted successfully."}
