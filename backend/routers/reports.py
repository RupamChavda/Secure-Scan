from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse
from typing import Optional
from backend.routers.scans import SCANS_DB
from backend.routers.auth import get_current_user, USERS_DB
from backend.config import settings
import jwt

router = APIRouter(prefix="/reports", tags=["Report Generator"])


@router.get("/{scan_id}/json")
def export_json_report(scan_id: str, token: Optional[str] = Query(None), current_user: dict = Depends(get_current_user)):
    scan = SCANS_DB.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan report not found")

    report_data = {
        "platform": "SecureScan AI v1.0",
        "generated_at": scan.get("end_time") or scan.get("start_time"),
        "auditor": current_user.get("full_name", "Security Analyst"),
        "scan_summary": scan
    }
    return report_data


def _severity_gauge_color(score) -> str:
    try:
        score = float(score)
    except Exception:
        return "#64748b"
    if score >= 9.0:
        return "#dc2626"
    if score >= 7.0:
        return "#ea580c"
    if score >= 4.0:
        return "#eab308"
    return "#16a34a"


def _severity_plain_label(score) -> str:
    try:
        score = float(score)
    except Exception:
        return "Unknown"
    if score >= 9.0:
        return "SEVERE — Act immediately"
    if score >= 7.0:
        return "SERIOUS — Act soon"
    if score >= 4.0:
        return "MODERATE — Plan a fix"
    if score > 0:
        return "MINOR — Low concern"
    return "NO RISK FOUND"


@router.get("/{scan_id}/html")
@router.get("/{scan_id}/pdf")
def export_pdf_report(
    scan_id: str,
    token: Optional[str] = Query(None, description="JWT for direct-link access from the browser"),
):
    # Reports opened via a plain <a href> link can't send an Authorization header,
    # so authenticate via the query-string token in that case.
    user = None
    if token:
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub")
            user = USERS_DB.get(username)
        except Exception:
            user = None
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated. Please log in to view this report.")

    scan = SCANS_DB.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan report not found")

    if hasattr(scan, "dict"):
        scan_dict = scan.dict()
    elif isinstance(scan, dict):
        scan_dict = scan
    else:
        scan_dict = dict(scan)

    ai_data = scan_dict.get("ai_analysis") or {}
    if hasattr(ai_data, "dict"):
        ai_data = ai_data.dict()

    risk_score = ai_data.get("overall_risk_score", 0)
    business_impact = ai_data.get("business_impact", "No business impact analysis is available for this scan yet.")
    technical_impact = ai_data.get("technical_impact", "No technical impact analysis is available for this scan yet.")
    likelihood = ai_data.get("likelihood", "Unknown")
    executive_summary = ai_data.get("executive_summary", f"Automated security audit for target '{scan_dict.get('target')}' identified {scan_dict.get('total_vulnerabilities', 0)} security findings.")
    recommendations = ai_data.get("recommendations", [])
    patch_priority = ai_data.get("patch_priority", [])

    gauge_color = _severity_gauge_color(risk_score)
    plain_label = _severity_plain_label(risk_score)

    vulns_html = ""
    vulnerabilities = scan_dict.get("vulnerabilities", [])
    for idx, v in enumerate(vulnerabilities, 1):
        if hasattr(v, "dict"):
            v = v.dict()
        v_title = v.get("title", "")
        v_sev = v.get("severity", "Medium")
        v_cve = v.get("cve_id", "N/A") or "N/A"
        v_owasp = v.get("owasp_category", "N/A") or "N/A"
        v_cvss = v.get("cvss_score", "N/A")
        v_desc = v.get("description", "")
        v_evid = v.get("evidence", "")
        v_remed = v.get("remediation", "")

        sev_color = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#eab308", "Low": "#16a34a", "Info": "#0ea5e9"}.get(v_sev, "#64748b")

        vulns_html += f"""
        <div style="background: #ffffff; border-left: 6px solid {sev_color}; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border: 1px solid #e2e8f0;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
                <h3 style="color: #0f172a; margin: 0; font-size: 18px;">#{idx}. {v_title}</h3>
                <span style="background:{sev_color}; color:white; font-size:12px; font-weight:700; padding:4px 12px; border-radius:20px; text-transform:uppercase;">{v_sev} (Score {v_cvss}/10)</span>
            </div>
            <p style="color: #64748b; font-size: 13px; margin-bottom: 12px;"><strong>Reference ID:</strong> {v_cve} &nbsp;|&nbsp; <strong>Category:</strong> {v_owasp}</p>

            <div style="background: #f8fafc; padding: 12px; border-radius: 6px; margin-bottom: 12px; border: 1px solid #f1f5f9;">
                <strong style="color: #334155; font-size: 14px;">🗣️ In Plain English — What does this mean for your business?</strong>
                <p style="color: #475569; font-size: 14px; margin-top: 4px; line-height: 1.5;">{v_desc}</p>
            </div>

            <div style="margin-bottom: 12px;">
                <strong style="color: #334155; font-size: 13px;">🔎 Technical Evidence (for your IT team):</strong>
                <pre style="background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; font-size: 12px; overflow-x: auto; margin-top: 6px; white-space: pre-wrap; word-break: break-word;">{v_evid}</pre>
            </div>

            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 12px; border-radius: 6px;">
                <strong style="color: #166534; font-size: 14px;">💡 How to Fix It:</strong>
                <p style="color: #15803d; font-size: 14px; margin-top: 4px;">{v_remed}</p>
            </div>
        </div>
        """

    rec_list_html = "".join([f"<li style='margin-bottom: 8px;'>{r}</li>" for r in recommendations]) or "<li>No specific recommendations — no issues found.</li>"
    priority_list_html = "".join([f"<li style='margin-bottom: 8px; font-weight: 600; color: #b91c1c;'>{p}</li>" for p in patch_priority]) or "<li>No urgent patches required.</li>"

    end_time = scan_dict.get("end_time")
    audit_date = end_time[:10] if end_time else scan_dict.get("start_time", "")[:10]

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureScan AI - Executive Security Report</title>
        <meta charset="UTF-8">
        <style>
            @media print {{
                .no-print {{ display: none !important; }}
                body {{ background: #fff !important; color: #000 !important; padding: 0 !important; }}
                .page-break {{ page-break-before: always; }}
            }}
            body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background-color: #f1f5f9; color: #1e293b; padding: 40px; margin: 0; }}
            .container {{ max-width: 900px; margin: 0 auto; background: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #0284c7; padding-bottom: 20px; margin-bottom: 30px; flex-wrap: wrap; gap: 12px; }}
            .title {{ font-size: 26px; color: #0284c7; font-weight: 800; display: flex; align-items: center; gap: 10px; }}
            .meta {{ color: #64748b; font-size: 13px; text-align: right; }}

            .banner-box {{ background: linear-gradient(135deg, #0f172a, #1e293b); color: #f8fafc; padding: 24px; border-radius: 10px; margin-bottom: 20px; }}
            .banner-box h2 {{ margin: 0 0 10px 0; color: #38bdf8; font-size: 20px; }}
            .banner-box p {{ margin: 0; color: #cbd5e1; font-size: 14px; line-height: 1.6; }}

            .gauge-row {{ display:flex; align-items:center; gap:20px; background:#f8fafc; border:1px solid #e2e8f0; padding:18px; border-radius:10px; margin-bottom:30px; }}
            .gauge-circle {{ min-width:90px; height:90px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:22px; font-weight:800; color:white; background:{gauge_color}; }}

            .stat-grid {{ display: flex; gap: 16px; margin-bottom: 30px; flex-wrap: wrap; }}
            .stat-card {{ background: #f8fafc; padding: 18px; border-radius: 8px; flex: 1; min-width: 140px; text-align: center; border: 1px solid #e2e8f0; }}
            .stat-label {{ font-size: 12px; text-transform: uppercase; color: #64748b; font-weight: 600; }}
            .stat-val {{ font-size: 26px; font-weight: 800; margin-top: 6px; }}

            .section-title {{ font-size: 20px; color: #0f172a; margin-bottom: 16px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; font-weight: 700; }}
            .impact-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }}
            .impact-card {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 18px; border-radius: 8px; }}
            .impact-card h4 {{ margin: 0 0 8px 0; color: #0369a1; font-size: 15px; }}

            .glossary {{ background:#eff6ff; border:1px solid #bfdbfe; padding:16px 20px; border-radius:8px; margin-bottom:30px; font-size:13px; color:#1e3a8a; }}
            .glossary strong {{ color: #1d4ed8; }}

            .btn-print {{ background: #0284c7; color: white; border: none; padding: 12px 24px; font-size: 14px; font-weight: 700; border-radius: 8px; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3); }}
            .btn-print:hover {{ background: #0369a1; }}
            @media (max-width: 640px) {{ .impact-grid {{ grid-template-columns: 1fr; }} }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="no-print" style="margin-bottom: 20px; text-align: right;">
                <button class="btn-print" onclick="window.print()">🖨️ Download PDF / Print This Report</button>
            </div>

            <div class="header">
                <div>
                    <div class="title">🛡️ SecureScan AI</div>
                    <div style="font-size: 13px; color: #64748b; margin-top: 4px;">Executive Security Audit Report — Written for Non-Technical Readers</div>
                </div>
                <div class="meta">
                    <div><strong>Target Asset:</strong> {scan_dict.get('target')}</div>
                    <div><strong>Report ID:</strong> {scan_dict.get('id')}</div>
                    <div><strong>Audit Date:</strong> {audit_date or 'N/A'}</div>
                    <div><strong>Prepared for:</strong> {user.get('full_name', 'Security Team')}</div>
                </div>
            </div>

            <div class="banner-box">
                <h2>📋 Executive Summary</h2>
                <p>{executive_summary}</p>
            </div>

            <div class="gauge-row">
                <div class="gauge-circle">{risk_score}/10</div>
                <div>
                    <div style="font-size:16px; font-weight:800; color:{gauge_color};">{plain_label}</div>
                    <div style="font-size:13px; color:#64748b; margin-top:4px;">This score summarizes overall risk from this scan on a scale of 0 (no risk) to 10 (extreme risk). It is calculated from how many issues were found and how severe they are.</div>
                </div>
            </div>

            <div class="stat-grid">
                <div class="stat-card"><div class="stat-label">Total Findings</div><div class="stat-val" style="color:#0284c7;">{scan_dict.get('total_vulnerabilities', 0)}</div></div>
                <div class="stat-card"><div class="stat-label">Critical (Fix Now)</div><div class="stat-val" style="color:#dc2626;">{scan_dict.get('critical_count', 0)}</div></div>
                <div class="stat-card"><div class="stat-label">High (Fix Soon)</div><div class="stat-val" style="color:#ea580c;">{scan_dict.get('high_count', 0)}</div></div>
                <div class="stat-card"><div class="stat-label">Medium / Low</div><div class="stat-val" style="color:#7c3aed;">{scan_dict.get('medium_count', 0) + scan_dict.get('low_count', 0)}</div></div>
            </div>

            <div class="glossary">
                <strong>How to read this report (for non-technical readers):</strong>
                &nbsp;<strong>Critical</strong> = attackers can likely break in easily, fix immediately.
                &nbsp;<strong>High</strong> = a serious weakness, fix within days.
                &nbsp;<strong>Medium</strong> = worth fixing soon, lower urgency.
                &nbsp;<strong>Low/Info</strong> = minor or informational, address when convenient.
            </div>

            <h3 class="section-title">📊 Business & Technical Risk Breakdown</h3>
            <div class="impact-grid">
                <div class="impact-card">
                    <h4>💼 What This Means For The Business</h4>
                    <p style="margin:0; font-size:13px; color:#475569; line-height:1.5;">{business_impact}</p>
                </div>
                <div class="impact-card">
                    <h4>⚙️ Technical Impact & Likelihood</h4>
                    <p style="margin:0; font-size:13px; color:#475569; line-height:1.5;"><strong>Impact:</strong> {technical_impact}<br><br><strong>Likelihood of Exploitation:</strong> {likelihood}</p>
                </div>
            </div>

            <h3 class="section-title">🚀 Action Plan & Fix Priorities</h3>
            <div style="background:#fef2f2; border:1px solid #fecaca; padding:18px; border-radius:8px; margin-bottom:12px;">
                <ol style="margin:0; padding-left:20px; font-size:14px;">
                    {priority_list_html}
                </ol>
            </div>
            <div style="background:#f0f9ff; border:1px solid #bae6fd; padding:18px; border-radius:8px; margin-bottom:30px;">
                <strong style="color:#0369a1; font-size:14px;">General Recommendations:</strong>
                <ul style="margin:8px 0 0 0; padding-left:20px; font-size:14px; color:#334155;">
                    {rec_list_html}
                </ul>
            </div>

            <div class="page-break"></div>
            <h3 class="section-title">🔍 Detailed Security Findings & How To Fix Them</h3>
            {vulns_html if vulns_html else '<p style="color:#64748b;">No vulnerabilities detected during this scan execution.</p>'}

            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; text-align: center; color: #94a3b8; font-size: 12px;">
                Generated automatically by SecureScan AI Security Platform &bull; Confidential Report &bull; Scan ID: {scan_dict.get('id')}
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
