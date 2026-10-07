from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from backend.models import AIRiskSummary, SeverityEnum
from backend.routers.auth import get_current_user

router = APIRouter(prefix="/ai", tags=["AI Risk Analysis"])

class AIExplainRequest(BaseModel):
    vulnerability_title: str
    cve_id: Optional[str] = "N/A"
    description: str

class AIExplainResponse(BaseModel):
    explanation: str
    remediation_steps: List[str]
    cwe_code: str

class AIChatRequest(BaseModel):
    message: str

class AIChatResponse(BaseModel):
    response: str
    suggested_actions: List[str]

@router.post("/chat", response_model=AIChatResponse)
def ai_chat_copilot(req: AIChatRequest, current_user: dict = Depends(get_current_user)):
    msg = req.message.lower()
    
    if "sql" in msg:
        reply = "SQL Injection occurs when unvalidated user input is directly concatenated into database queries. **Remediation**: Use parameterized queries / prepared statements via ORMs like SQLAlchemy or Django ORM.\n```python\n# Secure Example\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n```"
        actions = ["Enforce ORM parameterization", "Enable Web Application Firewall (WAF)", "Audit raw SQL statements"]
    elif "log4j" in msg or "cve-2021-44228" in msg:
        reply = "Log4Shell (CVE-2021-44228) allows remote code execution via LDAP JNDI lookups in Apache Log4j2 versions 2.0-beta9 to 2.14.1. **Remediation**: Upgrade `log4j-core` to version **2.17.1** or higher immediately."
        actions = ["Upgrade log4j-core to >= 2.17.1", "Set system property -Dlog4j2.formatMsgNoLookups=true"]
    elif "xss" in msg:
        reply = "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into trusted web pages. **Remediation**: Contextually encode user inputs in HTML templates, and enforce a strong Content-Security-Policy (CSP) header."
        actions = ["Configure CSP HTTP Header", "Use DOM-safe textContent instead of innerHTML", "Contextually encode HTML outputs"]
    elif "secret" in msg or "aws" in msg or "token" in msg:
        reply = "Hardcoded credentials in source code pose a critical security risk if repositories are accessed or exposed. **Remediation**: Revoke the exposed keys, migrate credentials to Environment Variables or Secret Managers (e.g. AWS Secrets Manager / HashiCorp Vault)."
        actions = ["Revoke exposed API keys", "Add .env to .gitignore", "Scan repo with GitLeaks"]
    else:
        reply = f"I am your **SecureScan Assistant**. I analyzed your query regarding '{req.message}'. For target security, prioritize remediating Critical/High severity findings, enforcing strict input validation, keeping dependencies updated, and reviewing generated PDF executive reports."

        actions = ["Run SAST audit on project archive", "View Executive PDF Security Report", "Scan target IP for open ports"]

    return AIChatResponse(
        response=reply,
        suggested_actions=actions
    )

@router.post("/explain", response_model=AIExplainResponse)
def explain_vulnerability(req: AIExplainRequest, current_user: dict = Depends(get_current_user)):
    return AIExplainResponse(
        explanation=f"The finding '{req.vulnerability_title}' ({req.cve_id}) indicates a security gap where an attacker can exploit improperly formatted input handling or missing access controls. In simple terms, user input is processed directly without sufficient validation.",
        remediation_steps=[
            "Sanitize and validate all incoming request parameters.",
            "Use parameterized database queries and modern frameworks with built-in protection.",
            "Implement strict Content Security Policy headers and rate limiting."
        ],
        cwe_code="CWE-89 / CWE-79"
    )

