# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime

class RoleEnum(str, Enum):
    ADMIN = "Admin"
    ANALYST = "Security Analyst"
    MANAGER = "Manager"
    VIEWER = "Viewer"

class ScanTypeEnum(str, Enum):
    QUICK = "Quick Scan"
    FULL = "Full Vulnerability Scan"
    WEB = "Web Security Scan"
    NETWORK = "Network Scan"
    PORT = "Port Scan"
    SSL = "SSL Scan"
    API = "API Security Scan"
    OWASP = "OWASP Top 10 Scan"
    SAST = "Source Code Security Scan"
    DEPENDENCY = "Dependency Scan"
    CONFIG = "Configuration Audit"

class TargetTypeEnum(str, Enum):
    URL = "Website URL"
    IP = "IP Address"
    DOMAIN = "Domain"
    SERVER = "Server"
    CIDR = "Network (CIDR)"
    REPO = "GitHub Repository"
    FOLDER = "Local Folder"
    CONTAINER = "Docker Container"
    CLOUD = "Cloud Instance"
    ZIP = "Uploaded ZIP"

class SeverityEnum(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

# --- Authentication Models ---
class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: RoleEnum = RoleEnum.ANALYST
    full_name: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: RoleEnum
    full_name: str
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# --- Asset Models ---
class AssetCreate(BaseModel):
    name: str
    target: str
    asset_type: TargetTypeEnum
    tags: List[str] = []
    owner: str = "Security Team"
    department: str = "DevOps / InfoSec"

class AssetResponse(BaseModel):
    id: str
    name: str
    target: str
    asset_type: TargetTypeEnum
    tags: List[str]
    owner: str
    department: str
    status: str = "Active"
    last_scanned: Optional[str] = None

# --- Scan Models ---
class ScanCreate(BaseModel):
    target: str
    target_type: TargetTypeEnum
    scan_types: List[ScanTypeEnum]
    asset_id: Optional[str] = None
    custom_notes: Optional[str] = ""

class VulnerabilityItem(BaseModel):
    id: str
    title: str
    severity: SeverityEnum
    cvss_score: float
    cve_id: Optional[str] = "N/A"
    owasp_category: Optional[str] = "N/A"
    mitre_attack: Optional[str] = "N/A"
    affected_asset: str
    description: str
    evidence: str
    remediation: str

class AIRiskSummary(BaseModel):
    overall_risk_score: float
    business_impact: str
    technical_impact: str
    likelihood: str
    recommendations: List[str]
    patch_priority: List[str]
    executive_summary: str

class UserSignup(BaseModel):
    username: str
    email: str
    password: str
    full_name: str

class ScanResultResponse(BaseModel):
    id: str
    target: str
    target_type: TargetTypeEnum
    scan_types: List[ScanTypeEnum]
    status: str # Queued, Running, Completed, Failed
    progress: int # 0 to 100
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: Optional[int] = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    vulnerabilities: List[VulnerabilityItem] = []
    ai_analysis: Optional[AIRiskSummary] = None
    logs: List[str] = []
    requested_by: Optional[str] = None
    parent_scan_id: Optional[str] = None
    remediation_diff: Optional[Dict[str, Any]] = None

# --- CVE Knowledgebase Models ---
class CveItem(BaseModel):
    cve_id: str
    title: str
    severity: SeverityEnum
    cvss_score: float = 8.0
    cisa_kev: Optional[bool] = True
    exploit_available: Optional[bool] = True
    summary: str
    affected_products: Optional[List[str]] = ["Production System"]
    published_date: Optional[str] = "2026-09-30"

