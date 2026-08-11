import json
import os
from typing import Dict, List, Any

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

SCANS_FILE = os.path.join(DATA_DIR, "scans_db.json")
ASSETS_FILE = os.path.join(DATA_DIR, "assets_db.json")
CVE_FILE = os.path.join(DATA_DIR, "cve_db.json")
USERS_FILE = os.path.join(DATA_DIR, "users_db.json")

def load_json(filepath: str, default_data: Any) -> Any:
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default_data
    return default_data

def save_json(filepath: str, data: Any):
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        print(f"Error saving JSON to {filepath}: {e}")

# Initial Default Datasets
DEFAULT_ASSETS = [
    {
        "id": "ast-001",
        "name": "CyberShield Production Web Portal",
        "target": "https://app.corp-securescan.internal",
        "asset_type": "Website URL",
        "tags": ["Production", "Web", "PCI-DSS"],
        "owner": "AppSec Team",
        "department": "Engineering",
        "status": "Active",
        "last_scanned": "2026-08-05T20:00:00Z"
    },
    {
        "id": "ast-002",
        "name": "Core Banking API Gateway",
        "target": "192.168.10.45",
        "asset_type": "IP Address",
        "tags": ["PCI-DSS", "Critical", "API"],
        "owner": "Infrastructure Team",
        "department": "IT Operations",
        "status": "Active",
        "last_scanned": "2026-08-06T10:15:00Z"
    },
    {
        "id": "ast-003",
        "name": "CyberShield Source Repo Archive",
        "target": "CyberShield_COMPLETE.zip",
        "asset_type": "Uploaded ZIP",
        "tags": ["SourceCode", "Python", "Secrets Audit"],
        "owner": "DevSecOps",
        "department": "Engineering",
        "status": "Active",
        "last_scanned": "2026-08-06T18:00:00Z"
    }
]

DEFAULT_CVES = [
    {
        "cve_id": "CVE-2024-3094",
        "title": "XZ Utils Backdoor Remote Code Execution",
        "severity": "Critical",
        "cvss_score": 10.0,
        "cisa_kev": True,
        "exploit_available": True,
        "summary": "Malicious code discovered in XZ Utils versions 5.6.0 and 5.6.1 allowing SSH authentication bypass.",
        "affected_products": ["XZ Utils 5.6.0", "XZ Utils 5.6.1", "Fedora 40", "Debian Testing"],
        "published_date": "2024-03-29"
    },
    {
        "cve_id": "CVE-2023-45853",
        "title": "Zlib Buffer Overflow Vulnerability",
        "severity": "High",
        "cvss_score": 8.8,
        "cisa_kev": False,
        "exploit_available": True,
        "summary": "Integer overflow in zlib zipOpenNewFileInZip4 allows remote code execution via malformed ZIP archives.",
        "affected_products": ["Zlib <= 1.3", "Minizip <= 1.3"],
        "published_date": "2023-10-14"
    },
    {
        "cve_id": "CVE-2021-44228",
        "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "severity": "Critical",
        "cvss_score": 10.0,
        "cisa_kev": True,
        "exploit_available": True,
        "summary": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP lookups leading to RCE.",
        "affected_products": ["Apache Log4j 2.0 - 2.14.1"],
        "published_date": "2021-12-10"
    },
    {
        "cve_id": "CVE-2023-38606",
        "title": "Apple iOS Kernel Memory Corruption Vulnerability",
        "severity": "High",
        "cvss_score": 7.8,
        "cisa_kev": True,
        "exploit_available": False,
        "summary": "An app may be able to modify sensitive kernel state leading to arbitrary code execution with kernel privileges.",
        "affected_products": ["iOS < 16.6", "iPadOS < 16.6", "macOS Ventura < 13.5"],
        "published_date": "2023-07-24"
    }
]

# Helper functions for persistent storage
def get_persisted_scans() -> Dict[str, Any]:
    return load_json(SCANS_FILE, {})

def save_persisted_scans(scans: Dict[str, Any]):
    save_json(SCANS_FILE, scans)

def get_persisted_assets() -> List[Dict[str, Any]]:
    return load_json(ASSETS_FILE, DEFAULT_ASSETS)

def save_persisted_assets(assets: List[Dict[str, Any]]):
    save_json(ASSETS_FILE, assets)

def get_persisted_cves() -> List[Dict[str, Any]]:
    return load_json(CVE_FILE, DEFAULT_CVES)

def save_persisted_cves(cves: List[Dict[str, Any]]):
    save_json(CVE_FILE, cves)

def get_persisted_users(default_users: Dict[str, Any]) -> Dict[str, Any]:
    loaded = load_json(USERS_FILE, default_users)
    updated = False
    for uname, udata in default_users.items():
        if uname not in loaded or loaded[uname].get("password_hash") != udata["password_hash"]:
            loaded[uname] = udata
            updated = True
    if updated:
        save_json(USERS_FILE, loaded)
    return loaded

def save_persisted_users(users: Dict[str, Any]):
    save_json(USERS_FILE, users)
