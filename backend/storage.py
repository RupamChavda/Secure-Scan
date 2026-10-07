import json
import os
from typing import Dict, List, Any
from backend.database import get_db, is_mongodb_available

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

SCANS_FILE = os.path.join(DATA_DIR, "scans_db.json")
ASSETS_FILE = os.path.join(DATA_DIR, "assets_db.json")
CVE_FILE = os.path.join(DATA_DIR, "cve_db.json")
USERS_FILE = os.path.join(DATA_DIR, "users_db.json")
WAZUH_FILE = os.path.join(DATA_DIR, "wazuh_config.json")

DEFAULT_WAZUH_CONFIG = {
    "enabled": True,
    "host": "192.168.127.99",
    "port": 55000,
    "user": "wazuh",
    "password": "wazuh",
    "verify_ssl": False,
    "use_mock_fallback": True
}


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

def clean_mongo_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Remove MongoDB internal _id field if present."""
    if isinstance(doc, dict):
        doc_copy = dict(doc)
        doc_copy.pop("_id", None)
        return doc_copy
    return doc

# --- Helper functions for MongoDB & File persistence ---

def get_persisted_scans() -> Dict[str, Any]:
    if is_mongodb_available():
        try:
            db = get_db()
            cursor = db.scans.find({})
            scans_dict = {}
            for doc in cursor:
                clean_doc = clean_mongo_doc(doc)
                scan_id = clean_doc.get("id")
                if scan_id:
                    scans_dict[scan_id] = clean_doc
            if scans_dict:
                return scans_dict
        except Exception as e:
            print(f"[MongoDB] Error fetching scans: {e}")

    # Fallback to local JSON file
    return load_json(SCANS_FILE, {})

def save_persisted_scans(scans: Dict[str, Any]):
    save_json(SCANS_FILE, scans)
    if is_mongodb_available():
        try:
            db = get_db()
            for scan_id, scan_data in scans.items():
                data_copy = clean_mongo_doc(scan_data)
                data_copy["id"] = scan_id
                db.scans.replace_one({"id": scan_id}, data_copy, upsert=True)
        except Exception as e:
            print(f"[MongoDB] Error saving scans: {e}")

def get_persisted_assets() -> List[Dict[str, Any]]:
    if is_mongodb_available():
        try:
            db = get_db()
            docs = list(db.assets.find({}))
            if docs:
                return [clean_mongo_doc(d) for d in docs]
            # Seed MongoDB if collection is empty
            for asset in DEFAULT_ASSETS:
                db.assets.replace_one({"id": asset["id"]}, asset, upsert=True)
            return DEFAULT_ASSETS
        except Exception as e:
            print(f"[MongoDB] Error fetching assets: {e}")

    # Fallback to JSON
    return load_json(ASSETS_FILE, DEFAULT_ASSETS)

def save_persisted_assets(assets: List[Dict[str, Any]]):
    save_json(ASSETS_FILE, assets)
    if is_mongodb_available():
        try:
            db = get_db()
            db.assets.delete_many({}) # sync dataset
            if assets:
                clean_assets = [clean_mongo_doc(a) for a in assets]
                db.assets.insert_many(clean_assets)
        except Exception as e:
            print(f"[MongoDB] Error saving assets: {e}")

def get_persisted_cves() -> List[Dict[str, Any]]:
    if is_mongodb_available():
        try:
            db = get_db()
            docs = list(db.cves.find({}))
            if docs:
                return [clean_mongo_doc(d) for d in docs]
            # Seed MongoDB if collection is empty
            for cve in DEFAULT_CVES:
                db.cves.replace_one({"cve_id": cve["cve_id"]}, cve, upsert=True)
            return DEFAULT_CVES
        except Exception as e:
            print(f"[MongoDB] Error fetching CVEs: {e}")

    # Fallback to JSON
    return load_json(CVE_FILE, DEFAULT_CVES)

def save_persisted_cves(cves: List[Dict[str, Any]]):
    save_json(CVE_FILE, cves)
    if is_mongodb_available():
        try:
            db = get_db()
            db.cves.delete_many({})
            if cves:
                clean_cves = [clean_mongo_doc(c) for c in cves]
                db.cves.insert_many(clean_cves)
        except Exception as e:
            print(f"[MongoDB] Error saving CVEs: {e}")

def get_persisted_users(default_users: Dict[str, Any]) -> Dict[str, Any]:
    if is_mongodb_available():
        try:
            db = get_db()
            docs = list(db.users.find({}))
            loaded = {}
            for d in docs:
                clean_d = clean_mongo_doc(d)
                uname = clean_d.get("username")
                if uname:
                    loaded[uname] = clean_d
            
            # Ensure default users exist
            updated = False
            for uname, udata in default_users.items():
                if uname not in loaded or loaded[uname].get("password_hash") != udata["password_hash"]:
                    loaded[uname] = udata
                    db.users.replace_one({"username": uname}, udata, upsert=True)
                    updated = True
            
            if loaded:
                save_json(USERS_FILE, loaded)
                return loaded
        except Exception as e:
            print(f"[MongoDB] Error fetching users: {e}")

    # Fallback to JSON
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
    if is_mongodb_available():
        try:
            db = get_db()
            for uname, udata in users.items():
                clean_u = clean_mongo_doc(udata)
                db.users.replace_one({"username": uname}, clean_u, upsert=True)
        except Exception as e:
            print(f"[MongoDB] Error saving users: {e}")

def get_persisted_wazuh_config() -> Dict[str, Any]:
    if is_mongodb_available():
        try:
            db = get_db()
            doc = db.settings.find_one({"type": "wazuh_config"})
            if doc:
                return clean_mongo_doc(doc.get("config", DEFAULT_WAZUH_CONFIG))
        except Exception as e:
            print(f"[MongoDB] Error fetching Wazuh config: {e}")
    return load_json(WAZUH_FILE, DEFAULT_WAZUH_CONFIG)

def save_persisted_wazuh_config(config: Dict[str, Any]):
    save_json(WAZUH_FILE, config)
    if is_mongodb_available():
        try:
            db = get_db()
            db.settings.replace_one({"type": "wazuh_config"}, {"type": "wazuh_config", "config": config}, upsert=True)
        except Exception as e:
            print(f"[MongoDB] Error saving Wazuh config: {e}")
