from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import requests
import urllib3
import time
from datetime import datetime

from backend.routers.auth import get_current_user
from backend.storage import get_persisted_wazuh_config, save_persisted_wazuh_config

# Suppress insecure HTTPS warnings when connecting to self-signed certs on Wazuh VM
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

router = APIRouter(prefix="/wazuh", tags=["Wazuh SIEM Integration"])

# --- Models ---
class WazuhConfigUpdate(BaseModel):
    host: str
    port: int = 55000
    user: str = "wazuh"
    password: str = "wazuh-password"
    verify_ssl: bool = False
    enabled: bool = True
    use_mock_fallback: bool = True

class AgentScanRequest(BaseModel):
    agent_id: str

# Token cache to avoid authenticating on every single HTTP request
_TOKEN_CACHE = {"token": None, "expires_at": 0}

def get_wazuh_auth_token(config: Dict[str, Any]) -> str:
    """Authenticates against Wazuh Manager REST API and returns JWT access token."""
    now = time.time()
    if _TOKEN_CACHE["token"] and _TOKEN_CACHE["expires_at"] > now:
        return _TOKEN_CACHE["token"]

    host = config.get("host", "192.168.1.100").strip()
    port = config.get("port", 55000)
    user = config.get("user", "wazuh")
    password = config.get("password", "wazuh")
    verify_ssl = config.get("verify_ssl", False)

    base_url = f"https://{host}:{port}"
    auth_url = f"{base_url}/security/user/authenticate"

    try:
        res = requests.post(
            auth_url,
            auth=(user, password),
            verify=verify_ssl,
            timeout=4.0
        )
        if res.status_code == 200:
            data = res.json()
            token = data.get("data", {}).get("token")
            if token:
                _TOKEN_CACHE["token"] = token
                # Cache token for 14 minutes (Wazuh token expires in 15m)
                _TOKEN_CACHE["expires_at"] = now + 840
                return token
        elif res.status_code == 401:
            raise Exception("Wazuh Authentication failed: Invalid API username or password")
        else:
            raise Exception(f"Wazuh API responded with HTTP {res.status_code}")
    except requests.exceptions.SSLError:
        raise Exception(f"SSL Certificate Verification Failed for {base_url}. Please UNCHECK 'Verify SSL Certificate' in Server Connection Settings since Wazuh uses a self-signed certificate.")
    except requests.exceptions.ConnectionError:
        raise Exception(f"Cannot connect to Wazuh Manager at {base_url}. Check VM IP and host firewall.")
    except requests.exceptions.Timeout:
        raise Exception(f"Connection timeout to Wazuh Manager at {base_url}.")
    except Exception as e:
        raise Exception(str(e))


def make_wazuh_request(config: Dict[str, Any], method: str, endpoint: str, params: Optional[Dict] = None, json_data: Optional[Dict] = None) -> Dict[str, Any]:
    """Helper to issue authorized HTTP requests to Wazuh REST API."""
    token = get_wazuh_auth_token(config)
    host = config.get("host", "192.168.1.100").strip()
    port = config.get("port", 55000)
    verify_ssl = config.get("verify_ssl", False)
    
    url = f"https://{host}:{port}{endpoint}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    res = requests.request(
        method=method,
        url=url,
        headers=headers,
        params=params,
        json=json_data,
        verify=verify_ssl,
        timeout=5.0
    )
    if res.status_code in (200, 201, 202):
        return res.json()
    else:
        raise Exception(f"Wazuh API Error {res.status_code}: {res.text}")

# --- Helper for Mock Demonstration Telemetry ---
def get_mock_wazuh_data(config: Dict[str, Any], connection_error: Optional[str] = None) -> Dict[str, Any]:
    return {
        "connected": False if connection_error else True,
        "is_mock": True,
        "error_message": connection_error,
        "wazuh_host": config.get("host"),
        "manager_info": {
            "node_name": "wazuh-master-vm",
            "version": "v4.7.2",
            "compilation_date": "2024-02-15",
            "status": "active",
            "cluster_name": "wazuh-lab-cluster"
        },
        "agents_summary": {
            "total": 4,
            "active": 3,
            "disconnected": 1,
            "never_connected": 0
        },
        "agents": [
            {
                "id": "000",
                "name": "wazuh-manager-vm",
                "ip": config.get("host", "192.168.1.100"),
                "status": "active",
                "os": {
                    "name": "Ubuntu Linux",
                    "version": "22.04.3 LTS (Jammy Jellyfish)",
                    "arch": "x86_64"
                },
                "version": "Wazuh v4.7.2",
                "lastKeepAlive": "2026-10-03T19:00:00Z"
            },
            {
                "id": "001",
                "name": "web-prod-srv01",
                "ip": "192.168.10.45",
                "status": "active",
                "os": {
                    "name": "Debian GNU/Linux",
                    "version": "12 (bookworm)",
                    "arch": "x86_64"
                },
                "version": "Wazuh v4.7.2",
                "lastKeepAlive": "2026-10-03T19:01:45Z"
            },
            {
                "id": "002",
                "name": "win-db-cluster01",
                "ip": "192.168.10.88",
                "status": "active",
                "os": {
                    "name": "Microsoft Windows Server",
                    "version": "2022 Standard",
                    "arch": "x64"
                },
                "version": "Wazuh v4.7.1",
                "lastKeepAlive": "2026-10-03T19:01:30Z"
            },
            {
                "id": "003",
                "name": "dev-workstation-04",
                "ip": "192.168.10.102",
                "status": "disconnected",
                "os": {
                    "name": "Windows 11 Enterprise",
                    "version": "23H2",
                    "arch": "x64"
                },
                "version": "Wazuh v4.6.0",
                "lastKeepAlive": "2026-10-02T14:20:00Z"
            }
        ],
        "alerts": [
            {
                "id": "alt-901",
                "timestamp": "2026-10-03T18:55:12Z",
                "rule_id": 5710,
                "description": "SSHD: Attempted login using invalid user 'admin'",
                "level": 5,
                "severity": "Medium",
                "agent_name": "web-prod-srv01",
                "agent_ip": "192.168.10.45",
                "mitre_attack": "T1110 - Brute Force",
                "location": "/var/log/auth.log"
            },
            {
                "id": "alt-902",
                "timestamp": "2026-10-03T18:42:01Z",
                "rule_id": 100200,
                "description": "Web Application Attack - SQL Injection probe detected on GET /api/v1/users",
                "level": 10,
                "severity": "High",
                "agent_name": "web-prod-srv01",
                "agent_ip": "192.168.10.45",
                "mitre_attack": "T1190 - Exploit Public-Facing Application",
                "location": "/var/log/nginx/access.log"
            },
            {
                "id": "alt-903",
                "timestamp": "2026-10-03T17:30:44Z",
                "rule_id": 23506,
                "description": "Vulnerability Detector: CVE-2024-3094 (XZ Utils RCE) detected in package xz-utils v5.6.0",
                "level": 13,
                "severity": "Critical",
                "agent_name": "web-prod-srv01",
                "agent_ip": "192.168.10.45",
                "mitre_attack": "T1190 - Exploit Public-Facing Application",
                "location": "Wazuh Vulnerability Detector"
            },
            {
                "id": "alt-904",
                "timestamp": "2026-10-03T16:15:20Z",
                "rule_id": 554,
                "description": "File Integrity Monitoring (FIM): System binary modified: /usr/bin/sudo",
                "level": 10,
                "severity": "High",
                "agent_name": "wazuh-manager-vm",
                "agent_ip": config.get("host", "192.168.1.100"),
                "mitre_attack": "T1036 - Masquerading",
                "location": "/usr/bin/sudo"
            }
        ]
    }

# --- Routes ---

@router.get("/config")

def get_wazuh_config(current_user: dict = Depends(get_current_user)):
    """Retrieve saved Wazuh integration configuration."""
    config = get_persisted_wazuh_config()
    # Mask password for security when returning config
    safe_config = dict(config)
    safe_config["password_masked"] = "••••••••" if safe_config.get("password") else ""
    return safe_config

@router.post("/config")
def update_wazuh_config(payload: WazuhConfigUpdate, current_user: dict = Depends(get_current_user)):
    """Update and save Wazuh integration configuration."""
    current_config = get_persisted_wazuh_config()

    new_config = payload.dict()
    
    # Keep old password if user submitted masked placeholder
    if new_config["password"] == "••••••••" or not new_config["password"]:
        new_config["password"] = current_config.get("password", "wazuh-password")
        
    save_persisted_wazuh_config(new_config)
    # Clear token cache to force re-auth
    _TOKEN_CACHE["token"] = None
    _TOKEN_CACHE["expires_at"] = 0
    return {"status": "success", "message": "Wazuh configuration saved successfully.", "config": new_config}

@router.get("/status")
def check_wazuh_status(current_user: dict = Depends(get_current_user)):
    """Check connectivity to Wazuh Manager VM and fetch manager information."""
    config = get_persisted_wazuh_config()
    if not config.get("enabled", True):
        return {
            "connected": False,
            "status": "disabled",
            "message": "Wazuh integration is currently disabled in settings."
        }
    
    try:
        token = get_wazuh_auth_token(config)
        info_resp = make_wazuh_request(config, "GET", "/manager/info")
        manager_info = info_resp.get("data", {}).get("affected_items", [{}])[0]
        
        status_resp = make_wazuh_request(config, "GET", "/manager/status")
        manager_status = status_resp.get("data", {}).get("affected_items", [{}])[0]
        
        return {
            "connected": True,
            "status": "online",
            "wazuh_host": config.get("host"),
            "manager_info": {
                "node_name": manager_info.get("name", "wazuh-node"),
                "version": manager_info.get("version", "v4.x"),
                "compilation_date": manager_info.get("compilation_date", "N/A"),
                "status": manager_status.get("wazuh-modulesd", "running"),
                "cluster_name": manager_info.get("cluster_name", "wazuh")
            }
        }
    except Exception as e:
        err_msg = str(e)
        if config.get("use_mock_fallback", True):
            mock = get_mock_wazuh_data(config, connection_error=err_msg)
            return mock
        return {
            "connected": False,
            "status": "offline",
            "error_message": err_msg,
            "wazuh_host": config.get("host")
        }

@router.get("/agents")
def get_wazuh_agents(current_user: dict = Depends(get_current_user)):
    """Fetch list of monitored agents from Wazuh API."""
    config = get_persisted_wazuh_config()
    try:
        resp = make_wazuh_request(config, "GET", "/agents", params={"limit": 100})
        raw_agents = resp.get("data", {}).get("affected_items", [])
        
        agents = []
        active_count = 0
        disconnected_count = 0
        
        for item in raw_agents:
            st = item.get("status", "disconnected").lower()
            if st == "active":
                active_count += 1
            else:
                disconnected_count += 1
                
            agents.append({
                "id": item.get("id"),
                "name": item.get("name"),
                "ip": item.get("ip", "N/A"),
                "status": st,
                "os": item.get("os", {}),
                "version": item.get("version", "Wazuh Agent"),
                "lastKeepAlive": item.get("lastKeepAlive", "N/A")
            })
            
        return {
            "connected": True,
            "is_mock": False,
            "agents_summary": {
                "total": len(agents),
                "active": active_count,
                "disconnected": disconnected_count
            },
            "agents": agents
        }
    except Exception as e:
        err_msg = str(e)
        if config.get("use_mock_fallback", True):
            mock_data = get_mock_wazuh_data(config, connection_error=err_msg)
            return {
                "connected": False,
                "is_mock": True,
                "error_message": err_msg,
                "agents_summary": mock_data["agents_summary"],
                "agents": mock_data["agents"]
            }
        raise HTTPException(status_code=502, detail=f"Failed to communicate with Wazuh Manager: {err_msg}")

@router.get("/alerts")
def get_wazuh_alerts(current_user: dict = Depends(get_current_user)):
    """Fetch recent security alerts & events from Wazuh."""
    config = get_persisted_wazuh_config()
    try:
        # Query syscheck or alerts endpoint
        resp = make_wazuh_request(config, "GET", "/manager/logs", params={"limit": 50})
        # Alternatively return standard alerts stream
        items = resp.get("data", {}).get("affected_items", [])
        alerts = []
        for idx, item in enumerate(items):
            lvl = item.get("rule", {}).get("level", 3)
            sev = "Critical" if lvl >= 12 else ("High" if lvl >= 7 else ("Medium" if lvl >= 4 else "Low"))
            alerts.append({
                "id": f"alt-real-{idx}",
                "timestamp": item.get("timestamp", datetime.utcnow().isoformat()),
                "rule_id": item.get("rule", {}).get("id", 100),
                "description": item.get("description") or item.get("log") or "Security Log Event",
                "level": lvl,
                "severity": sev,
                "agent_name": item.get("agent", {}).get("name", "Wazuh Agent"),
                "agent_ip": item.get("agent", {}).get("ip", "N/A"),
                "mitre_attack": item.get("rule", {}).get("mitre", {}).get("id", ["T1000"])[0] if isinstance(item.get("rule", {}).get("mitre", {}).get("id"), list) else "N/A",
                "location": item.get("location", "System Log")
            })

        return {"connected": True, "is_mock": False, "alerts": alerts}
    except Exception as e:
        err_msg = str(e)
        if config.get("use_mock_fallback", True):
            mock_data = get_mock_wazuh_data(config, connection_error=err_msg)
            return {
                "connected": False,
                "is_mock": True,
                "error_message": err_msg,
                "alerts": mock_data["alerts"]
            }
        raise HTTPException(status_code=502, detail=f"Failed to fetch Wazuh alerts: {err_msg}")

@router.post("/agents/{agent_id}/scan")
def trigger_agent_scan(agent_id: str, current_user: dict = Depends(get_current_user)):
    """Trigger an active File Integrity / Syscheck scan on a Wazuh agent."""
    config = get_persisted_wazuh_config()
    try:
        resp = make_wazuh_request(config, "PUT", f"/syscheck", params={"agents_list": agent_id})
        return {
            "status": "success",
            "message": f"Syscheck & Integrity Scan initiated for Wazuh Agent ID {agent_id}.",
            "wazuh_response": resp
        }
    except Exception as e:
        # If running in mock/demo mode or VM unreachable
        if config.get("use_mock_fallback", True):
            return {
                "status": "success",
                "is_mock": True,
                "message": f"[Demo Mode] Active scan trigger command sent to Wazuh Agent '{agent_id}'. Syscheck scan in progress."
            }
        raise HTTPException(status_code=500, detail=f"Failed to trigger Wazuh agent scan: {str(e)}")
