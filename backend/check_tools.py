import shutil
import subprocess
import requests
import socket

def check_all_tools():
    """
    Checks local system installation and daemon status for Nmap, Trivy, OWASP ZAP, and OpenVAS.
    """
    # 1. Nmap Check
    nmap_path = shutil.which("nmap")
    nmap_installed = nmap_path is not None
    nmap_version = "Not Installed (Install via apt/brew/nmap.org)"
    if nmap_installed:
        try:
            res = subprocess.run([nmap_path, "--version"], capture_output=True, text=True, timeout=5)
            nmap_version = res.stdout.split("\n")[0] if res.returncode == 0 else "Installed"
        except Exception as e:
            nmap_version = f"Installed (Error querying version: {e})"

    # 2. Trivy Check
    trivy_path = shutil.which("trivy")
    trivy_installed = trivy_path is not None
    trivy_version = "Not Installed (Install via aquasecurity.github.io/trivy)"
    if trivy_installed:
        try:
            res = subprocess.run([trivy_path, "--version"], capture_output=True, text=True, timeout=5)
            trivy_version = res.stdout.split("\n")[0] if res.returncode == 0 else "Installed"
        except Exception as e:
            trivy_version = f"Installed (Error querying version: {e})"

    # 3. OWASP ZAP API Check
    zap_status = "Offline (Daemon not running at http://localhost:8080)"
    try:
        r = requests.get("http://localhost:8080", timeout=2)
        zap_status = f"Online (HTTP {r.status_code} - API Daemon Active)"
    except Exception:
        pass

    # 4. OpenVAS GMP Check
    openvas_status = "Offline (GMP socket 127.0.0.1:9390 closed)"
    try:
        s = socket.create_connection(("127.0.0.1", 9390), timeout=2)
        s.close()
        openvas_status = "Online (GMP Socket 127.0.0.1:9390 Active)"
    except Exception:
        pass

    return {
        "scanners": {
            "nmap": {
                "name": "Nmap Network Scanner",
                "installed": nmap_installed,
                "status": nmap_version
            },
            "trivy": {
                "name": "Trivy Dependency & Vulnerability Scanner",
                "installed": trivy_installed,
                "status": trivy_version
            },
            "owasp_zap": {
                "name": "OWASP ZAP API Daemon",
                "status": zap_status
            },
            "openvas": {
                "name": "OpenVAS / Greenbone GMP Connector",
                "status": openvas_status
            }
        }
    }

if __name__ == "__main__":
    import json
    print(json.dumps(check_all_tools(), indent=2))
