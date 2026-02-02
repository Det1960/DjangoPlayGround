import socket
import requests
import subprocess
try:
    import paramiko
    HAS_PARAMIKO = True
except Exception:
    paramiko = None
    HAS_PARAMIKO = False

from typing import Dict, List, Generator, Tuple
from urllib.parse import urlparse
import warnings

if HAS_PARAMIKO:
    # Suppress paramiko warnings when installed
    warnings.filterwarnings("ignore", category=DeprecationWarning)

# Common default credentials to test
DEFAULT_CREDENTIALS = [
    ("guest", "guest"),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "password"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "12345"),
    ("test", "test"),
    ("anonymous", "anonymous"),
    ("gast", "gast"),
    ("user", "user"),
]

# Common backdoor file paths to check
BACKDOOR_FILES = [
    "/shell.php",
    "/backdoor.php",
    "/cmd.php",
    "/.htaccess",
    "/config.php",
    "/webshell.php",
    "/admin.php",
    "/wp-admin/",
    "/phpmyadmin/",
    "/.env",
    "/web.config",
]


def test_http_access(url: str) -> Dict:
    """Test if a URL is accessible and returns status."""
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        return {
            "type": "http_access",
            "url": url,
            "status_code": resp.status_code,
            "accessible": resp.status_code < 400,
            "headers": dict(resp.headers),
        }
    except Exception as e:
        return {
            "type": "http_access",
            "url": url,
            "accessible": False,
            "error": str(e),
        }


def test_http_basic_auth(url: str, username: str, password: str) -> Dict:
    """Test HTTP Basic Auth with given credentials."""
    try:
        resp = requests.get(url, auth=(username, password), timeout=5)
        success = resp.status_code < 400
        return {
            "type": "http_basic_auth",
            "url": url,
            "username": username,
            "password": password,
            "status_code": resp.status_code,
            "success": success,
        }
    except Exception as e:
        return {
            "type": "http_basic_auth",
            "url": url,
            "username": username,
            "password": password,
            "error": str(e),
        }

def test_http_basic_auth_curl(url: str, username: str, password: str) -> Dict:
    """Attempt HTTP Basic Auth using system `curl`. Falls back to requests if curl fehlt."""
    cmd = [
        "curl",
        "-s",
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "-u", f"{username}:{password}",
        url,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        stdout = proc.stdout.strip()
        status_code = int(stdout) if stdout.isdigit() else None
        success = (status_code is not None and status_code < 400)
        return {
            "type": "http_basic_auth",
            "method": "curl",
            "url": url,
            "username": username,
            "password": password,
            "status_code": status_code,
            "success": success,
        }
    except FileNotFoundError:
        # curl not available, fallback
        return {"type": "http_basic_auth", "method": "curl", "error": "curl not installed"}
    except Exception:
        # fallback to requests implementation if anything goes wrong
        return test_http_basic_auth(url, username, password)


def test_backdoor_files(base_url: str) -> List[Dict]:
    """Check for common backdoor/sensitive files."""
    results = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in BACKDOOR_FILES:
        url = base + path
        try:
            resp = requests.head(url, timeout=5, allow_redirects=False)
            found = resp.status_code < 400
            results.append({
                "type": "backdoor_file",
                "path": path,
                "url": url,
                "status_code": resp.status_code,
                "found": found,
            })
        except Exception as e:
            results.append({
                "type": "backdoor_file",
                "path": path,
                "url": url,
                "error": str(e),
            })

    return results


def test_ssh_access(host: str, username: str, password: str, port: int = 22) -> Dict:
    """Test SSH access with given credentials. If paramiko is not installed, return an explanatory error."""
    if not HAS_PARAMIKO:
        return {
            "type": "ssh_access",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "success": False,
            "error": "paramiko not installed",
        }

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password, timeout=5)
        client.close()
        return {
            "type": "ssh_access",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "success": True,
        }
    except paramiko.AuthenticationException:
        return {
            "type": "ssh_access",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "success": False,
            "reason": "Authentication failed",
        }
    except Exception as e:
        return {
            "type": "ssh_access",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "error": str(e),
        }


def test_ftp_access(host: str, username: str, password: str, port: int = 21) -> Dict:
    """Test FTP access with given credentials."""
    try:
        from ftplib import FTP
        ftp = FTP()
        ftp.connect(host, port, timeout=5)
        ftp.login(username, password)
        ftp.quit()
        return {
            "type": "ftp_access",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "success": True,
        }
    except Exception as e:
        return {
            "type": "ftp_access",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "success": False,
            "error": str(e),
        }


def scan_internet_security(url: str) -> Generator[Tuple[int, str, Dict], None, None]:
    """Generator that tests various security vulnerabilities on a URL.
    
    Yields: (step_num, description, result_dict)
    """
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
    host = parsed.netloc.split(':')[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    step = 0
    
    # Step 1: Test basic accessibility
    step += 1
    yield (step, "Teste HTTP-Zugriff", test_http_access(base_url))
    
        # Step 2-N: Test HTTP Basic Auth with default credentials (requests + curl)
        for username, password in DEFAULT_CREDENTIALS:
         step += 1
         # requests-based check
         yield (step, f"Teste HTTP Basic Auth (requests): {username}/{password}",
             test_http_basic_auth(base_url, username, password))
         # curl-based check (may provide different behavior)
         step += 1
         yield (step, f"Teste HTTP Basic Auth (curl): {username}/{password}",
             test_http_basic_auth_curl(base_url, username, password))
    
    # Step N+1: Check for backdoor files
    step += 1
    backdoor_results = test_backdoor_files(base_url)
    for result in backdoor_results:
        yield (step, f"Prüfe Datei: {result.get('path', '?')}", result)
        step += 1
    
    # Step N+2: Try SSH access
    for username, password in DEFAULT_CREDENTIALS:
        step += 1
        yield (step, f"Teste SSH: {username}/{password}", 
               test_ssh_access(host, username, password))
    
    # Step N+3: Try FTP access
    for username, password in DEFAULT_CREDENTIALS:
        step += 1
        yield (step, f"Teste FTP: {username}/{password}", 
               test_ftp_access(host, username, password))
