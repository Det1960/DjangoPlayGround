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
    r = test_http_access(base_url)
    r['analysis'] = analyze_result(r, "Teste HTTP-Zugriff")
    yield (step, "Teste HTTP-Zugriff", r)

    # Step 2-N: Test HTTP Basic Auth with default credentials (requests + curl)
    for username, password in DEFAULT_CREDENTIALS:
        step += 1
        r1 = test_http_basic_auth(base_url, username, password)
        r1['analysis'] = analyze_result(r1, f"Teste HTTP Basic Auth (requests): {username}/{password}")
        yield (step, f"Teste HTTP Basic Auth (requests): {username}/{password}", r1)

        step += 1
        r2 = test_http_basic_auth_curl(base_url, username, password)
        r2['analysis'] = analyze_result(r2, f"Teste HTTP Basic Auth (curl): {username}/{password}")
        yield (step, f"Teste HTTP Basic Auth (curl): {username}/{password}", r2)

    # Step N+1: Check for backdoor files
    step += 1
    backdoor_results = test_backdoor_files(base_url)
    for result in backdoor_results:
        result['analysis'] = analyze_result(result, f"Prüfe Datei: {result.get('path', '?')}")
        yield (step, f"Prüfe Datei: {result.get('path', '?')}", result)
        step += 1

    # Step N+2: Try SSH access
    for username, password in DEFAULT_CREDENTIALS:
        step += 1
        r = test_ssh_access(host, username, password)
        r['analysis'] = analyze_result(r, f"Teste SSH: {username}/{password}")
        yield (step, f"Teste SSH: {username}/{password}", r)

    # Step N+3: Try FTP access
    for username, password in DEFAULT_CREDENTIALS:
        step += 1
        r = test_ftp_access(host, username, password)
        r['analysis'] = analyze_result(r, f"Teste FTP: {username}/{password}")
        yield (step, f"Teste FTP: {username}/{password}", r)


def analyze_result(result: Dict, description: str) -> Dict:
    """Produce a small analysis with severity and remediation suggestions for a scan result."""
    sev = 'info'
    summary = 'Keine Aktion nötig'
    remediation: List[str] = []

    t = result.get('type')

    if t == 'http_basic_auth':
        # success true indicates credentials worked
        if result.get('success'):
            user = result.get('username', '?')
            pwd = result.get('password', '?')
            sev = 'high'
            summary = f'✗ Anmeldung möglich mit: {user} / {pwd}'
            remediation = [
                f'Sofort Passwort für "{user}" ändern oder Account deaktivieren',
                'HTTPS erzwingen, Basic-Auth hinter zusätzlicher Auth oder VPN betreiben',
                'Logs auf verdächtige Aktivitäten prüfen',
            ]
        elif result.get('status_code') and result.get('status_code') >= 400:
            sev = 'info'
            summary = f'Zugang verweigert ({result.get("username", "?")} / {result.get("password", "?")})'
        elif result.get('error'):
            sev = 'warning'
            summary = 'Fehler beim Test: ' + str(result.get('error'))

    elif t == 'backdoor_file':
        path = result.get('path', '?')
        if result.get('found'):
            sev = 'critical'
            status = result.get('status_code', '?')
            summary = f'✗ Datei erreichbar: {path} (HTTP {status})'
            remediation = [
                f'Sofort "{path}" aus Webroot entfernen/sperren',
                'Gegebenenfalls Server isolieren und forensisch untersuchen',
                'Alle Secrets/Keys/Passwörter rotieren',
            ]
        else:
            sev = 'info'
            summary = f'Datei nicht erreichbar: {path}'

    elif t == 'http_access':
        sc = result.get('status_code')
        if sc and sc < 400:
            sev = 'info'
            summary = f'HTTP erreichbar (Status {sc})'
            remediation = ['HTTPS erzwingen, Header prüfen (HSTS)']
        else:
            sev = 'info'
            summary = f'Nicht erreichbar oder Fehler (Status {sc})'

    elif t in ('ssh_access', 'ftp_access'):
        proto = t.split("_")[0].upper()
        user = result.get('username', '?')
        pwd = result.get('password', '?')
        if result.get('success'):
            sev = 'critical'
            summary = f'✗ {proto} Anmeldung möglich mit: {user} / {pwd}'
            remediation = [
                f'Sofort Passwort für "{user}" ändern oder Account sperren',
                'Passwort-Authentifizierung deaktivieren (SSH) und nur Schlüssel verwenden',
                'Zugriffs-Ports beschränken und Logins prüfen',
            ]
        elif result.get('error') == 'paramiko not installed':
            sev = 'info'
            summary = f'{proto}-Test übersprungen (paramiko fehlt)'
        else:
            sev = 'info'
            summary = f'{proto} Zugang nicht möglich ({user} / {pwd})'

    else:
        summary = 'Unbekannter Befund'

    return {
        'severity': sev,
        'summary': summary,
        'remediation': remediation,
        'description': description,
    }
