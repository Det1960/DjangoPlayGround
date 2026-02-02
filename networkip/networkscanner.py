import concurrent.futures
import socket
import subprocess
from typing import List, Dict


def _ping_ip(ip: str) -> bool:
    try:
        # -c 1 : send 1 packet, -W 0.5 : timeout 0.5 second ( Linux )
        completed = subprocess.run(["ping", "-c", "1", "-W", "0.5", ip],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        return completed.returncode == 0
    except Exception:
        return False


def scan_network(base: str = "192.168.1.", start: int = 1, end: int = 255, max_workers: int = 100) -> List[Dict]:
    """Scans a range of IPs and returns a list of dicts with ip, hostname and status.

    Fast scan using concurrent pinging and hostname resolution.
    For full /24 subnet (1-255): ~15-30 seconds depending on network.
    """
    start = max(1, int(start))
    end = min(254, int(end))
    ips = [f"{base}{i}" for i in range(start, end + 1)]

    results: List[Dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as e:
        futures = {e.submit(_ping_ip, ip): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            alive = False
            try:
                alive = bool(fut.result())
            except Exception:
                alive = False

            hostname = "-"
            if alive:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = "-"

            results.append({"ip": ip, "hostname": hostname, "alive": alive})

    # sort by ip
    def _ip_key(item: Dict) -> List[int]:
        parts = item["ip"].split('.')
        return [int(p) for p in parts]

    results.sort(key=_ip_key)
    return results


if __name__ == '__main__':
    # quick manual test when invoked directly
    for r in scan_network(start=1, end=10):
        print(r)

