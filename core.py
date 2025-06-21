import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict


class PortScanner:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
    def scan_target(self, target: str, ports: List[int],
                    max_threads: int = 100 ) -> List[Dict]:
        with ThreadPoolExecutor(max_workers = max_threads) as executor:
            results = list(
                executor.map(
                    lambda port: self._scan_port(target, port),
                    ports
                )
            )
        return results
    def _scan_port(self, target: str, port: int) -> Dict:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((target, port))
                return {
                    "target": target,
                    "port": port,
                    "status": "open" if result == 0 else "closed"
                }
        except socket.gaierror:
            return {
                "target": target,
                "port": port,
                "status": "invalid_host"
            }
        except:
            return {
                "target": target,
                "port": port,
                "status": "error"
            }
