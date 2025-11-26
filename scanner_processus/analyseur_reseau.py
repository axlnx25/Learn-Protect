# module_a/network_analyzer.py

from dataclasses import dataclass
from typing import Optional, List
import psutil
import socket
import ipaddress
from datetime import datetime, timezone


@dataclass
class ConnectionInfo:
    pid: int
    laddr_ip: Optional[str]
    laddr_port: Optional[int]
    raddr_ip: Optional[str]
    raddr_port: Optional[int]
    protocol: str           # "TCP" or "UDP"
    status: Optional[str]   # "ESTABLISHED", "LISTEN", "NONE", etc.
    timestamp: str
    is_external: Optional[bool]  # True if remote ip is public (not RFC1918), None if no remote addr


class NetworkAnalyzer:
    """
    Analyse les connexions réseau d'un processus (par PID).
    Utilise psutil.net_connections (cross-platform). Si psutil ne retourne rien
    pour le pid (permissions), la classe gère proprement les exceptions.
    """

    def __init__(self, pid: int):
        self.pid = pid
        try:
            self.process = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.process = None

    @staticmethod
    def _socktype_to_proto(sock_type: int) -> str:
        if sock_type == socket.SOCK_STREAM:
            return "TCP"
        if sock_type == socket.SOCK_DGRAM:
            return "UDP"
        return "UNKNOWN"

    @staticmethod
    def _is_external_ip(ip_str: str) -> Optional[bool]:
        """
        Retourne True si ip_str est une adresse publique,
        False si privée (RFC1918/RFC4193), None si ip_str invalide/None.
        """
        if not ip_str:
            return None
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
        except ValueError:
            return None

    def list_connections(self) -> List[ConnectionInfo]:
        """
        Retourne la liste des ConnectionInfo pour le PID.
        Peut retourner liste vide si aucun socket ou si inaccessible.
        """
        if self.process is None:
            return []

        results: List[ConnectionInfo] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            # psutil.net_connections accepts a pid via process.connections()
            # use kind='inet' to include both TCP and UDP (IPv4/IPv6)
            conns = self.process.connections(kind='inet')
        except psutil.AccessDenied:
            return []
        except psutil.NoSuchProcess:
            return []
        except Exception:
            # On some systems `connections` peut échouer — fallback to global scan
            try:
                # scan global and filter by pid (slower)
                conns = [c for c in psutil.net_connections(kind='inet') if c.pid == self.pid]
            except Exception:
                return []

        for c in conns:
            # local addr
            laddr_ip, laddr_port = (None, None)
            if c.laddr:
                try:
                    laddr_ip = c.laddr.ip if hasattr(c.laddr, 'ip') else c.laddr[0]
                    laddr_port = c.laddr.port if hasattr(c.laddr, 'port') else c.laddr[1]
                except Exception:
                    # older psutil versions may return tuple
                    try:
                        laddr_ip, laddr_port = c.laddr
                    except Exception:
                        laddr_ip, laddr_port = (None, None)

            # remote addr
            raddr_ip, raddr_port = (None, None)
            if c.raddr:
                try:
                    raddr_ip = c.raddr.ip if hasattr(c.raddr, 'ip') else c.raddr[0]
                    raddr_port = c.raddr.port if hasattr(c.raddr, 'port') else c.raddr[1]
                except Exception:
                    try:
                        raddr_ip, raddr_port = c.raddr
                    except Exception:
                        raddr_ip, raddr_port = (None, None)

            proto = self._socktype_to_proto(c.type)
            status = c.status if hasattr(c, 'status') else None
            external = self._is_external_ip(raddr_ip)

            info = ConnectionInfo(
                pid=self.pid,
                laddr_ip=laddr_ip,
                laddr_port=laddr_port,
                raddr_ip=raddr_ip,
                raddr_port=raddr_port,
                protocol=proto,
                status=status,
                timestamp=timestamp,
                is_external=external
            )
            results.append(info)

        return results


# Quick CLI test (optional)
if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="PID to inspect")
    args = parser.parse_args()

    na = NetworkAnalyzer(args.pid)
    conns = na.list_connections()

    # serialize dataclasses to dict
    def ci_to_dict(ci: ConnectionInfo):
        return {
            "pid": ci.pid,
            "laddr_ip": ci.laddr_ip,
            "laddr_port": ci.laddr_port,
            "raddr_ip": ci.raddr_ip,
            "raddr_port": ci.raddr_port,
            "protocol": ci.protocol,
            "status": ci.status,
            "timestamp": ci.timestamp,
            "is_external": ci.is_external
        }

    print(json.dumps([ci_to_dict(c) for c in conns], indent=2))
