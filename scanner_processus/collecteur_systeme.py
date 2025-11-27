#!/usr/bin/env python3
"""
Collecteur d'informations système pour Learn-Protect.
Collecte CPU, mémoire, disque, réseau, processus, etc.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import json

try:
    import psutil
except ImportError:
    print("psutil requis: pip install psutil")
    psutil = None


@dataclass
class SystemSnapshot:
    """Snapshot des infos système à un instant t."""
    timestamp: str
    cpu_percent: float
    cpu_count: int
    memory: Dict[str, Any]
    disk: Dict[str, Any]
    network: Dict[str, Any]
    process_count: int
    boot_time: str


class SystemInfoCollector:
    """Collecteur d'informations système."""

    def __init__(self):
        pass

    @staticmethod
    def collect() -> Dict[str, Any]:
        """
        Collecte snapshot complet du système.
        Retourne dict avec CPU, mémoire, disque, réseau, processus.
        """
        if not psutil:
            return {"error": "psutil not available"}

        try:
            now = datetime.now(timezone.utc).isoformat()

            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count(logical=True)
            cpu_count_physical = psutil.cpu_count(logical=False)

            # Mémoire
            mem = psutil.virtual_memory()

            # Disque (root)
            try:
                disk = psutil.disk_usage("/")
            except Exception:
                disk = None

            # Réseau
            net_io = psutil.net_io_counters()

            # Processus
            process_count = len(psutil.pids())

            # Boot time
            try:
                boot_time = datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat()
            except Exception:
                boot_time = None

            return {
                "timestamp": now,
                "cpu": {
                    "percent": float(cpu_percent),
                    "logical_count": int(cpu_count),
                    "physical_count": int(cpu_count_physical) if cpu_count_physical else None,
                },
                "memory": {
                    "total": int(mem.total),
                    "used": int(mem.used),
                    "available": int(mem.available),
                    "percent": float(mem.percent),
                    "free": int(mem.free),
                    "buffers": int(mem.buffers) if hasattr(mem, "buffers") else None,
                    "cached": int(mem.cached) if hasattr(mem, "cached") else None,
                },
                "disk": {
                    "total": int(disk.total),
                    "used": int(disk.used),
                    "free": int(disk.free),
                    "percent": float(disk.percent),
                } if disk else None,
                "network": {
                    "bytes_sent": int(net_io.bytes_sent),
                    "bytes_recv": int(net_io.bytes_recv),
                    "packets_sent": int(net_io.packets_sent),
                    "packets_recv": int(net_io.packets_recv),
                },
                "process_count": int(process_count),
                "boot_time": boot_time,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def get_top_processes(n: int = 10, sort_by: str = "memory") -> List[Dict[str, Any]]:
        """
        Retourne les N processus consommant le plus de ressources.
        sort_by: 'memory', 'cpu', 'pid'
        """
        if not psutil:
            return []

        procs = []
        for p in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"]):
            try:
                info = p.info
                mem_mb = info["memory_info"].rss / 1024 / 1024 if info["memory_info"] else 0
                procs.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu_percent": float(info["cpu_percent"] or 0),
                    "memory_mb": float(mem_mb),
                })
            except Exception:
                pass

        # Sort
        if sort_by == "memory":
            procs.sort(key=lambda x: x["memory_mb"], reverse=True)
        elif sort_by == "cpu":
            procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
        else:
            procs.sort(key=lambda x: x["pid"])

        return procs[:n]

    @staticmethod
    def get_network_stats() -> Dict[str, Any]:
        """Statistiques réseau (interfaces, connexions)."""
        if not psutil:
            return {}

        try:
            result = {}

            # Interfaces réseau
            addrs = psutil.net_if_addrs()
            result["interfaces"] = {}
            for iface, addr_list in addrs.items():
                result["interfaces"][iface] = [
                    {
                        "family": str(a.family),
                        "address": a.address,
                        "netmask": a.netmask,
                        "broadcast": a.broadcast,
                    }
                    for a in addr_list
                ]

            # Stats globales
            io = psutil.net_io_counters()
            result["io"] = {
                "bytes_sent": int(io.bytes_sent),
                "bytes_recv": int(io.bytes_recv),
                "packets_sent": int(io.packets_sent),
                "packets_recv": int(io.packets_recv),
                "errin": int(io.errin),
                "errout": int(io.errout),
                "dropin": int(io.dropin),
                "dropout": int(io.dropout),
            }

            return result
        except Exception as e:
            return {"error": str(e)}


if __name__ == "__main__":
    import json

    collector = SystemInfoCollector()

    print("=" * 60)
    print("System Information")
    print("=" * 60)

    info = collector.collect()
    print(json.dumps(info, indent=2))

    print("\n" + "=" * 60)
    print("Top 5 Processes by Memory")
    print("=" * 60)
    top = collector.get_top_processes(5, sort_by="memory")
    print(json.dumps(top, indent=2))

    print("\n" + "=" * 60)
    print("Network Stats")
    print("=" * 60)
    net = collector.get_network_stats()
    print(json.dumps(net, indent=2))
