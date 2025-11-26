from dataclasses import dataclass
from typing import Optional
import psutil
import time
from datetime import datetime, timezone


@dataclass
class ResourceUsage:
    pid: int
    cpu_percent: float
    memory_rss: int          # RAM réelle utilisée
    memory_vms: int          # taille mémoire virtuelle
    io_read_bytes: Optional[int]
    io_write_bytes: Optional[int]
    timestamp: str           # ISO-8601 UTC


class ResourceMonitor:
    """
    Récupère les ressources consommées par un processus donné.
    Utilise psutil de manière robuste pour supporter les erreurs d'accès.
    """

    def __init__(self, pid: int):
        self.pid = pid

        try:
            self.process = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.process = None

    def collect(self) -> Optional[ResourceUsage]:
        """
        Retourne un objet ResourceUsage contenant les métriques du processus.
        Retourne None si le process n'est pas accessible.
        """

        if self.process is None:
            return None

        try:
            # CPU (%) — psutil a besoin d'un premier appel "blanc"
            self.process.cpu_percent(interval=None)
            time.sleep(0.1)
            cpu = self.process.cpu_percent(interval=None)

            mem = self.process.memory_info()

            # I/O — peut échouer sur certains OS → fallback None
            try:
                io = self.process.io_counters()
                read_bytes = io.read_bytes
                write_bytes = io.write_bytes
            except Exception:
                read_bytes = None
                write_bytes = None

            timestamp = datetime.now(timezone.utc).isoformat()

            return ResourceUsage(
                pid=self.pid,
                cpu_percent=cpu,
                memory_rss=mem.rss,
                memory_vms=mem.vms,
                io_read_bytes=read_bytes,
                io_write_bytes=write_bytes,
                timestamp=timestamp
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
