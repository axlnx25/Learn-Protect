# module_a/process_lister.py

from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime, timezone
import psutil


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    username: Optional[str]
    ppid: Optional[int]
    status: str
    create_time: Optional[str]


class ProcessLister:
    """
    Classe responsable de la récupération de la liste complète des processus.
    Fournit une interface robuste, orientée-objet et réutilisable par le moteur B.
    """

    def __init__(self):
        pass

    def _safe_process_info(self, p: psutil.Process) -> Optional[ProcessInfo]:
        """
        Tente de récupérer les métadonnées d'un processus.
        Renvoie None si non accessible (AccessDenied/NoSuchProcess).
        """
        try:
            pid = p.pid
            name = p.name()

            try:
                exe = p.exe()
            except Exception:
                exe = None

            try:
                cmdline = p.cmdline()
            except Exception:
                cmdline = []

            try:
                username = p.username()
            except Exception:
                username = None

            try:
                ppid = p.ppid()
            except Exception:
                ppid = None

            try:
                status = p.status()
            except Exception:
                status = "unknown"

            try:
                ct = datetime.fromtimestamp(p.create_time(), timezone.utc).isoformat()
            except Exception:
                ct = None

            return ProcessInfo(
                pid=pid,
                name=name,
                exe=exe,
                cmdline=cmdline,
                username=username,
                ppid=ppid,
                status=status,
                create_time=ct
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def list_processes(self) -> List[ProcessInfo]:
        """
        Retourne une liste d'objets ProcessInfo.
        Ignore les processus inaccessibles.
        """
        processes = []
        for proc in psutil.process_iter():
            info = self._safe_process_info(proc)
            if info:
                processes.append(info)
        return processes
