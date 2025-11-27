# module_a/hash_calculator.py

from dataclasses import dataclass
from typing import Optional
import hashlib
import os
from datetime import datetime, timezone


CHUNK_SIZE = 1024 * 1024  # 1 MB pour éviter d'utiliser trop de RAM


@dataclass
class FileHashResult:
    path: str
    sha256: Optional[str]
    size_bytes: Optional[int]
    mtime: Optional[str]
    success: bool
    error: Optional[str]


class HashCalculator:
    """
    Module de calcul du hash SHA-256 d'un fichier.
    - Non bloquant (ne modifie pas le système)
    - Sécurisé (gère les erreurs)
    - Optimisé (lecture en chunks)
    """

    def __init__(self):
        pass

    def compute_sha256(self, filepath: str) -> FileHashResult:
        """
        Calcule le SHA-256 du fichier passé en paramètre.
        Retourne un FileHashResult.
        """

        if not os.path.exists(filepath):
            return FileHashResult(
                path=filepath,
                sha256=None,
                size_bytes=None,
                mtime=None,
                success=False,
                error="File not found"
            )

        if not os.path.isfile(filepath):
            return FileHashResult(
                path=filepath,
                sha256=None,
                size_bytes=None,
                mtime=None,
                success=False,
                error="Not a regular file"
            )

        try:
            hasher = hashlib.sha256()

            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)

            size_bytes = os.path.getsize(filepath)
            mtime = datetime.fromtimestamp(
                os.path.getmtime(filepath), timezone.utc
            ).isoformat()

            return FileHashResult(
                path=filepath,
                sha256=hasher.hexdigest(),
                size_bytes=size_bytes,
                mtime=mtime,
                success=True,
                error=None
            )

        except PermissionError:
            return FileHashResult(
                path=filepath,
                sha256=None,
                size_bytes=None,
                mtime=None,
                success=False,
                error="Access denied"
            )

        except Exception as e:
            return FileHashResult(
                path=filepath,
                sha256=None,
                size_bytes=None,
                mtime=None,
                success=False,
                error=str(e)
            )
