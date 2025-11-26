# module_b/heuristic.py

from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class HeuristicResult:
    rule_id: str
    score: int
    message: str
    metadata: dict


class HeuristicRule:
    """Classe abstraite pour une règle heuristique."""
    rule_id: str = "BASE_RULE"
    score: int = 0

    def check(self, data: dict) -> List[HeuristicResult]:
        raise NotImplementedError


# ============================================================
#   A. RÈGLES BASÉES SUR LES CHEMINS DE FICHIERS
# ============================================================

class RulePathTmp(HeuristicRule):
    rule_id = "PATH_TMP"
    score = 20

    def check(self, data):
        exe = data.get("exe_path", "").lower()
        suspicious_paths = ["/tmp", "appdata\\local\\temp", "downloads", "/var/tmp"]

        for p in suspicious_paths:
            if exe.startswith(p):
                return [HeuristicResult(
                    rule_id=self.rule_id,
                    score=self.score,
                    message=f"Le processus s'exécute depuis {p}, ce qui est inhabituel.",
                    metadata={"exe": exe}
                )]
        return []


class RuleHiddenFile(HeuristicRule):
    rule_id = "HIDDEN_FILE"
    score = 15

    def check(self, data):
        exe = data.get("exe_path", "")
        if exe.split("/")[-1].startswith("."):
            return [HeuristicResult(
                rule_id=self.rule_id,
                score=self.score,
                message="L'exécutable est un fichier caché, caractéristique fréquente de malware.",
                metadata={"exe": exe}
            )]
        return []


# ============================================================
#   B. RÈGLES BASÉES SUR LE RÉSEAU
# ============================================================

class RuleManyConnections(HeuristicRule):
    rule_id = "NETWORK_MANY_CONN"
    score = 25

    def check(self, data):
        conns = data.get("network", [])
        if len(conns) > 20:
            return [HeuristicResult(
                rule_id=self.rule_id,
                score=self.score,
                message=f"Ce processus a plus de {len(conns)} connexions actives — possible botnet.",
                metadata={"connections": len(conns)}
            )]
        return []


class RuleSuspiciousRemoteIP(HeuristicRule):
    rule_id = "NETWORK_SUSPICIOUS_IP"
    score = 30

    def check(self, data):
        suspicious_zones = ("ru", "cn", "kp", "ir")
        result = []

        for conn in data.get("network", []):
            geo = conn.get("geo", "")
            if geo.lower() in suspicious_zones:
                result.append(HeuristicResult(
                    rule_id=self.rule_id,
                    score=self.score,
                    message=f"Connexion à une IP située en zone sensible ({geo}).",
                    metadata={"ip": conn.get("ip"), "geo": geo}
                ))
        return result


# ============================================================
#   C. RÈGLES PERMISSIONS / SIGNATURE
# ============================================================

class RuleUnsignedBinary(HeuristicRule):
    rule_id = "UNSIGNED_BINARY"
    score = 10

    def check(self, data):
        if data.get("signature", {}).get("signed") is False:
            return [HeuristicResult(
                rule_id=self.rule_id,
                score=self.score,
                message="Le fichier exécutable n'est pas signé.",
                metadata=data.get("signature")
            )]
        return []


class RuleUnexpectedAdmin(HeuristicRule):
    rule_id = "ADMIN_PRIVILEGE"
    score = 20

    def check(self, data):
        user = data.get("user", "").lower()
        if user in ("root", "administrator"):
            parent = data.get("parent_name", "")
            if parent not in ("systemd", "services.exe", "wininit.exe"):
                return [HeuristicResult(
                    rule_id=self.rule_id,
                    score=self.score,
                    message="Le processus s'exécute avec des privilèges élevés sans justification.",
                    metadata={"user": user, "parent": parent}
                )]
        return []


# ============================================================
#   D. RÈGLES CPU / RAM / RESSOURCES
# ============================================================

class RuleHighCPU(HeuristicRule):
    rule_id = "HIGH_CPU"
    score = 20

    def check(self, data):
        cpu = data.get("cpu_percent", 0)
        if cpu > 80:
            return [HeuristicResult(
                rule_id=self.rule_id,
                score=self.score,
                message=f"CPU anormalement élevé : {cpu}%.",
                metadata={"cpu": cpu}
            )]
        return []


class RuleHighMemory(HeuristicRule):
    rule_id = "HIGH_MEMORY"
    score = 15

    def check(self, data):
        mem = data.get("memory_rss", 0)
        if mem > 500 * 1024 * 1024:  # 500MB
            return [HeuristicResult(
                rule_id=self.rule_id,
                score=self.score,
                message=f"Utilisation RAM élevée : {mem/1024/1024:.1f} MB.",
                metadata={"rss": mem}
            )]
        return []


# ============================================================
#   E. RÈGLES BASÉES SUR L’ARBRE DES PROCESSUS
# ============================================================

class RuleSuspiciousParent(HeuristicRule):
    rule_id = "SUSPICIOUS_PARENT"
    score = 25

    def check(self, data):
        parent = data.get("parent_name", "").lower()
        child = data.get("name", "").lower()

        suspicious_pairs = [
            ("word.exe", "powershell.exe"),
            ("winword.exe", "cmd.exe"),
            ("firefox", "bash"),
            ("chrome", "python"),
        ]

        for p, c in suspicious_pairs:
            if parent.startswith(p) and child.startswith(c):
                return [HeuristicResult(
                    rule_id=self.rule_id,
                    score=self.score,
                    message=f"Relation parent-enfant suspecte : {parent} → {child}",
                    metadata={"parent": parent, "child": child}
                )]
        return []


# ============================================================
#   F. RÈGLES D'INTÉGRITÉ (basées sur Module C)
# ============================================================

class RuleIntegrityFailed(HeuristicRule):
    rule_id = "INTEGRITY_FAIL"
    score = 40

    def check(self, data):
        integ = data.get("integrity", {})
        if integ.get("status") == "modified":
            return [HeuristicResult(
                rule_id=self.rule_id,
                score=self.score,
                message="L’intégrité du fichier a été compromise (hash modifié).",
                metadata=integ
            )]
        return []


# ============================================================
#   MOTEUR HEURISTIQUE PRINCIPAL
# ============================================================

class HeuristicEngine:
    def __init__(self):
        self.rules: List[HeuristicRule] = [
            RulePathTmp(),
            RuleHiddenFile(),
            RuleManyConnections(),
            RuleSuspiciousRemoteIP(),
            RuleUnsignedBinary(),
            RuleUnexpectedAdmin(),
            RuleHighCPU(),
            RuleHighMemory(),
            RuleSuspiciousParent(),
            RuleIntegrityFailed()
        ]

    def analyze(self, process_data: dict) -> Dict[str, Any]:
        """Retourne un score total + la liste des règles activées."""
        results: List[HeuristicResult] = []

        for rule in self.rules:
            r = rule.check(process_data)
            if r:
                results.extend(r)

        total_score = sum(r.score for r in results)

        return {
            "score": total_score,
            "triggers": [r.__dict__ for r in results]
        }
