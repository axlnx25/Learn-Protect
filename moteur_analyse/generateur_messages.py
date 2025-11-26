# module_b/message_generator.py

from dataclasses import dataclass
from typing import Dict, Any, List
from .score_de_risque import ScoreResult


@dataclass
class PedagogicMessage:
    risk_level: str
    score: int
    summary: str
    details: List[str]
    explanations: List[str]
    best_practices: List[str]


class MessageGenerator:
    """
    Générateur de messages pédagogiques basé sur :
    - les règles heuristiques déclenchées
    - le niveau de risque final
    """

    # Mapping : règle → explication pédagogique
    RULE_EXPLANATIONS = {
        "PATH_TMP": "Les exécutables dans /tmp sont souvent utilisés par des malwares car ce dossier est temporaire et non surveillé.",
        "PATH_DOWNLOADS": "Les exécutables lancés depuis Downloads proviennent souvent d'archives ou d'emails douteux.",
        "HIDDEN_EXECUTABLE": "Les fichiers cachés peuvent être utilisés pour dissimuler des programmes malveillants.",
        "UNSIGNED_BINARY": "Un programme non signé n’est pas forcément dangereux, mais augmente les risques.",
        "NETWORK_SUSPICIOUS_IP": "Le processus communique avec une IP suspecte, potentiellement un serveur de commande et contrôle.",
        "NETWORK_EXTERNAL": "Ce processus effectue une connexion sortante inhabituelle.",
        "CPU_SPIKE": "Le processus consomme fortement le CPU, comportement typique de cryptominers ou scanners.",
        "MEMORY_ABNORMAL": "La consommation mémoire est anormalement élevée.",
        "INTEGRITY_FAIL": "Le hash du fichier ne correspond pas à la version connue : le binaire pourrait avoir été modifié.",
        "PRIV_ESCALATION": "Le processus possède des privilèges administrateur injustifiés.",
        "PPID_ANOMALY": "Le parent de ce processus est inhabituel, ce qui peut indiquer un chargement indirect malveillant.",
    }

    # Mapping règles → bonnes pratiques
    RULE_PRACTICES = {
        "PATH_TMP": "Évitez d’exécuter des programmes depuis /tmp. Utilisez des dossiers protégés.",
        "PATH_DOWNLOADS": "Ne lancez jamais un exécutable directement depuis Downloads.",
        "HIDDEN_EXECUTABLE": "Affichez les fichiers cachés et vérifiez les binaires inconnus.",
        "UNSIGNED_BINARY": "Téléchargez des logiciels signés provenant de sources officielles.",
        "NETWORK_SUSPICIOUS_IP": "Bloquez les connexions sortantes non reconnues via un pare-feu.",
        "NETWORK_EXTERNAL": "Vérifiez l’activité réseau des logiciels inconnus.",
        "CPU_SPIKE": "Réduisez les processus inutiles et analysez tout pic anormal.",
        "MEMORY_ABNORMAL": "Surveillez l’utilisation de la mémoire et fermez tout processus anormal.",
        "INTEGRITY_FAIL": "Ne jamais exécuter un programme dont l’intégrité est compromise.",
        "PRIV_ESCALATION": "N’exécutez pas d’applications en administrateur sans nécessité.",
        "PPID_ANOMALY": "Vérifiez la chaîne de processus et identifiez les lancements suspects.",
    }

    # Messages généraux en fonction du niveau
    LEVEL_SUMMARY = {
        "SAFE": "🟢 Aucun signe de comportement malveillant.",
        "SUSPICIOUS": "🟡 Activité suspecte détectée. Une vérification manuelle est recommandée.",
        "DANGEROUS": "🔴 Risque élevé : ce processus présente plusieurs indicateurs de comportement dangereux.",
    }

    def __init__(self):
        pass

    def generate(self, score_result: ScoreResult) -> PedagogicMessage:
        """
        Transforme un ScoreResult en message pédagogique structuré.
        """
        risk_level = score_result.level.upper()
        summary = self.LEVEL_SUMMARY.get(risk_level, "")

        details = []
        explanations = []
        practices = []

        # Pour chaque règle déclenchée
        for trig in score_result.triggers:
            rule_id = trig.get("rule_id")
            msg = trig.get("message")

            # Détails factuels (ex. "Connexion vers IP 1.2.3.4:443")
            details.append(f"• {msg}")

            # Explication pédagogique
            if rule_id in self.RULE_EXPLANATIONS:
                explanations.append(f"- {self.RULE_EXPLANATIONS[rule_id]}")

            # Bonne pratique associée
            if rule_id in self.RULE_PRACTICES:
                practices.append(f"👉 {self.RULE_PRACTICES[rule_id]}")

        return PedagogicMessage(
            risk_level=risk_level,
            score=score_result.total_score,
            summary=summary,
            details=details,
            explanations=explanations,
            best_practices=practices
        )


# ---------------------------------------
# Exemple d’exécution
# ---------------------------------------
if __name__ == "__main__":
    from .score_de_risque import ScoringEngine

    triggers = [
        {"rule_id": "PATH_TMP", "score": 20, "message": "Exécuté depuis /tmp/evil"},
        {"rule_id": "NETWORK_SUSPICIOUS_IP", "score": 30, "message": "Connexion vers 203.55.77.12:4444"},
        {"rule_id": "UNSIGNED_BINARY", "score": 10, "message": "Binaire non signé"},
    ]

    scorer = ScoringEngine()
    score = scorer.score_from_triggers(triggers)

    generator = MessageGenerator()
    msg = generator.generate(score)

    print(msg)
