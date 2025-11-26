# module_b/classifier.py

from dataclasses import dataclass
from typing import Optional
from .score_de_risque import ScoreResult


@dataclass
class ClassificationResult:
    label: str          # SAFE / SUSPICIOUS / DANGEROUS
    level: int          # 0, 1, 2
    score: int          # score total
    explanation: str    # résumé simple pour UI


class Classifier:
    """
    Module de classification basé sur le ScoreResult.
    Ne calcule rien : il applique simplement la grille de décision.
    """

    LABELS = {
        "SAFE": 0,
        "SUSPICIOUS": 1,
        "DANGEROUS": 2,
    }

    EXPLANATIONS = {
        "SAFE": "Aucun comportement malveillant apparent.",
        "SUSPICIOUS": "Certains comportements nécessitent une vérification.",
        "DANGEROUS": "Comportement fortement suspect détecté. Action recommandée.",
    }

    def __init__(self):
        pass

    def classify(self, score_result: ScoreResult) -> ClassificationResult:
        """
        Transforme un ScoreResult en ClassificationResult utilisable par le front-end.
        """
        label = score_result.level.upper()

        level = self.LABELS.get(label, 0)
        explanation = self.EXPLANATIONS.get(label, "")

        return ClassificationResult(
            label=label,
            level=level,
            score=score_result.total_score,
            explanation=explanation
        )


# ------------------------------------
# Exemple d’utilisation interne
# ------------------------------------
if __name__ == "__main__":
    # exemple de test
    from .score_de_risque import ScoringEngine

    triggers = [
        {"rule_id": "PATH_TMP", "score": 20, "message": "Depuis /tmp"},
        {"rule_id": "UNSIGNED_BINARY", "score": 15, "message": "Non signé"},
    ]

    scoring = ScoringEngine()
    result_score = scoring.score_from_triggers(triggers)

    classifier = Classifier()
    classification = classifier.classify(result_score)

    print(classification)
