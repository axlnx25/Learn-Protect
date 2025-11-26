# module_b/scoring.py

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class Trigger:
    rule_id: str
    score: int
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreResult:
    total_score: int
    level: str                  # "SAFE", "SUSPICIOUS", "DANGEROUS"
    breakdown: Dict[str, int]   # rule_id -> effective score
    triggers: List[Dict[str, Any]]  # original triggers (dicts)
    adjusted_scores: Optional[Dict[str, int]] = None  # if weights applied


class ScoringEngine:
    """
    Scoring engine configurable by:
      - thresholds: dict with 'safe', 'suspicious', 'dangerous' upper bounds
      - rule_weights: optional mapping rule_id -> multiplier or absolute override
      - min_score_per_rule: optional floor (not used by default)
    """

    DEFAULT_THRESHOLDS = {
        "safe": 30,        # 0..30 => SAFE
        "suspicious": 70,  # 31..70 => SUSPICIOUS
        # >70 => DANGEROUS
    }

    def __init__(self,
                 thresholds: Optional[Dict[str, int]] = None,
                 rule_weights: Optional[Dict[str, float]] = None,
                 absolute_overrides: Optional[Dict[str, int]] = None):
        """
        - thresholds: override DEFAULT_THRESHOLDS
        - rule_weights: multiplier applied to each rule's base score (float)
            e.g. {"INTEGRITY_FAIL": 1.5} will multiply that rule by 1.5
        - absolute_overrides: if present, replaces given rule's score with this absolute value
            (takes precedence over rule_weights)
        """
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS.copy()
        self.rule_weights = rule_weights or {}
        self.absolute_overrides = absolute_overrides or {}

    def _apply_weight(self, rule_id: str, base_score: int) -> int:
        """
        Apply absolute override or multiplier and return effective integer score.
        """
        if rule_id in self.absolute_overrides:
            return int(self.absolute_overrides[rule_id])
        multiplier = self.rule_weights.get(rule_id, 1.0)
        effective = int(round(base_score * multiplier))
        return effective

    def score_from_triggers(self, triggers: List[Dict[str, Any]]) -> ScoreResult:
        """
        Accepts triggers as produced by HeuristicEngine:
          {'score': <int>, 'triggers': [ {rule fields...}, ... ]}
        or accepts a simple list of trigger dicts:
          [{'rule_id': 'X', 'score': 20, 'message': '...'}, ...]
        Returns ScoreResult.
        """
        # Normalize triggers to list of dicts with keys: rule_id, score, message
        normalized: List[Trigger] = []
        for t in triggers:
            # Accept both dataclass-like dicts and raw dicts
            rule_id = t.get("rule_id") or t.get("rule") or t.get("id")
            score = t.get("score", 0)
            message = t.get("message", "")
            metadata = t.get("metadata", {}) if isinstance(t.get("metadata", {}), dict) else {}
            normalized.append(Trigger(rule_id=rule_id, score=int(score), message=message, metadata=metadata))

        breakdown: Dict[str, int] = {}
        adjusted_scores: Dict[str, int] = {}
        total = 0

        for trig in normalized:
            effective = self._apply_weight(trig.rule_id, trig.score)
            breakdown[trig.rule_id] = breakdown.get(trig.rule_id, 0) + trig.score
            adjusted_scores[trig.rule_id] = adjusted_scores.get(trig.rule_id, 0) + effective
            total += effective

        # Classification by thresholds
        if total <= self.thresholds["safe"]:
            level = "SAFE"
        elif total <= self.thresholds["suspicious"]:
            level = "SUSPICIOUS"
        else:
            level = "DANGEROUS"

        return ScoreResult(
            total_score=total,
            level=level,
            breakdown=breakdown,
            triggers=[t.__dict__ for t in normalized],
            adjusted_scores=adjusted_scores
        )

    def score_from_heuristic_output(self, heuristic_output: Dict[str, Any]) -> ScoreResult:
        """
        If you pass the direct output of HeuristicEngine.analyze ({"score":..., "triggers":[...]})
        we use the triggers list to compute adjusted score (so we don't rely on the precomputed sum).
        """
        triggers = heuristic_output.get("triggers", [])
        return self.score_from_triggers(triggers)


# -----------------------------
# Example usage (for tests/docs)
# -----------------------------
if __name__ == "__main__":
    # sample triggers (as produced by HeuristicEngine)
    sample_triggers = [
        {"rule_id": "PATH_TMP", "score": 20, "message": "Executed from /tmp"},
        {"rule_id": "UNSIGNED_BINARY", "score": 10, "message": "Binary unsigned"},
        {"rule_id": "NETWORK_SUSPICIOUS_IP", "score": 30, "message": "Connected to suspicious IP"},
        {"rule_id": "INTEGRITY_FAIL", "score": 40, "message": "Hash mismatch detected"},
    ]

    engine = ScoringEngine()
    result = engine.score_from_triggers(sample_triggers)
    print("TOTAL:", result.total_score)
    print("LEVEL:", result.level)
    print("BREAKDOWN:", result.breakdown)
    print("ADJUSTED:", result.adjusted_scores)

    # Example with custom weights: make integrity fail more severe
    engine2 = ScoringEngine(rule_weights={"INTEGRITY_FAIL": 2.0})
    result2 = engine2.score_from_triggers(sample_triggers)
    print("--- with override ---")
    print("TOTAL:", result2.total_score)
    print("LEVEL:", result2.level)
    print("ADJUSTED:", result2.adjusted_scores)
