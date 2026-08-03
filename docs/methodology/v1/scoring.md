# Scoring behavior 1.0

Applicable completed checks use `pass=1`, `warning=0.5`, and `fail=0`. Suppressed and accepted-risk failures retain a zero factor so workflow decisions cannot improve posture. Unknown, error, and missing evidence reduce coverage but do not become failures. Not-applicable checks leave the denominator.

Pillar scores are weighted means of completed applicable checks. Overall posture is the weighted mean of available pillars and is withheld below 60% weighted coverage. Values are rounded once to six decimal places.

Technical posture, coverage, evidence confidence, and attribution confidence remain separate. Critical caps require an explicit policy cap plus current, required, high-confidence, directly attributable, non-fixture evidence without provider disagreement. A cap can only lower a score.

Monotonicity applies only under fixed methodology, applicability, coverage, confidence, and attribution. Other changes require explicit attribution.
