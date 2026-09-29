from dataclasses import dataclass


@dataclass
class RiskResult:
    level: str
    reason: str


def classify_risk(
    severity: str | None,
    cvss_score: float | None,
    confidence: int | None,
) -> RiskResult:
    """
    Initial deterministic risk classification.

    Priority:
    1. Numeric CVSS score when available.
    2. Otherwise use the scanner-reported severity.
    3. Detection confidence is preserved as evidence quality,
       but is not used to artificially increase severity.
    """

    normalized_severity = (severity or "").strip().lower()

    if cvss_score is not None:
        if cvss_score >= 9.0:
            return RiskResult(
                level="critical",
                reason=f"CVSS score {cvss_score:.1f} indicates critical severity.",
            )

        if cvss_score >= 7.0:
            return RiskResult(
                level="high",
                reason=f"CVSS score {cvss_score:.1f} indicates high severity.",
            )

        if cvss_score >= 4.0:
            return RiskResult(
                level="medium",
                reason=f"CVSS score {cvss_score:.1f} indicates medium severity.",
            )

        if cvss_score > 0.0:
            return RiskResult(
                level="low",
                reason=f"CVSS score {cvss_score:.1f} indicates low severity.",
            )

        return RiskResult(
            level="informational",
            reason="CVSS score is 0.0.",
        )

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "informational",
        "informational": "informational",
        "unknown": "informational",
    }

    level = severity_map.get(normalized_severity, "informational")

    confidence_text = (
        f" Detection confidence: {confidence}."
        if confidence is not None
        else ""
    )

    return RiskResult(
        level=level,
        reason=(
            f"Classification based on reported severity "
            f"'{normalized_severity or 'unknown'}'."
            f"{confidence_text}"
        ),
    )