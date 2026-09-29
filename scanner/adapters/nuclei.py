import json
import subprocess
from dataclasses import dataclass


NUCLEI_PATH = r"C:\Users\fajle\go\bin\nuclei.exe"


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    host: str | None
    port: int | None
    matched_at: str | None
    matcher_name: str | None
    cve_id: str | None
    cwe_ids: list[str]
    cvss_score: float | None
    cvss_metrics: str | None
    cpe: str | None


def run_nuclei(
    target: str,
    tags: str | None = None,
    severity: str | None = None,
) -> list[NucleiFinding]:

    command = [
        NUCLEI_PATH,
        "-target",
        target,
        "-jsonl",
        "-silent",
        "-timeout",
        "5",
        "-retries",
        "0",
        "-no-interactsh",
    ]

    if tags:
        command.extend([
            "-tags",
            tags,
        ])

    if severity:
        command.extend([
            "-severity",
            severity,
        ])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=300,
    )
    findings: list[NucleiFinding] = []

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line.startswith("{"):
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info") or {}
        classification = info.get("classification") or {}

        cve_id = classification.get("cve-id")
        cwe_ids = classification.get("cwe-id") or []

        cvss_score_value = classification.get("cvss-score")
        try:
            cvss_score = (
            float(cvss_score_value)
            if cvss_score_value is not None
            else None
            )
        except (TypeError, ValueError):
            cvss_score = None

        if isinstance(cve_id, list):
            cve_id = cve_id[0] if cve_id else None

        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        port_value = data.get("port")

        try:
            port = int(port_value) if port_value is not None else None
        except (TypeError, ValueError):
            port = None

        findings.append(
            NucleiFinding(
                template_id=data.get("template-id", ""),
                name=info.get("name", ""),
                severity=info.get("severity", "unknown"),
                host=data.get("host"),
                port=port,
                matched_at=data.get("matched-at"),
                matcher_name=data.get("matcher-name"),
                cve_id=cve_id,
                cwe_ids=cwe_ids,
                cvss_score=cvss_score,
                cvss_metrics=classification.get("cvss-metrics"),
                cpe=classification.get("cpe"),
            )
        )

    return findings