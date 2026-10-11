
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path



def resolve_executable(env_name: str, executable_name: str) -> str:
    """Resolve an executable from configuration or system PATH."""
    configured_path = os.getenv(env_name)

    if configured_path:
        path = Path(configured_path).expanduser()

        if path.is_file():
            return str(path.resolve())

        raise FileNotFoundError(
            f"{env_name} points to a missing executable: {path}"
        )

    resolved_path = shutil.which(executable_name)

    if resolved_path:
        return resolved_path

    raise FileNotFoundError(
        f"{executable_name} was not found. "
        f"Add it to system PATH or configure {env_name}."
    )


NUCLEI_PATH = resolve_executable("NUCLEI_PATH", "nuclei")


# Maximum time allowed for the complete Nuclei process.
# Can be changed without modifying code.
NUCLEI_PROCESS_TIMEOUT = int(
    os.getenv("NUCLEI_PROCESS_TIMEOUT", "900")
)


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

        # Request timeout
        "-timeout",
        "5",

        # No retries
        "-retries",
        "0",

        # Controlled concurrency
        "-c",
        "25",

        # Controlled request rate
        "-rl",
        "100",

        # Batch size
        "-bs",
        "25",

        # No Interactsh
        "-no-interactsh",

        # No automatic update check
        "-disable-update-check",
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

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=NUCLEI_PROCESS_TIMEOUT,
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Nuclei scan exceeded the configured "
            f"{NUCLEI_PROCESS_TIMEOUT}s process timeout "
            f"for target {target}"
        ) from exc

    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()

        raise RuntimeError(
            f"Nuclei exited with code {exc.returncode}"
            + (f": {stderr[-1000:]}" if stderr else "")
        ) from exc

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
            port = (
                int(port_value)
                if port_value is not None
                else None
            )
        except (TypeError, ValueError):
            port = None

        findings.append(
            NucleiFinding(
                template_id=data.get(
                    "template-id",
                    "",
                ),
                name=info.get(
                    "name",
                    "",
                ),
                severity=info.get(
                    "severity",
                    "unknown",
                ),
                host=data.get("host"),
                port=port,
                matched_at=data.get(
                    "matched-at",
                ),
                matcher_name=data.get(
                    "matcher-name",
                ),
                cve_id=cve_id,
                cwe_ids=cwe_ids,
                cvss_score=cvss_score,
                cvss_metrics=classification.get(
                    "cvss-metrics",
                ),
                cpe=classification.get(
                    "cpe",
                ),
            )
        )

    return findings