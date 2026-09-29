from dataclasses import dataclass
import os
import xml.etree.ElementTree as ET
from typing import Any


@dataclass
class GreenboneFinding:
    host: str
    port: int | None
    name: str
    severity: str | None
    cvss_score: float | None
    cve_ids: list[str]
    cwe_ids: list[str]
    description: str | None
    solution: str | None
    evidence: str | None


class GreenboneClient:
    """
    Optional Greenbone/OpenVAS integration.

    The scanner is disabled unless explicitly configured with a
    Greenbone/OpenVAS feed or connector.

    Environment variables:
        GREENBONE_ENABLED=true
        GREENBONE_HOST=<scanner host>
        GREENBONE_PORT=<scanner port>
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        enabled: bool | None = None,
    ) -> None:
        self.host = host or os.getenv("GREENBONE_HOST", "127.0.0.1")
        self.port = port or int(
            os.getenv("GREENBONE_PORT", "9390")
        )

        if enabled is None:
            enabled = (
                os.getenv("GREENBONE_ENABLED", "false")
                .strip()
                .lower()
                in {"1", "true", "yes", "on"}
            )

        self.enabled = enabled

    def is_available(self) -> bool:
        """
        Return whether Greenbone integration is enabled.

        Actual Greenbone connectivity is intentionally not attempted
        unless the integration is explicitly enabled.
        """
        return self.enabled

    def scan(self, target: str) -> list[GreenboneFinding]:
        """
        Run a Greenbone/OpenVAS assessment.

        This adapter currently provides the integration boundary.
        A live Greenbone deployment/credential configuration is
        required before executing a real GMP/OSP scan.
        """
        if not self.enabled:
            return []

        raise RuntimeError(
            "Greenbone/OpenVAS is enabled but no live GMP/OSP "
            "connector is configured."
        )

    @staticmethod
    def parse_report(report_xml: str) -> list[GreenboneFinding]:
        """
        Parse a Greenbone XML report into normalized findings.

        This parser is deliberately tolerant because Greenbone
        report structures can vary between versions.
        """
        root = ET.fromstring(report_xml)
        findings: list[GreenboneFinding] = []

        for result in root.findall(".//result"):
            name = (
                result.findtext("./name")
                or result.findtext("./nvt/name")
                or "Greenbone finding"
            )

            host = (
                result.findtext("./host")
                or ""
            )

            port_text = result.findtext("./port")
            port: int | None = None

            if port_text:
                try:
                    port = int(
                        port_text.split("/")[0]
                    )
                except ValueError:
                    port = None

            severity_text = result.findtext("./severity")
            cvss_score: float | None = None

            if severity_text:
                try:
                    cvss_score = float(severity_text)
                except ValueError:
                    cvss_score = None

            description = (
                result.findtext("./description")
                or result.findtext("./nvt/description")
            )

            solution = (
                result.findtext("./solution")
                or result.findtext("./nvt/solution")
            )

            cve_ids = [
                value.text.strip()
                for value in result.findall(".//cve")
                if value.text and value.text.strip()
            ]

            cwe_ids = [
                value.text.strip()
                for value in result.findall(".//cwe")
                if value.text and value.text.strip()
            ]

            findings.append(
                GreenboneFinding(
                    host=host,
                    port=port,
                    name=name,
                    severity=None,
                    cvss_score=cvss_score,
                    cve_ids=cve_ids,
                    cwe_ids=cwe_ids,
                    description=description,
                    solution=solution,
                    evidence=None,
                )
            )

        return findings