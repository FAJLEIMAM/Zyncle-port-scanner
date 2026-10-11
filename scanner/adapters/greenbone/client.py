from __future__ import annotations

import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import settings


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
    cvss_metrics: str | None = None


class GreenboneClient:
    """
    Greenbone/OpenVAS GMP adapter.

    Greenbone is an additional vulnerability-assessment adapter.
    Existing Zyncle scanner engines remain untouched.

    Communication path:

        Zyncle Python
            |
            v
        docker compose run gvm-tools
            |
            v
        gvm-cli
            |
            v
        gvmd Unix socket
            |
            v
        Greenbone/OpenVAS
    """

    DEFAULT_COMPOSE_DIR = ""
    DEFAULT_COMPOSE_FILE = "compose.yaml"
    DEFAULT_COMPOSE_SERVICE = "gvm-tools"
    DEFAULT_SOCKET = "/run/gvmd/gvmd.sock"

    # ------------------------------------------------------------
    # Greenbone scan configurations
    # ------------------------------------------------------------

    # Lightweight / Base configuration
    DEFAULT_LIGHTWEIGHT_CONFIG_ID = (
        "d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663"
    )

    # Full & Fast configuration
    DEFAULT_FULL_CONFIG_ID = (
        "daba56c8-73ec-11df-a475-002264764cea"
    )

    DEFAULT_SCANNER_ID = (
        "08b69003-5fc2-4037-a479-93b440211c73"
    )

    DEFAULT_PORT_LIST_ID = (
        "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    )

    VALID_VULNERABILITY_PROFILES = {
        "lightweight",
        "full",
    }

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        enabled: bool | None = None,
    ) -> None:
        # Kept for compatibility with the previous adapter.
        self.host = host or "127.0.0.1"
        self.port = port or 9390

        self.enabled = (
            settings.greenbone_enabled
            if enabled is None
            else enabled
        )

        self.compose_dir = Path(
            settings.greenbone_compose_dir
        )

        self.compose_file = (
            settings.greenbone_compose_file
        )

        self.compose_service = (
            settings.greenbone_compose_service
        )

        self.socket_path = (
            settings.greenbone_socket
        )

        self.username = (
            settings.greenbone_username
        )

        self.password = (
            settings.greenbone_password
        )

        # Existing environment configuration remains the
        # lightweight/default configuration for compatibility.
        self.config_id = (
            settings.greenbone_config_id
            or self.DEFAULT_LIGHTWEIGHT_CONFIG_ID
        )

        self.scanner_id = (
            settings.greenbone_scanner_id
            or self.DEFAULT_SCANNER_ID
        )

        self.port_list_id = (
            settings.greenbone_port_list_id
            or self.DEFAULT_PORT_LIST_ID
        )

        self.timeout_seconds = (
            settings.greenbone_timeout_seconds
        )

        self.poll_seconds = (
            settings.greenbone_poll_seconds
        )

    # ============================================================
    # Public API
    # ============================================================

    def is_available(self) -> bool:
        """Return whether the Greenbone adapter is enabled."""
        return self.enabled

    def get_version(self) -> str:
        """Return the GMP server version."""

        response = self._run_gmp(
            "<get_version/>"
        )

        version = response.findtext(
            ".//version"
        )

        if not version:
            raise RuntimeError(
                "Greenbone GMP did not return a server version."
            )

        return version.strip()

    def scan(
        self,
        target: str,
        scan_id: int | str | None = None,
        vulnerability_profile: str = "lightweight",
    ) -> list[GreenboneFinding]:
        """
        Run a Greenbone vulnerability scan.

        Profiles:

            lightweight
                Greenbone Base configuration

            full
                Greenbone Full and Fast configuration
        """

        if not self.enabled:
            return []

        profile = (
            vulnerability_profile
            .strip()
            .lower()
        )

        if profile not in self.VALID_VULNERABILITY_PROFILES:
            raise ValueError(
                "Unsupported Greenbone vulnerability profile: "
                f"{vulnerability_profile}. "
                "Use 'lightweight' or 'full'."
            )

        config_id = self._get_config_id(
            profile
        )

        host = self._normalize_host(target)

        if not self.username:
            raise RuntimeError(
                "GREENBONE_USERNAME is not configured."
            )

        if not self.password:
            raise RuntimeError(
                "GREENBONE_PASSWORD is not configured."
            )

        print(
            f"[GREENBONE] Profile={profile}",
            flush=True,
        )

        print(
            f"[GREENBONE] Config={config_id}",
            flush=True,
        )

        print(
            "[GREENBONE] GMP version: "
            f"{self.get_version()}",
            flush=True,
        )

        target_id = self._find_target(
            host
        )

        if target_id:
            print(
                "[GREENBONE] Reusing target "
                f"{target_id} for {host}",
                flush=True,
            )
        else:
            target_id = self._create_target(
                host
            )

            print(
                "[GREENBONE] Created target "
                f"{target_id} for {host}",
                flush=True,
            )

        task_name = self._build_task_name(
            host,
            scan_id,
            profile,
        )

        task_id = self._create_task(
            task_name=task_name,
            target_id=target_id,
            config_id=config_id,
        )

        print(
            f"[GREENBONE] Created task {task_id}",
            flush=True,
        )

        report_id = self._start_task(
            task_id
        )

        print(
            f"[GREENBONE] Started task {task_id}; "
            f"report={report_id}",
            flush=True,
        )

        self._wait_for_task(
            task_id
        )

        report_xml = self._get_report(
            report_id
        )

        findings = self.parse_report(
            report_xml
        )

        print(
            f"[GREENBONE] Parsed "
            f"{len(findings)} findings",
            flush=True,
        )

        return findings

    # ============================================================
    # Profile selection
    # ============================================================

    def _get_config_id(
        self,
        profile: str,
    ) -> str:
        """
        Resolve Greenbone configuration from vulnerability profile.

        lightweight:
            Uses GREENBONE_CONFIG_ID when configured,
            otherwise Greenbone Base.

        full:
            Always uses Greenbone Full and Fast.
        """

        profile = profile.strip().lower()

        if profile == "lightweight":
            return (
                self.config_id
                or self.DEFAULT_LIGHTWEIGHT_CONFIG_ID
            )

        if profile == "full":
            return self.DEFAULT_FULL_CONFIG_ID

        raise ValueError(
            f"Unsupported Greenbone profile: {profile}"
        )

    # ============================================================
    # GMP operations
    # ============================================================

    def _run_gmp(
        self,
        xml_command: str,
    ) -> ET.Element:
        """
        Execute one GMP XML command through gvm-tools Docker service.

        Credentials are written to a temporary config file instead
        of being placed directly in command arguments.
        """

        if not self.compose_dir.exists():
            raise RuntimeError(
                "Greenbone compose directory does not exist: "
                f"{self.compose_dir}"
            )

        compose_path = (
            self.compose_dir / self.compose_file
        )

        if not compose_path.exists():
            raise RuntimeError(
                "Greenbone compose file does not exist: "
                f"{compose_path}"
            )

        config_text = (
            "[gmp]\n"
            f"username={self.username}\n"
            f"password={self.password}\n"
            "\n"
            "[unixsocket]\n"
            f"socketpath={self.socket_path}\n"
        )

        with tempfile.TemporaryDirectory(
            prefix="zyncle-gvm-"
        ) as temp_dir:

            temp_path = (
                Path(temp_dir)
                / "gvm-tools.conf"
            )

            temp_path.write_text(
                config_text,
                encoding="utf-8",
            )

            mount = (
                f"{temp_path}"
                ":/tmp/gvm-tools.conf:ro"
            )

            command = [
                "docker",
                "compose",
                "-f",
                str(compose_path),
                "run",
                "--rm",
                "-T",
                "-v",
                mount,
                self.compose_service,
                "gvm-cli",
                "--config",
                "/tmp/gvm-tools.conf",
                "socket",
                "--socketpath",
                self.socket_path,
                "-X",
                xml_command,
            ]

            try:
                completed = subprocess.run(
                    command,
                    cwd=str(self.compose_dir),
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )

            except FileNotFoundError as exc:
                raise RuntimeError(
                    "Docker CLI was not found. "
                    "Make sure Docker Desktop is running "
                    "and docker.exe is available in PATH."
                ) from exc

            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    "Greenbone GMP command timed out."
                ) from exc

        if completed.returncode != 0:
            stderr = (
                completed.stderr.strip()
                or completed.stdout.strip()
            )

            raise RuntimeError(
                "Greenbone GMP command failed: "
                f"{stderr}"
            )

        output = completed.stdout.strip()

        if not output:
            raise RuntimeError(
                "Greenbone GMP returned an empty response."
            )

        try:
            root = ET.fromstring(output)

        except ET.ParseError as exc:
            raise RuntimeError(
                "Greenbone returned invalid XML.\n"
                f"Output:\n{output[:2000]}"
            ) from exc

        status = root.attrib.get(
            "status"
        )

        if status and status not in {
            "200",
            "201",
            "202",
        }:
            status_text = root.attrib.get(
                "status_text",
                "",
            )

            raise RuntimeError(
                "Greenbone GMP error "
                f"{status}: {status_text}"
            )

        return root

    def _find_target(
        self,
        host: str,
    ) -> str | None:
        """Find an existing Greenbone target containing host."""

        root = self._run_gmp(
            "<get_targets/>"
        )

        for target in root.findall(
            ".//target"
        ):
            target_id = target.attrib.get(
                "id"
            )

            if not target_id:
                continue

            hosts = target.findtext(
                "./hosts"
            ) or ""

            normalized_hosts = {
                item.strip().lower()
                for item in hosts.split(",")
                if item.strip()
            }

            if host.lower() in normalized_hosts:
                return target_id

        return None

    def _create_target(
        self,
        host: str,
    ) -> str:
        """Create a Greenbone target."""

        command = (
            "<create_target>"
            "<name>Zyncle - "
            f"{self._xml_escape(host)}"
            "</name>"
            "<comment>"
            "Created by Zyncle Port Scanner"
            "</comment>"
            "<hosts>"
            f"{self._xml_escape(host)}"
            "</hosts>"
            f'<port_list id="{self.port_list_id}"/>'
            "</create_target>"
        )

        root = self._run_gmp(
            command
        )

        target_id = root.attrib.get(
            "id"
        )

        if not target_id:
            raise RuntimeError(
                "Greenbone did not return a target ID."
            )

        return target_id

    def _create_task(
        self,
        task_name: str,
        target_id: str,
        config_id: str,
    ) -> str:
        """Create a Greenbone scan task."""

        command = (
            "<create_task>"
            f"<name>{self._xml_escape(task_name)}</name>"
            "<comment>"
            "Zyncle Port Scanner Greenbone scan"
            "</comment>"
            f'<config id="{config_id}"/>'
            f'<target id="{target_id}"/>'
            f'<scanner id="{self.scanner_id}"/>'
            "</create_task>"
        )

        root = self._run_gmp(
            command
        )

        task_id = root.attrib.get(
            "id"
        )

        if not task_id:
            raise RuntimeError(
                "Greenbone did not return a task ID."
            )

        return task_id

    def _start_task(
        self,
        task_id: str,
    ) -> str:
        """Start a Greenbone task and return report ID."""

        command = (
            f'<start_task task_id="{task_id}"/>'
        )

        root = self._run_gmp(
            command
        )

        report_id = root.findtext(
            ".//report_id"
        )

        if not report_id:
            raise RuntimeError(
                "Greenbone did not return a report ID "
                "when starting the task."
            )

        return report_id.strip()

    def _get_task_status(
        self,
        task_id: str,
    ) -> tuple[str, int | None]:
        """Return current task status and progress."""

        command = (
            f'<get_tasks task_id="{task_id}"/>'
        )

        root = self._run_gmp(
            command
        )

        task = root.find(
            ".//task"
        )

        if task is None:
            raise RuntimeError(
                f"Greenbone task {task_id} "
                "was not returned."
            )

        status = (
            task.findtext("./status")
            or ""
        ).strip()

        progress_text = (
            task.findtext("./progress")
            or ""
        ).strip()

        progress: int | None = None

        if progress_text.isdigit():
            progress = int(
                progress_text
            )

        return status, progress

    def _wait_for_task(
        self,
        task_id: str,
    ) -> None:
        """Poll the task until Greenbone finishes it."""

        started = time.monotonic()

        terminal_success = {
            "Done",
        }

        terminal_failure = {
            "Stopped",
            "Interrupted",
            "Delete Requested",
        }

        while True:
            elapsed = (
                time.monotonic()
                - started
            )

            if elapsed > self.timeout_seconds:
                raise TimeoutError(
                    f"Greenbone task {task_id} "
                    f"did not finish within "
                    f"{self.timeout_seconds} seconds."
                )

            status, progress = (
                self._get_task_status(
                    task_id
                )
            )

            if progress is None:
                print(
                    f"[GREENBONE] Task {task_id}: "
                    f"{status}",
                    flush=True,
                )
            else:
                print(
                    f"[GREENBONE] Task {task_id}: "
                    f"{status} ({progress}%)",
                    flush=True,
                )

            if status in terminal_success:
                return

            if status in terminal_failure:
                raise RuntimeError(
                    f"Greenbone task {task_id} "
                    f"ended with status: {status}"
                )

            time.sleep(
                self.poll_seconds
            )

    def _get_report(
        self,
        report_id: str,
    ) -> str:
        """
        Retrieve the complete XML report.

        details=1 includes result details.
        ignore_pagination=1 prevents default pagination
        from hiding findings.
        """

        command = (
            "<get_reports "
            f'report_id="{report_id}" '
            'details="1" '
            'ignore_pagination="1" '
            'filter="rows=-1"/>'
        )

        root = self._run_gmp(
            command
        )

        report = root.find(
            ".//report"
        )

        if report is None:
            raise RuntimeError(
                f"Greenbone report {report_id} "
                "was not returned."
            )

        inner_report = report.find(
            "./report"
        )

        if inner_report is not None:
            return ET.tostring(
                inner_report,
                encoding="unicode",
            )

        return ET.tostring(
            report,
            encoding="unicode",
        )

    # ============================================================
    # XML parsing
    # ============================================================

    @classmethod
    def parse_report(
        cls,
        report_xml: str,
    ) -> list[GreenboneFinding]:
        """
        Convert Greenbone report XML into Zyncle findings.
        """

        root = ET.fromstring(
            report_xml
        )

        findings: list[GreenboneFinding] = []

        for result in root.findall(
            ".//result"
        ):
            finding = cls._parse_result(
                result
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    @classmethod
    def _parse_result(
        cls,
        result: ET.Element,
    ) -> GreenboneFinding | None:

        name = (
            cls._text(
                result,
                "./name",
            )
            or cls._text(
                result,
                "./nvt/name",
            )
            or "Greenbone finding"
        )

        host = (
            cls._text(
                result,
                "./host",
            )
            or ""
        ).strip()

        port = cls._parse_port(
            cls._text(
                result,
                "./port",
            )
        )

        severity_text = cls._text(
            result,
            "./severity",
        )

        cvss_score = cls._parse_float(
            severity_text
        )

        severity = cls._severity_from_cvss(
            cvss_score
        )

        description = (
            cls._text(
                result,
                "./description",
            )
            or cls._text(
                result,
                "./nvt/description",
            )
        )

        solution = (
            cls._text(
                result,
                "./solution",
            )
            or cls._text(
                result,
                "./nvt/solution",
            )
        )

        cvss_metrics = (
            cls._text(
                result,
                "./nvt/cvss_base_vector",
            )
            or cls._extract_cvss_vector(
                result
            )
        )

        cve_ids, cwe_ids = (
            cls._extract_references(
                result
            )
        )

        evidence = (
            cls._text(
                result,
                "./detection",
            )
            or cls._text(
                result,
                "./qod/value",
            )
            or cls._text(
                result,
                "./port",
            )
        )

        return GreenboneFinding(
            host=host,
            port=port,
            name=name.strip(),
            severity=severity,
            cvss_score=cvss_score,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            description=description,
            solution=solution,
            evidence=evidence,
            cvss_metrics=cvss_metrics,
        )

    @staticmethod
    def _extract_references(
        result: ET.Element,
    ) -> tuple[list[str], list[str]]:

        cves: set[str] = set()
        cwes: set[str] = set()

        for ref in result.findall(
            ".//ref"
        ):
            ref_type = (
                ref.attrib.get(
                    "type",
                    "",
                )
                .strip()
                .lower()
            )

            ref_id = (
                ref.attrib.get(
                    "id",
                    "",
                )
                .strip()
            )

            if not ref_id:
                continue

            if ref_type == "cve":
                cves.add(
                    ref_id
                )

            elif ref_type == "cwe":
                cwes.add(
                    ref_id
                )

        for element in result.findall(
            ".//cve"
        ):
            if element.text:
                value = element.text.strip()

                if value:
                    cves.add(
                        value
                    )

        for element in result.findall(
            ".//cwe"
        ):
            if element.text:
                value = element.text.strip()

                if value:
                    cwes.add(
                        value
                    )

        return (
            sorted(cves),
            sorted(cwes),
        )

    @staticmethod
    def _extract_cvss_vector(
        result: ET.Element,
    ) -> str | None:

        for element in result.iter():
            tag = (
                element.tag
                .split("}")[-1]
                .lower()
            )

            if "cvss" not in tag:
                continue

            value = (
                element.text
                or ""
            ).strip()

            if value.startswith(
                "CVSS:"
            ):
                return value

            if value.startswith(
                "AV:"
            ):
                return value

        return None

    @staticmethod
    def _severity_from_cvss(
        score: float | None,
    ) -> str | None:

        if score is None:
            return None

        if score >= 9.0:
            return "Critical"

        if score >= 7.0:
            return "High"

        if score >= 4.0:
            return "Medium"

        if score > 0.0:
            return "Low"

        return "Log"

    # ============================================================
    # Helpers
    # ============================================================

    @staticmethod
    def _normalize_host(
        target: str,
    ) -> str:

        value = target.strip()

        if not value:
            raise ValueError(
                "Greenbone target cannot be empty."
            )

        if "://" not in value:
            value = f"http://{value}"

        parsed = urlparse(
            value
        )

        if not parsed.hostname:
            raise ValueError(
                f"Invalid Greenbone target: {target}"
            )

        return parsed.hostname

    @staticmethod
    def _parse_port(
        value: str | None,
    ) -> int | None:

        if not value:
            return None

        first = (
            value
            .strip()
            .split(
                "/",
                1,
            )[0]
        )

        try:
            return int(first)

        except ValueError:
            return None

    @staticmethod
    def _parse_float(
        value: str | None,
    ) -> float | None:

        if not value:
            return None

        try:
            return float(
                value.strip()
            )

        except ValueError:
            return None

    @staticmethod
    def _text(
        element: ET.Element,
        path: str,
    ) -> str | None:

        value = element.findtext(
            path
        )

        if value is None:
            return None

        value = value.strip()

        return value or None

    @staticmethod
    def _xml_escape(
        value: str,
    ) -> str:

        return (
            value
            .replace(
                "&",
                "&amp;",
            )
            .replace(
                "<",
                "&lt;",
            )
            .replace(
                ">",
                "&gt;",
            )
            .replace(
                '"',
                "&quot;",
            )
            .replace(
                "'",
                "&apos;",
            )
        )

    @staticmethod
    def _build_task_name(
        host: str,
        scan_id: int | str | None,
        profile: str = "lightweight",
    ) -> str:

        suffix = (
            f"scan-{scan_id}"
            if scan_id is not None
            else time.strftime(
                "%Y%m%d-%H%M%S"
            )
        )

        return (
            f"Zyncle Greenbone "
            f"{host} "
            f"{profile} "
            f"{suffix}"
        )