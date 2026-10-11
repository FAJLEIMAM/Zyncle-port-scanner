from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
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


NMAP_PATH = resolve_executable("NMAP_PATH", "nmap")

NMAP_TIMEOUT_SECONDS = 120


@dataclass
class NmapService:
    ip: str
    port: int
    protocol: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    cpe: str | None
    confidence: int | None
    banner: str | None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip()

    return value or None


def _extract_cpe(
    service_element: ET.Element,
) -> str | None:

    for cpe_element in service_element.findall("cpe"):
        cpe = _clean(cpe_element.text)

        if cpe:
            return cpe

    return None


def _extract_script_output(
    port_element: ET.Element,
) -> list[str]:

    outputs: list[str] = []

    for script in port_element.findall("./script"):
        script_id = (
            script.get("id", "").strip()
        )

        output = _clean(
            script.get("output")
        )

        if not output:
            continue

        outputs.append(
            f"{script_id}: {output}"
        )

    return outputs


def _build_banner(
    service_element: ET.Element,
    port_element: ET.Element,
) -> str | None:

    product = _clean(
        service_element.get("product")
    )

    version = _clean(
        service_element.get("version")
    )

    extrainfo = _clean(
        service_element.get("extrainfo")
    )

    parts: list[str] = []

    if product:
        parts.append(product)

    if version:
        parts.append(version)

    if extrainfo:
        parts.append(
            f"({extrainfo})"
        )

    script_outputs = _extract_script_output(
        port_element
    )

    if script_outputs:
        parts.extend(script_outputs)

    if parts:
        return " | ".join(parts)

    return None


def _parse_confidence(
    service_element: ET.Element,
) -> int | None:

    value = _clean(
        service_element.get("conf")
    )

    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def _is_tls_port(port: int) -> bool:
    return port in {
        443,
        465,
        636,
        853,
        989,
        990,
        992,
        993,
        995,
        8443,
        9443,
    }


def run_nmap_service_detection(
    target: str,
    ports: list[int],
) -> list[NmapService]:

    if not ports:
        return []

    # ------------------------------------------------------
    # Clean and deduplicate ports
    # ------------------------------------------------------

    unique_ports: set[int] = set()

    for port in ports:
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            continue

        if 1 <= port_number <= 65535:
            unique_ports.add(port_number)

    if not unique_ports:
        return []

    sorted_ports = sorted(unique_ports)

    port_spec = ",".join(
        str(port)
        for port in sorted_ports
    )

    # ------------------------------------------------------
    # Base Nmap command
    #
    # Naabu already discovered the ports, therefore:
    # -Pn avoids another host-discovery phase
    # -sV performs service/version detection
    # -T4 keeps normal scan speed
    # intensity 7 is the normal/default level
    # ------------------------------------------------------

    command = [
        NMAP_PATH,
        "-sV",
        "--version-light",
        "-Pn",
        "-T4",
        "-p",
        port_spec,
        "-oX",
        "-",
    ]


    # ------------------------------------------------------
    # HTTPS/TLS metadata
    #
    # Only enable ssl-cert when the discovered port list
    # contains a likely TLS port.
    # ------------------------------------------------------


    command.append(target)

    print(
        "[NMAP] Command:",
        " ".join(command),
        flush=True,
    )

    # ------------------------------------------------------
    # Execute Nmap
    # ------------------------------------------------------

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=NMAP_TIMEOUT_SECONDS,
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Nmap service detection timed out "
            f"after {NMAP_TIMEOUT_SECONDS} seconds "
            f"for {target}"
        ) from exc

    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Nmap executable was not found at "
            f"{NMAP_PATH}"
        ) from exc

    if result.returncode != 0:
        stderr = (
            result.stderr.strip()
            if result.stderr
            else "No error output"
        )

        raise RuntimeError(
            f"Nmap service detection failed "
            f"(exit code {result.returncode}): "
            f"{stderr}"
        )

    if not result.stdout.strip():
        raise RuntimeError(
            "Nmap returned empty XML output."
        )

    # ------------------------------------------------------
    # Parse XML
    # ------------------------------------------------------

    try:
        root = ET.fromstring(
            result.stdout
        )
    except ET.ParseError as exc:
        raise RuntimeError(
            "Unable to parse Nmap XML output."
        ) from exc

    services: list[NmapService] = []

    # ------------------------------------------------------
    # Hosts
    # ------------------------------------------------------

    for host in root.findall("host"):

        ip = target

        for address_element in host.findall(
            "address"
        ):

            address = _clean(
                address_element.get("addr")
            )

            address_type = (
                address_element.get(
                    "addrtype"
                )
            )

            if (
                address
                and address_type in {
                    "ipv4",
                    "ipv6",
                }
            ):
                ip = address
                break

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        # --------------------------------------------------
        # Ports
        # --------------------------------------------------

        for port_element in ports_element.findall(
            "port"
        ):

            port_number = port_element.get(
                "portid"
            )

            if port_number is None:
                continue

            try:
                port = int(port_number)
            except ValueError:
                continue

            protocol = (
                port_element.get(
                    "protocol",
                    "tcp",
                )
                or "tcp"
            )

            # --------------------------------------------------
            # State
            # --------------------------------------------------

            state_element = port_element.find(
                "state"
            )

            state = "unknown"

            if state_element is not None:
                state = (
                    state_element.get(
                        "state",
                        "unknown",
                    )
                    or "unknown"
                )

            # --------------------------------------------------
            # Service
            # --------------------------------------------------

            service_element = port_element.find(
                "service"
            )

            if service_element is None:

                services.append(
                    NmapService(
                        ip=ip,
                        port=port,
                        protocol=protocol,
                        state=state,
                        service_name=None,
                        product=None,
                        version=None,
                        cpe=None,
                        confidence=None,
                        banner=None,
                    )
                )

                continue

            service_name = _clean(
                service_element.get(
                    "name"
                )
            )

            product = _clean(
                service_element.get(
                    "product"
                )
            )

            version = _clean(
                service_element.get(
                    "version"
                )
            )

            cpe = _extract_cpe(
                service_element
            )

            confidence = _parse_confidence(
                service_element
            )

            banner = _build_banner(
                service_element,
                port_element,
            )

            services.append(
                NmapService(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    state=state,
                    service_name=service_name,
                    product=product,
                    version=version,
                    cpe=cpe,
                    confidence=confidence,
                    banner=banner,
                )
            )

            print(
                f"[NMAP] {ip}:{port} "
                f"service={service_name or 'unknown'} "
                f"product={product or 'unknown'} "
                f"version={version or 'unknown'} "
                f"cpe={cpe or 'none'} "
                f"confidence={confidence}",
                flush=True,
            )

    print(
        f"[NMAP] Parsed {len(services)} "
        f"service result(s)",
        flush=True,
    )

    return services