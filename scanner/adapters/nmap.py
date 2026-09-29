import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"


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


def run_nmap_service_detection(
    target: str,
    ports: list[int],
) -> list[NmapService]:
    if not ports:
        return []

    port_spec = ",".join(str(port) for port in ports)

    command = [
        NMAP_PATH,
        "-sV",
        "-p",
        port_spec,
        target,
        "-oX",
        "-",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=120,
    )

    root = ET.fromstring(result.stdout)

    services: list[NmapService] = []

    for host in root.findall("host"):
        address_element = host.find("address")

        ip = target

        if address_element is not None:
            ip = address_element.get("addr") or target

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port_element in ports_element.findall("port"):
            port_number = port_element.get("portid")

            if port_number is None:
                continue

            try:
                port = int(port_number)
            except ValueError:
                continue

            protocol = port_element.get("protocol", "tcp")

            state_element = port_element.find("state")
            state = (
                state_element.get("state", "unknown")
                if state_element is not None
                else "unknown"
            )

            service_element = port_element.find("service")

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

            service_name = service_element.get("name")
            product = service_element.get("product")
            version = service_element.get("version")
            extrainfo = service_element.get("extrainfo")
            confidence_value = service_element.get("conf")

            confidence = None

            if confidence_value is not None:
                try:
                    confidence = int(confidence_value)
                except ValueError:
                    confidence = None

            cpe = None

            for cpe_element in service_element.findall("cpe"):
                if cpe_element.text:
                    cpe = cpe_element.text.strip()
                    break

            banner_parts = []

            if product:
                banner_parts.append(product)

            if version:
                banner_parts.append(version)

            if extrainfo:
                banner_parts.append(extrainfo)

            banner = " ".join(banner_parts) or None

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

    return services