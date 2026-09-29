from __future__ import annotations

import socket
import time

from sqlalchemy.orm import Session

from app.models.host import Host
from app.models.port import Port
from app.models.scan import Scan
from app.models.service import Service
from app.models.finding import Finding

from scanner.target import normalize_target
from scanner.adapters.naabu import run_naabu
from scanner.adapters.nmap import run_nmap_service_detection
from scanner.adapters.nuclei import run_nuclei
from scanner.adapters.greenbone.client import GreenboneClient
from scanner.risk import classify_risk

from scanner.intelligence.cpe_mapper import (
    normalize_cpe,
    is_cve_lookup_ready,
)

from scanner.intelligence.cve_client import (
    query_cves_by_cpe_and_version,
    get_nvd_api_key,
)


def _legacy_cpe_to_cpe23(
    cpe: str,
    detected_version: str,
) -> str | None:
    """
    Convert a simple Nmap legacy CPE URI into a CPE 2.3
    name using the detected service version.

    Example:
        cpe:/a:postgresql:postgresql
        + version 16.0

        ->
        cpe:2.3:a:postgresql:postgresql:16.0:*:*:*:*:*:*:*
    """

    if not cpe:
        return None

    raw = cpe.strip()

    if raw.startswith("cpe:2.3:"):
        return raw

    if not raw.startswith("cpe:/"):
        return None

    parts = raw[5:].split(":")

    if len(parts) < 3:
        return None

    part = parts[0]
    vendor = parts[1]
    product = parts[2]

    if not part or not vendor or not product:
        return None

    if not detected_version:
        return None

    version = detected_version.strip()

    if not version:
        return None

    return (
        f"cpe:2.3:{part}:"
        f"{vendor}:"
        f"{product}:"
        f"{version}:"
        "*:*:*:*:*:*:*"
    )


def _severity_from_cvss(
    cvss_score: float | None,
) -> str:
    """
    Convert CVSS base score to a severity label.

    CVSS:
        9.0 - 10.0  Critical
        7.0 - 8.9   High
        4.0 - 6.9   Medium
        0.1 - 3.9   Low
        0.0         Informational
    """

    if cvss_score is None:
        return "unknown"

    if cvss_score >= 9.0:
        return "critical"

    if cvss_score >= 7.0:
        return "high"

    if cvss_score >= 4.0:
        return "medium"

    if cvss_score > 0.0:
        return "low"

    return "informational"


def _add_nvd_findings(
    db: Session,
    services: list[Service],
) -> tuple[int, int, int]:
    """
    Correlate Nmap service/version/CPE information with NVD.

    Returns:
        (lookup_count, skipped_count, finding_count)
    """

    nvd_start = time.perf_counter()

    api_key = get_nvd_api_key()

    lookup_count = 0
    skipped_count = 0
    stored_count = 0

    # Prevent duplicate NVD API requests for the same
    # CPE + version combination.
    queried: dict[
        tuple[str, str],
        list,
    ] = {}

    for service in services:

        # ---------------------------------------------------------
        # CVE lookup requires a CPE.
        # ---------------------------------------------------------
        if not service.cpe:
            skipped_count += 1
            continue

        # ---------------------------------------------------------
        # CVE lookup requires a detected version.
        # ---------------------------------------------------------
        if not service.version:
            skipped_count += 1
            continue

        normalized = normalize_cpe(service.cpe)

        if normalized is None:
            skipped_count += 1
            continue

        if not is_cve_lookup_ready(normalized):
            skipped_count += 1
            continue

        # ---------------------------------------------------------
        # NVD query currently uses CPE 2.3.
        # ---------------------------------------------------------
        cpe23 = _legacy_cpe_to_cpe23(
            service.cpe,
            service.version,
        )

        if not cpe23:
            skipped_count += 1
            continue

        lookup_key = (
            cpe23.lower(),
            service.version.strip().lower(),
        )

        # ---------------------------------------------------------
        # Reuse previous query for identical services.
        # ---------------------------------------------------------
        if lookup_key in queried:
            cve_records = queried[lookup_key]

        else:
            print(
                f"[NVD] Looking up "
                f"CPE={cpe23} "
                f"version={service.version}",
                flush=True,
            )

            try:
                cve_records = query_cves_by_cpe_and_version(
                    cpe23,
                    service.version,
                    api_key=api_key,
                    timeout=20,
                    max_results=100,
                )

            except Exception as exc:
                print(
                    f"[NVD] Lookup failed for "
                    f"{cpe23}: {exc}",
                    flush=True,
                )

                queried[lookup_key] = []
                continue

            queried[lookup_key] = cve_records
            lookup_count += 1

        # ---------------------------------------------------------
        # Convert applicable CVEs into backend findings.
        # ---------------------------------------------------------
        for cve in cve_records:

            severity = _severity_from_cvss(
                cve.cvss_score
            )

            risk_result = classify_risk(
                severity=severity,
                cvss_score=cve.cvss_score,
                confidence=service.confidence,
            )

            # -----------------------------------------------------
            # Avoid duplicate CVE findings for the same service.
            # -----------------------------------------------------
            existing = (
                db.query(Finding)
                .filter(
                    Finding.service_id == service.id,
                    Finding.vulnerability_id == cve.cve_id,
                    Finding.source == "nvd",
                )
                .first()
            )

            if existing is not None:
                continue

            finding = Finding(
                service_id=service.id,

                title=cve.cve_id,

                description=(
                    cve.description
                    or (
                        f"NVD vulnerability associated with "
                        f"{service.product or service.service_name or 'service'} "
                        f"version {service.version}."
                    )
                ),

                vulnerability_id=cve.cve_id,

                severity=severity,

                cvss_score=cve.cvss_score,

                cwe_ids=(
                    ",".join(cve.cwe_ids)
                    if cve.cwe_ids
                    else None
                ),

                cvss_metrics=cve.cvss_metrics,

                risk_level=risk_result.level,

                risk_reason=(
                    f"NVD CVE applicability matched detected "
                    f"service version {service.version}. "
                    f"{risk_result.reason}"
                ),

                source="nvd",

                evidence=cve.source_url,
            )

            db.add(finding)
            stored_count += 1

    nvd_duration = time.perf_counter() - nvd_start

    print(
        f"[PERF] NVD CVE correlation: "
        f"{nvd_duration:.3f}s "
        f"(lookups={lookup_count}, "
        f"skipped={skipped_count}, "
        f"findings={stored_count})",
        flush=True,
    )

    return (
        lookup_count,
        skipped_count,
        stored_count,
    )


def run_port_scan(
    db: Session,
    scan: Scan,
) -> None:

    # =========================================================
    # TOTAL SCAN TIMER
    # =========================================================
    total_start = time.perf_counter()

    print(
        f"[SCAN] Starting scan #{scan.id} "
        f"target={scan.target}",
        flush=True,
    )

    # =========================================================
    # Target normalization
    # =========================================================
    normalization_start = time.perf_counter()

    target = normalize_target(scan.target)

    print(
        f"[PERF] Target normalization: "
        f"{time.perf_counter() - normalization_start:.3f}s",
        flush=True,
    )

    # =========================================================
    # Phase 1: Port discovery with Naabu
    # =========================================================
    naabu_start = time.perf_counter()

    print(
        f"[NAABU] Starting for {target.host}",
        flush=True,
    )

    results = run_naabu(target.host)

    naabu_duration = time.perf_counter() - naabu_start

    print(
        f"[PERF] Naabu: {naabu_duration:.3f}s "
        f"({len(results)} results)",
        flush=True,
    )

    # =========================================================
    # Create hosts and ports
    # =========================================================
    db_host_port_start = time.perf_counter()

    hosts: dict[str, Host] = {}

    for result in results:

        if result.ip not in hosts:

            host = Host(
                scan_id=scan.id,
                address=result.ip,
                status="up",
            )

            db.add(host)
            db.flush()

            hosts[result.ip] = host

        host = hosts[result.ip]

        port = Port(
            host_id=host.id,
            port_number=result.port,
            protocol=result.protocol,
            state="open",
        )

        db.add(port)

    db.flush()

    print(
        f"[PERF] Host/port DB preparation: "
        f"{time.perf_counter() - db_host_port_start:.3f}s",
        flush=True,
    )

    print(
        f"[SCAN] Discovered {len(hosts)} host(s)",
        flush=True,
    )

    # =========================================================
    # Phase 2: Service and version detection with Nmap
    # =========================================================
    nmap_start = time.perf_counter()

    ports_by_host: dict[str, list[int]] = {}

    for result in results:

        ports_by_host.setdefault(
            result.ip,
            [],
        ).append(result.port)

    total_nmap_results = 0

    # Keep references for NVD correlation.
    detected_services: list[Service] = []

    for ip, port_numbers in ports_by_host.items():

        print(
            f"[NMAP] Starting {ip} "
            f"ports={port_numbers}",
            flush=True,
        )

        nmap_host_start = time.perf_counter()

        nmap_results = run_nmap_service_detection(
            ip,
            port_numbers,
        )

        nmap_host_duration = (
            time.perf_counter()
            - nmap_host_start
        )

        total_nmap_results += len(nmap_results)

        print(
            f"[PERF] Nmap {ip}: "
            f"{nmap_host_duration:.3f}s "
            f"({len(nmap_results)} services)",
            flush=True,
        )

        host = hosts[ip]

        for nmap_result in nmap_results:

            port = next(
                (
                    port
                    for port in host.ports
                    if port.port_number == nmap_result.port
                    and port.protocol == nmap_result.protocol
                ),
                None,
            )

            if port is None:
                continue

            service = Service(
                port_id=port.id,
                service_name=nmap_result.service_name,
                product=nmap_result.product,
                version=nmap_result.version,
                cpe=nmap_result.cpe,
                confidence=nmap_result.confidence,
                banner=nmap_result.banner,
            )

            db.add(service)

            detected_services.append(service)

    db.flush()

    nmap_duration = time.perf_counter() - nmap_start

    print(
        f"[PERF] Nmap TOTAL: "
        f"{nmap_duration:.3f}s "
        f"({total_nmap_results} services)",
        flush=True,
    )

    # =========================================================
    # Phase 3: NVD CVE correlation
    # =========================================================
    #
    # Only services with:
    #
    #     CPE + version
    #
    # are sent to NVD.
    #
    # Services without a reliable version are skipped rather
    # than receiving blind CVE associations.
    # =========================================================

    _add_nvd_findings(
        db,
        detected_services,
    )

    # =========================================================
    # Resolve target hostname to IPv4 addresses
    # =========================================================
    dns_start = time.perf_counter()

    resolved_target_ips: set[str] = set()

    try:

        address_info = socket.getaddrinfo(
            target.host,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        for item in address_info:

            ip_address = item[4][0]

            if ip_address:
                resolved_target_ips.add(
                    ip_address.lower()
                )

    except socket.gaierror:
        pass

    dns_duration = time.perf_counter() - dns_start

    print(
        f"[PERF] DNS resolution: "
        f"{dns_duration:.3f}s "
        f"({len(resolved_target_ips)} IPv4 addresses)",
        flush=True,
    )

    # =========================================================
    # Target hostname aliases that can identify the same target
    # =========================================================
    target_hostnames = {
        target.host.lower(),
    }

    target_addresses = {
        address.lower()
        for address in resolved_target_ips
    }

    # =========================================================
    # Phase 4: Nuclei vulnerability / CVE detection
    # =========================================================
    nuclei_start = time.perf_counter()

    print(
        f"[NUCLEI] Starting for {target.web_url}",
        flush=True,
    )

    nuclei_findings = run_nuclei(
        target.web_url,
        tags="vuln,cve",
        severity="low,medium,high,critical",
    )

    nuclei_duration = time.perf_counter() - nuclei_start

    print(
        f"[PERF] Nuclei: "
        f"{nuclei_duration:.3f}s "
        f"({len(nuclei_findings)} findings)",
        flush=True,
    )

    # =========================================================
    # Phase 5: Store Nuclei findings
    # =========================================================
    findings_start = time.perf_counter()

    stored_findings = 0
    skipped_no_port = 0
    skipped_no_service = 0

    for nuclei_finding in nuclei_findings:

        if nuclei_finding.port is None:
            skipped_no_port += 1
            continue

        matching_service = None

        # -----------------------------------------------------
        # Normalize Nuclei host value
        # -----------------------------------------------------
        finding_host = None

        if nuclei_finding.host:

            finding_host = (
                nuclei_finding.host
                .strip()
                .lower()
            )

        # -----------------------------------------------------
        # Match Nuclei host to database host
        # -----------------------------------------------------
        for host in hosts.values():

            host_address = (
                host.address
                .strip()
                .lower()
            )

            if finding_host:

                host_matches = (
                    finding_host == host_address
                    or finding_host in target_hostnames
                    or finding_host in target_addresses
                )

                if not host_matches:
                    continue

            # -------------------------------------------------
            # Match Nuclei port to discovered port
            # -------------------------------------------------
            for port in host.ports:

                if port.port_number != nuclei_finding.port:
                    continue

                if port.service is None:
                    continue

                matching_service = port.service
                break

            if matching_service is not None:
                break

        # -----------------------------------------------------
        # No matching service
        # -----------------------------------------------------
        if matching_service is None:
            skipped_no_service += 1
            continue

        # =====================================================
        # CVSS
        # =====================================================
        #
        # Do not invent CVSS.
        #
        # Nuclei adapter supplies CVSS only when actually
        # present in its metadata.
        # =====================================================
        cvss_score = nuclei_finding.cvss_score

        # =====================================================
        # Risk classification
        # =====================================================
        risk_result = classify_risk(
            severity=nuclei_finding.severity,
            cvss_score=cvss_score,
            confidence=matching_service.confidence,
        )

        # =====================================================
        # Create finding record
        # =====================================================
        finding = Finding(
            service_id=matching_service.id,

            title=nuclei_finding.name,

            description=(
                f"Nuclei template: "
                f"{nuclei_finding.template_id}"
            ),

            vulnerability_id=nuclei_finding.cve_id,

            severity=nuclei_finding.severity,

            cvss_score=cvss_score,

            cvss_metrics=nuclei_finding.cvss_metrics,

            cwe_ids=(
                ",".join(nuclei_finding.cwe_ids)
                if nuclei_finding.cwe_ids
                else None
            ),

            risk_level=risk_result.level,

            risk_reason=risk_result.reason,

            source="nuclei",

            matcher_name=nuclei_finding.matcher_name,

            evidence=nuclei_finding.matched_at,
        )

        db.add(finding)

        stored_findings += 1

    findings_duration = (
        time.perf_counter()
        - findings_start
    )

    print(
        f"[PERF] Finding processing: "
        f"{findings_duration:.3f}s "
        f"(stored={stored_findings}, "
        f"no_port={skipped_no_port}, "
        f"no_service={skipped_no_service})",
        flush=True,
    )

        # =========================================================
    # Phase 6: Optional Greenbone/OpenVAS correlation
    # =========================================================
    greenbone = GreenboneClient()

    if greenbone.is_available():
        greenbone_start = time.perf_counter()

        print(
            f"[GREENBONE] Starting for {target.web_url}",
            flush=True,
        )

        try:
            greenbone_findings = greenbone.scan(target.web_url)

            print(
                f"[GREENBONE] Findings received: "
                f"{len(greenbone_findings)}",
                flush=True,
            )

            # Live Greenbone result storage will be connected
            # here when a GMP/OSP service is configured.
            for greenbone_finding in greenbone_findings:
                print(
                    f"[GREENBONE] "
                    f"{greenbone_finding.name} "
                    f"host={greenbone_finding.host} "
                    f"port={greenbone_finding.port}",
                    flush=True,
                )

        except Exception as exc:
            print(
                f"[GREENBONE] Integration error: {exc}",
                flush=True,
            )

        greenbone_duration = (
            time.perf_counter() - greenbone_start
        )

        print(
            f"[PERF] Greenbone: "
            f"{greenbone_duration:.3f}s",
            flush=True,
        )
    else:
        print(
            "[GREENBONE] Disabled "
            "(no live Greenbone/OpenVAS service configured)",
            flush=True,
        )


    # =========================================================
    # Final persistence
    # =========================================================
    db_start = time.perf_counter()

    db.commit()

    db_duration = time.perf_counter() - db_start

    print(
        f"[PERF] DB commit: "
        f"{db_duration:.3f}s",
        flush=True,
    )

    # =========================================================
    # TOTAL
    # =========================================================
    total_duration = (
        time.perf_counter()
        - total_start
    )

    print(
        f"[PERF] TOTAL SCAN TIME: "
        f"{total_duration:.3f}s",
        flush=True,
    )

    print(
        f"[SCAN] Completed scan #{scan.id}",
        flush=True,
    )