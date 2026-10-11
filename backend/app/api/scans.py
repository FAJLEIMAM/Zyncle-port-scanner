from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, get_db
from app.models.scan import Scan
from scanner.target import normalize_target
from app.services.scan_service import run_port_scan


router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"],
)


class ScanCreate(BaseModel):
    target: str
    profile: str = "common"
    vulnerability_profile: str = "lightweight"


def execute_scan(scan_id: int) -> None:
    db = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if scan is None:
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        run_port_scan(db, scan)

        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

    except Exception as exc:
        db.rollback()

        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if scan is not None:
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()

    finally:
        db.close()


# ============================================================
# CREATE SCAN
# ============================================================

@router.post("")
def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    # --------------------------------------------------------
    # Validate port scan profile
    # --------------------------------------------------------

    profile = scan_data.profile.strip().lower()

    if profile not in {"common", "full"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid profile. Use 'common' or 'full'.",
        )

    # --------------------------------------------------------
    # Validate vulnerability scan profile
    # --------------------------------------------------------

    vulnerability_profile = (
        scan_data.vulnerability_profile
        .strip()
        .lower()
    )

    if vulnerability_profile not in {
        "lightweight",
        "full",
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid vulnerability_profile. "
                "Use 'lightweight' or 'full'."
            ),
        )

    # --------------------------------------------------------
    # Normalize target
    # --------------------------------------------------------

    try:
        normalized = normalize_target(scan_data.target)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    # --------------------------------------------------------
    # Create scan
    # --------------------------------------------------------

    scan = Scan(
        target=normalized.web_url,
        status="pending",
        profile=profile,
        vulnerability_profile=vulnerability_profile,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # --------------------------------------------------------
    # Start background scan
    # --------------------------------------------------------

    background_tasks.add_task(
        execute_scan,
        scan.id,
    )

    return {
        "id": scan.id,
        "target": scan.target,
        "profile": scan.profile,
        "vulnerability_profile": scan.vulnerability_profile,
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }


# ============================================================
# SCAN HISTORY
# GET /api/scans
# ============================================================

@router.get("")
def get_scan_history(
    db: Session = Depends(get_db),
):
    """
    Return the latest scan history.

    The newest scans are returned first.
    Detailed host/port/finding data remains available
    through GET /api/scans/{scan_id}.
    """

    scans = (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .limit(50)
        .all()
    )

    history = []

    for scan in scans:
        host_count = 0
        port_count = 0
        finding_count = 0

        # Count discovered hosts, ports and findings
        # from the existing relationships.
        for host in scan.hosts:
            host_count += 1

            for port in host.ports:
                port_count += 1

                if port.service is not None:
                    finding_count += len(
                        port.service.findings
                    )

        history.append(
            {
                "id": scan.id,
                "target": scan.target,
                "profile": scan.profile,
                "vulnerability_profile": (
                    scan.vulnerability_profile
                ),
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "error_message": scan.error_message,
                "hosts": host_count,
                "open_ports": port_count,
                "services": sum(
                    1
                    for host in scan.hosts
                    for port in host.ports
                    if port.service is not None
                ),
                "findings": finding_count,
            }
        )

    return history


# ============================================================
# GET SINGLE SCAN
# GET /api/scans/{scan_id}
# ============================================================

@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    hosts = []

    for host in scan.hosts:
        ports = []

        for port in host.ports:
            service_data = None

            if port.service is not None:
                service_data = {
                    "id": port.service.id,
                    "service_name": port.service.service_name,
                    "product": port.service.product,
                    "version": port.service.version,
                    "cpe": port.service.cpe,
                    "confidence": port.service.confidence,
                    "banner": port.service.banner,
                }

            findings = []

            if port.service is not None:
                for finding in port.service.findings:
                    findings.append(
                        {
                            "id": finding.id,
                            "title": finding.title,
                            "description": finding.description,
                            "vulnerability_id": (
                                finding.vulnerability_id
                            ),
                            "severity": finding.severity,
                            "cvss_score": finding.cvss_score,
                            "cwe_ids": finding.cwe_ids,
                            "cvss_metrics": (
                                finding.cvss_metrics
                            ),
                            "risk_level": finding.risk_level,
                            "risk_reason": finding.risk_reason,
                            "source": finding.source,
                            "matcher_name": (
                                finding.matcher_name
                            ),
                            "evidence": finding.evidence,
                            "detected_at": finding.detected_at,
                        }
                    )

            ports.append(
                {
                    "id": port.id,
                    "port_number": port.port_number,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": service_data,
                    "findings": findings,
                }
            )

        hosts.append(
            {
                "id": host.id,
                "address": host.address,
                "hostname": host.hostname,
                "status": host.status,
                "ports": ports,
            }
        )

    return {
        "id": scan.id,
        "target": scan.target,
        "profile": scan.profile,
        "vulnerability_profile": (
            scan.vulnerability_profile
        ),
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,
        "hosts": hosts,
    }