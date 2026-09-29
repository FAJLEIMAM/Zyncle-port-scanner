import sys

sys.path.insert(0, r"E:\Zyncle-Port-Scanner")

from app.core.database import SessionLocal
from app.models.scan import Scan
from app.services.scan_service import run_port_scan


db = SessionLocal()

try:
    scan = Scan(
        target="127.0.0.1",
        status="running",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    print(f"Created scan: {scan.id}")

    run_port_scan(db, scan)

    scan.status = "completed"
    db.commit()

    print(f"Scan completed: {scan.id}")

finally:
    db.close()