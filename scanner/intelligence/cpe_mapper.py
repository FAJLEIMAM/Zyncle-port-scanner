from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizedCPE:
    raw: str
    normalized: str
    part: str | None
    vendor: str | None
    product: str | None
    version: str | None


def normalize_cpe(cpe: str | None) -> NormalizedCPE | None:
    if not cpe:
        return None

    raw = cpe.strip()

    if not raw:
        return None

    # Nmap commonly returns legacy CPE URI format:
    # cpe:/a:vendor:product:version
    if raw.startswith("cpe:/"):
        parts = raw[5:].split(":")

        part = parts[0] if len(parts) > 0 else None
        vendor = parts[1] if len(parts) > 1 else None
        product = parts[2] if len(parts) > 2 else None
        version = parts[3] if len(parts) > 3 else None

        normalized = raw

        return NormalizedCPE(
            raw=raw,
            normalized=normalized,
            part=part or None,
            vendor=vendor or None,
            product=product or None,
            version=version or None,
        )

    # Nmap/NVD may also use CPE 2.3:
    # cpe:2.3:a:vendor:product:version:...
    if raw.startswith("cpe:2.3:"):
        parts = raw.split(":")

        part = parts[2] if len(parts) > 2 else None
        vendor = parts[3] if len(parts) > 3 else None
        product = parts[4] if len(parts) > 4 else None
        version = parts[5] if len(parts) > 5 else None

        return NormalizedCPE(
            raw=raw,
            normalized=raw,
            part=None if part in (None, "*", "-") else part,
            vendor=None if vendor in (None, "*", "-") else vendor,
            product=None if product in (None, "*", "-") else product,
            version=None if version in (None, "*", "-") else version,
        )

    return None


def is_cve_lookup_ready(cpe: NormalizedCPE | None) -> bool:
    if cpe is None:
        return False

    return bool(
        cpe.vendor
        and cpe.product
        and cpe.version
    )