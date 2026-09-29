from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from scanner.intelligence.cve_applicability import cpe_match_applies


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(frozen=True)
class CVERecord:
    cve_id: str
    description: str | None
    cvss_score: float | None
    cvss_metrics: str | None
    cwe_ids: list[str]
    published: str | None
    last_modified: str | None
    source_url: str
    configurations: list[dict]


def _extract_description(cve: dict) -> str | None:
    descriptions = cve.get("descriptions") or []

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value")

    if descriptions:
        return descriptions[0].get("value")

    return None


def _extract_cvss(
    cve: dict,
) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}

    # Prefer newer CVSS versions first.
    for key in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        metric_list = metrics.get(key) or []

        if not metric_list:
            continue

        metric = metric_list[0]
        cvss_data = metric.get("cvssData") or {}

        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")

        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None

        return score, vector

    return None, None


def _extract_cwes(cve: dict) -> list[str]:
    weaknesses = cve.get("weaknesses") or []

    cwe_ids: list[str] = []

    for weakness in weaknesses:
        descriptions = weakness.get("description") or []

        for description in descriptions:
            value = description.get("value")

            if value and value not in cwe_ids:
                cwe_ids.append(value)

    return cwe_ids


def _build_record(cve: dict) -> CVERecord:
    cve_id = cve.get("id", "")

    cvss_score, cvss_metrics = _extract_cvss(cve)

    return CVERecord(
        cve_id=cve_id,
        description=_extract_description(cve),
        cvss_score=cvss_score,
        cvss_metrics=cvss_metrics,
        cwe_ids=_extract_cwes(cve),
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        configurations=cve.get("configurations") or [],
    )


def _split_cpe23(cpe: str) -> list[str] | None:
    """
    Split a CPE 2.3 name into its components.

    Expected format:

    cpe:2.3:part:vendor:product:version:...
    """

    cpe = cpe.strip().lower()

    if not cpe.startswith("cpe:2.3:"):
        return None

    parts = cpe.split(":")

    if len(parts) < 6:
        return None

    return parts


def _cpe_product_matches(
    requested_cpe: str,
    criteria_cpe: str,
) -> bool:
    """
    Check whether the NVD CPE criteria belongs to the
    same part/vendor/product family as the detected CPE.

    Version is handled separately.
    """

    requested_parts = _split_cpe23(requested_cpe)
    criteria_parts = _split_cpe23(criteria_cpe)

    if requested_parts is None:
        return False

    if criteria_parts is None:
        return False

    requested_part = requested_parts[2]
    requested_vendor = requested_parts[3]
    requested_product = requested_parts[4]

    criteria_part = criteria_parts[2]
    criteria_vendor = criteria_parts[3]
    criteria_product = criteria_parts[4]

    if criteria_part != requested_part:
        return False

    if criteria_vendor != requested_vendor:
        return False

    if criteria_product != requested_product:
        return False

    return True


def _criteria_version_matches(
    criteria_cpe: str,
    detected_version: str,
) -> bool:
    """
    Check an exact version contained inside an NVD CPE criteria.

    Wildcard versions are handled by the NVD version-range
    information instead.
    """

    criteria_parts = _split_cpe23(criteria_cpe)

    if criteria_parts is None:
        return False

    criteria_version = criteria_parts[5]

    # Wildcard / unspecified version.
    if criteria_version in ("*", "-"):
        return True

    return criteria_version == detected_version.strip().lower()


def _cve_applies_to_version(
    cve: dict,
    requested_cpe: str,
    detected_version: str,
) -> bool:
    """
    Determine whether a CVE actually applies to the
    requested CPE and detected software version.

    Rules:

    1. CPE match must be marked vulnerable=true.
    2. NVD criteria must belong to the same
       part/vendor/product family.
    3. Exact criteria versions must match.
    4. NVD version boundaries must match.
    """

    configurations = cve.get("configurations") or []

    requested_cpe = requested_cpe.strip().lower()
    detected_version = detected_version.strip().lower()

    for configuration in configurations:

        nodes = configuration.get("nodes") or []

        for node in nodes:

            cpe_matches = node.get("cpeMatch") or []

            for cpe_match in cpe_matches:

                # Ignore explicitly non-vulnerable matches.
                if cpe_match.get("vulnerable") is not True:
                    continue

                criteria = cpe_match.get("criteria")

                if not criteria:
                    continue

                criteria = criteria.strip().lower()

                # Check vendor/product family.
                if not _cpe_product_matches(
                    requested_cpe,
                    criteria,
                ):
                    continue

                # Check exact version when NVD provides one.
                if not _criteria_version_matches(
                    criteria,
                    detected_version,
                ):
                    continue

                # Check NVD version ranges.
                if not cpe_match_applies(
                    detected_version,
                    cpe_match,
                ):
                    continue

                return True

    return False


def _build_request(
    url: str,
    api_key: str | None,
) -> urllib.request.Request:

    headers = {
        "User-Agent": "Zyncle-Port-Scanner/1.0",
        "Accept": "application/json",
    }

    if api_key:
        headers["apiKey"] = api_key

    return urllib.request.Request(
        url,
        headers=headers,
        method="GET",
    )


def _request_nvd(
    url: str,
    *,
    api_key: str | None,
    timeout: int,
) -> dict:

    request = _build_request(
        url,
        api_key,
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:

            payload = response.read().decode("utf-8")

            return json.loads(payload)

    except urllib.error.HTTPError as exc:

        if exc.code == 429:
            raise RuntimeError(
                "NVD API rate limit reached. "
                "Retry later or configure an NVD API key."
            ) from exc

        raise RuntimeError(
            f"NVD API request failed with HTTP {exc.code}"
        ) from exc

    except urllib.error.URLError as exc:

        raise RuntimeError(
            f"NVD API connection failed: {exc.reason}"
        ) from exc

    except json.JSONDecodeError as exc:

        raise RuntimeError(
            "NVD API returned invalid JSON."
        ) from exc


def query_cves_by_cpe(
    cpe_name: str,
    *,
    api_key: str | None = None,
    timeout: int = 20,
    max_results: int = 100,
) -> list[CVERecord]:
    """
    Query NVD CVEs associated with a CPE.

    This function returns the raw CPE-associated CVE candidates.
    It does not perform version applicability filtering.
    """

    if not cpe_name or not cpe_name.strip():
        return []

    params = {
        "cpeName": cpe_name.strip(),
        "resultsPerPage": str(max_results),
    }

    url = (
        f"{NVD_CVE_API}?"
        f"{urllib.parse.urlencode(params)}"
    )

    payload = _request_nvd(
        url,
        api_key=api_key,
        timeout=timeout,
    )

    vulnerabilities = payload.get("vulnerabilities") or []

    records: list[CVERecord] = []

    for item in vulnerabilities:

        cve = item.get("cve")

        if not isinstance(cve, dict):
            continue

        records.append(
            _build_record(cve)
        )

    return records


def query_cves_by_cpe_and_version(
    cpe_name: str,
    detected_version: str,
    *,
    api_key: str | None = None,
    timeout: int = 20,
    max_results: int = 100,
) -> list[CVERecord]:
    """
    Query NVD CVEs by CPE and detected software version.

    Only CVEs whose NVD configuration matches the
    requested vendor/product and detected version
    are returned.
    """

    if not cpe_name or not cpe_name.strip():
        return []

    if not detected_version or not detected_version.strip():
        return []

    params = {
        "cpeName": cpe_name.strip(),
        "resultsPerPage": str(max_results),
    }

    url = (
        f"{NVD_CVE_API}?"
        f"{urllib.parse.urlencode(params)}"
    )

    payload = _request_nvd(
        url,
        api_key=api_key,
        timeout=timeout,
    )

    vulnerabilities = payload.get("vulnerabilities") or []

    records: list[CVERecord] = []

    for item in vulnerabilities:

        cve = item.get("cve")

        if not isinstance(cve, dict):
            continue

        if not _cve_applies_to_version(
            cve,
            cpe_name,
            detected_version,
        ):
            continue

        records.append(
            _build_record(cve)
        )

    return records


def get_nvd_api_key() -> str | None:
    """
    Read the optional NVD API key from the environment.

    Never hard-code an API key in source code.
    """

    value = os.getenv("NVD_API_KEY")

    if value:
        return value.strip()

    return None