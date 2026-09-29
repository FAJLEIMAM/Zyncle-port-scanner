from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VersionRange:
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None


def _version_parts(version: str) -> tuple:
    """
    Convert a simple software version into comparable parts.

    Examples:
        16.0      -> (16, 0)
        16.2.1    -> (16, 2, 1)
        3.11.1    -> (3, 11, 1)
    """
    parts = []

    for part in version.split("."):
        number = ""

        for char in part:
            if char.isdigit():
                number += char
            else:
                break

        if number:
            parts.append(int(number))
        else:
            parts.append(part.lower())

    return tuple(parts)


def compare_versions(version_a: str, version_b: str) -> int:
    """
    Compare two simple numeric software versions.

    Returns:
        -1 if a < b
         0 if a == b
         1 if a > b
    """
    a = _version_parts(version_a)
    b = _version_parts(version_b)

    max_len = max(len(a), len(b))

    a = a + (0,) * (max_len - len(a))
    b = b + (0,) * (max_len - len(b))

    if a < b:
        return -1

    if a > b:
        return 1

    return 0


def version_matches_range(
    version: str,
    version_range: VersionRange,
) -> bool:
    """
    Determine whether a detected software version falls
    inside an NVD version range.
    """

    if version_range.start_including:
        if compare_versions(version, version_range.start_including) < 0:
            return False

    if version_range.start_excluding:
        if compare_versions(version, version_range.start_excluding) <= 0:
            return False

    if version_range.end_including:
        if compare_versions(version, version_range.end_including) > 0:
            return False

    if version_range.end_excluding:
        if compare_versions(version, version_range.end_excluding) >= 0:
            return False

    return True


def extract_version_range(cpe_match: dict) -> VersionRange:
    """
    Extract an NVD version range from a cpeMatch object.
    """

    return VersionRange(
        start_including=cpe_match.get("versionStartIncluding"),
        start_excluding=cpe_match.get("versionStartExcluding"),
        end_including=cpe_match.get("versionEndIncluding"),
        end_excluding=cpe_match.get("versionEndExcluding"),
    )


def cpe_match_applies(
    detected_version: str,
    cpe_match: dict,
) -> bool:
    """
    Check whether a detected version satisfies the
    version constraints of an NVD cpeMatch entry.

    If no version boundaries are supplied, the CPE match
    itself is treated as applicable.
    """

    version_range = extract_version_range(cpe_match)

    has_range = any(
        (
            version_range.start_including,
            version_range.start_excluding,
            version_range.end_including,
            version_range.end_excluding,
        )
    )

    if not has_range:
        return True

    return version_matches_range(
        detected_version,
        version_range,
    )