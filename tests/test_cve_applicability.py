from scanner.intelligence.cve_client import _cve_applies_to_version


REQUESTED_CPE = (
    "cpe:2.3:a:postgresql:postgresql:"
    "16.0:*:*:*:*:*:*:*"
)


def make_cve(
    *,
    vulnerable: bool = True,
    criteria: str = REQUESTED_CPE,
    **ranges,
) -> dict:
    cpe_match = {
        "vulnerable": vulnerable,
        "criteria": criteria,
    }

    cpe_match.update(ranges)

    return {
        "configurations": [
            {
                "operator": "OR",
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [cpe_match],
                    }
                ],
            }
        ]
    }


def test_matching_exact_version():
    cve = make_cve()

    assert _cve_applies_to_version(
        cve,
        REQUESTED_CPE,
        "16.0",
    ) is True


def test_non_vulnerable_cpe():
    cve = make_cve(
        vulnerable=False,
    )

    assert _cve_applies_to_version(
        cve,
        REQUESTED_CPE,
        "16.0",
    ) is False


def test_wrong_vendor():
    cve = make_cve(
        criteria=(
            "cpe:2.3:a:mysql:mysql:"
            "16.0:*:*:*:*:*:*:*"
        ),
    )

    assert _cve_applies_to_version(
        cve,
        REQUESTED_CPE,
        "16.0",
    ) is False


def test_wrong_product():
    cve = make_cve(
        criteria=(
            "cpe:2.3:a:postgresql:"
            "postgresql-jdbc:16.0:*:*:*:*:*:*:*"
        ),
    )

    assert _cve_applies_to_version(
        cve,
        REQUESTED_CPE,
        "16.0",
    ) is False


def test_wrong_exact_version():
    cve = make_cve(
        criteria=(
            "cpe:2.3:a:postgresql:"
            "postgresql:15.0:*:*:*:*:*:*:*"
        ),
    )

    assert _cve_applies_to_version(
        cve,
        REQUESTED_CPE,
        "16.0",
    ) is False


def test_version_range_match():
    cve = make_cve(
        criteria=(
            "cpe:2.3:a:postgresql:"
            "postgresql:*:*:*:*:*:*:*:*"
        ),
        versionStartIncluding="15.0",
        versionEndExcluding="17.0",
    )

    assert _cve_applies_to_version(
        cve,
        REQUESTED_CPE,
        "16.0",
    ) is True


def test_version_range_no_match():
    cve = make_cve(
        criteria=(
            "cpe:2.3:a:postgresql:"
            "postgresql:*:*:*:*:*:*:*:*"
        ),
        versionStartIncluding="17.0",
        versionEndExcluding="18.0",
    )

    assert _cve_applies_to_version(
        cve,s
        REQUESTED_CPE,
        "16.0",
    ) is False