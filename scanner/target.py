from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class NormalizedTarget:
    original: str
    host: str
    web_url: str


def normalize_target(target: str) -> NormalizedTarget:
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty")

    original = target

    if "://" not in target:
        target = f"http://{target}"

    parsed = urlparse(target)

    if not parsed.hostname:
        raise ValueError("Invalid target")

    host = parsed.hostname
    web_url = target.rstrip("/")

    return NormalizedTarget(
        original=original,
        host=host,
        web_url=web_url,
    )