import json
import subprocess
from dataclasses import dataclass

import os
import shutil
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


NAABU_PATH = resolve_executable("NAABU_PATH", "naabu")


@dataclass
class NaabuPort:
    ip: str
    port: int
    protocol: str
    tls: bool


NAABU_PROFILES = {
    "common": "1-1000",
    "full": "1-65535",
}


def run_naabu(
    target: str,
    profile: str = "common",
) -> list[NaabuPort]:

    profile = profile.lower().strip()

    if profile not in NAABU_PROFILES:
        raise ValueError(
            f"Unsupported Naabu profile: {profile}. "
            f"Available profiles: {', '.join(NAABU_PROFILES)}"
        )

    ports_range = NAABU_PROFILES[profile]

    print(
        f"[NAABU] Profile={profile} ports={ports_range}",
        flush=True,
    )

    command = [
        NAABU_PATH,
        "-host",
        target,
        "-p",
        ports_range,

        # Performance tuning
        "-c",
        "100",
        "-rate",
        "3000",
        "-timeout",
        "1000",
        "-retries",
        "1",

        # Output
        "-json",
        "-silent",
        "-duc",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )

    ports: list[NaabuPort] = []
    seen: set[tuple[str, int, str]] = set()

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line.startswith("{"):
            continue

        try:
            data = json.loads(line)

            ip = data["ip"]
            port = int(data["port"])
            protocol = data.get("protocol", "tcp")
            tls = bool(data.get("tls", False))

            key = (ip, port, protocol)

            if key in seen:
                continue

            seen.add(key)

            ports.append(
                NaabuPort(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    tls=tls,
                )
            )

        except (json.JSONDecodeError, KeyError, ValueError):
            continue

    return ports