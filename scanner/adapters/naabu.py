import json
import subprocess
from dataclasses import dataclass


NAABU_PATH = r"C:\Users\fajle\go\bin\naabu.exe"


@dataclass
class NaabuPort:
    ip: str
    port: int
    protocol: str
    tls: bool


def run_naabu(target: str) -> list[NaabuPort]:
    command = [
        NAABU_PATH,
        "-host",
        target,
        "-json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    ports: list[NaabuPort] = []
    seen: set[tuple[str, int, str]] = set()

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line.startswith("{"):
            continue

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

    return ports