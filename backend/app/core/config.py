from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    database_url: str


    naabu_path: str = ""
    nuclei_path: str = ""
    nmap_path: str = ""


    greenbone_enabled: bool = False
    greenbone_compose_dir: str = ""
    greenbone_compose_file: str = "compose.yaml"
    greenbone_compose_service: str = "gvm-tools"
    greenbone_socket: str = "/run/gvmd/gvmd.sock"

    greenbone_username: str = "admin"
    greenbone_password: str = ""

    greenbone_config_id: str = ""
    greenbone_lightweight_config_id: str = ""
    greenbone_full_config_id: str = ""
    greenbone_scanner_id: str = ""
    greenbone_port_list_id: str = ""

    greenbone_timeout_seconds: int = 7200
    greenbone_poll_seconds: int = 5

    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
