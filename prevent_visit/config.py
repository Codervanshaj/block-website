from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "prevent_visit" / "data"
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "settings.json"
DEFAULT_LOG_PATH = REPO_ROOT / "logs" / "blocked-events.jsonl"
DEFAULT_HOSTS_PATH = REPO_ROOT / "build" / "hosts.generated"
DEFAULT_PAC_PATH = REPO_ROOT / "build" / "prevent-visit.pac"
DEFAULT_CERTS_DIR = REPO_ROOT / "config" / "certs"


@dataclass(slots=True)
class SafeSearchTargets:
    google_force_host: str = "forcesafesearch.google.com"
    youtube_restrict_host: str = "restrict.youtube.com"
    bing_strict_host: str = "strict.bing.com"


@dataclass(slots=True)
class AppConfig:
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8877
    search_only_mode: bool = True
    block_page_title: str = "Blocked by Prevent Visit"
    block_page_message: str = (
        "This request matched your blocked adult-content rules and was stopped."
    )
    hosts_output_path: str = str(DEFAULT_HOSTS_PATH)
    pac_output_path: str = str(DEFAULT_PAC_PATH)
    log_path: str = str(DEFAULT_LOG_PATH)
    certs_dir: str = str(DEFAULT_CERTS_DIR)
    blocked_domains_path: str = str(DATA_DIR / "adult_domains.txt")
    blocked_keywords_path: str = str(DATA_DIR / "blocked_keywords.txt")
    allow_domains: list[str] = field(default_factory=lambda: ["ntp.msn.com"])
    intercept_search_hosts: list[str] = field(
        default_factory=lambda: [
            "google.com",
            "google.co.in",
            "www.google.co.in",
            "www.google.com",
            "bing.com",
            "www.bing.com",
            "duckduckgo.com",
            "www.duckduckgo.com",
            "search.yahoo.com",
            "search.brave.com",
            "www.startpage.com",
            "yandex.com",
            "www.yandex.com",
            "www.ecosia.org",
        ]
    )
    safe_search: SafeSearchTargets = field(default_factory=SafeSearchTargets)

    @classmethod
    def load(cls, path: Path | None = None) -> "AppConfig":
        config_path = path or DEFAULT_CONFIG_PATH
        if not config_path.exists():
            config = cls()
            config.save(config_path)
            return config

        payload = json.loads(config_path.read_text(encoding="utf-8"))
        safe_search = SafeSearchTargets(**payload.get("safe_search", {}))
        payload["safe_search"] = safe_search
        return cls(**payload)

    def save(self, path: Path | None = None) -> None:
        config_path = path or DEFAULT_CONFIG_PATH
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(asdict(self), indent=2),
            encoding="utf-8",
        )
