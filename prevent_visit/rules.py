from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

from .config import AppConfig


SEARCH_QUERY_KEYS = {
    "q",
    "p",
    "query",
    "search_query",
    "search",
    "text",
    "wd",
    "k",
    "keyword",
    "keywords",
    "s",
    "qs",
    "ie",
    "hl",
    "qpar",
    "encquery",
    "aqs",
    "filter",
    "um",
    "uddg",
}


def _read_list(path: str) -> list[str]:
    items: list[str] = []
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith("#"):
            continue
        items.append(line)
    return items


def normalize_host(host: str) -> str:
    value = host.strip().lower()
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.lstrip(".")


def normalize_text(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _has_obfuscation(text: str) -> bool:
    return bool(re.search(r"[*_.\-+!?/@#$%&^=~\\|]", text)) or any(char.isdigit() for char in text)


def _derive_domain_search_terms(domain: str) -> set[str]:
    host = normalize_host(domain)
    if not host:
        return set()

    labels = [normalize_text(part) for part in host.split(".") if part and part != "www"]
    terms = {normalize_text(host)}
    if labels:
        terms.add(labels[0])

    return {
        term
        for term in terms
        if len(term) >= 4 and any(char.isalpha() for char in term)
    }


@dataclass(slots=True)
class Decision:
    blocked: bool
    reason: str
    matched_value: str | None = None


class RuleSet:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.blocked_domains = {normalize_host(item) for item in _read_list(config.blocked_domains_path)}
        self.blocked_keywords = tuple(sorted(set(_read_list(config.blocked_keywords_path)), key=len, reverse=True))
        self.blocked_search_terms = tuple(
            sorted(
                {
                    *{normalize_text(keyword) for keyword in self.blocked_keywords},
                    *{
                        term
                        for domain in self.blocked_domains
                        for term in _derive_domain_search_terms(domain)
                    },
                },
                key=len,
                reverse=True,
            )
        )
        self.allow_domains = {normalize_host(item) for item in config.allow_domains}
        self.search_hosts = {normalize_host(item) for item in config.intercept_search_hosts}

    def reload(self) -> None:
        self.__init__(self.config)

    def is_allowed_host(self, host: str) -> bool:
        value = normalize_host(host)
        return any(
            value == allowed or value.endswith(f".{allowed}")
            for allowed in self.allow_domains
        )

    def is_search_host(self, host: str) -> bool:
        value = normalize_host(host)
        if not value:
            return False
        # Direct match
        if value in self.search_hosts:
            return True
        # Check if host is a subdomain of any search host
        for search_host in self.search_hosts:
            if value.endswith(f".{search_host}"):
                return True
        return False

    def match_host(self, host: str) -> Decision:
        value = normalize_host(host)
        if not value:
            return Decision(False, "no-host")
        if self.is_allowed_host(value):
            return Decision(False, "allowlisted")
        if self.config.search_only_mode:
            return Decision(False, "search-only-host-allowed")
        for domain in self.blocked_domains:
            if value == domain or value.endswith(f".{domain}"):
                return Decision(True, "blocked-domain", domain)
        return Decision(False, "host-allowed")

    def match_text(self, text: str) -> Decision:
        lowered = text.lower()
        normalized = normalize_text(text)
        for keyword in self.blocked_keywords:
            keyword_normalized = normalize_text(keyword)
            if keyword in lowered or (keyword_normalized and keyword_normalized in normalized):
                return Decision(True, "blocked-keyword", keyword)
        return Decision(False, "text-allowed")

    def match_search_text(self, text: str) -> Decision:
        lowered = text.lower()
        normalized = normalize_text(text)

        for keyword in self.blocked_keywords:
            keyword_normalized = normalize_text(keyword)
            if keyword in lowered or (keyword_normalized and keyword_normalized in normalized):
                return Decision(True, "blocked-search-query", keyword)

            if keyword_normalized and _has_obfuscation(text):
                if len(keyword_normalized) >= 2 and len(normalized) >= 2:
                    if keyword_normalized.startswith(normalized) or normalized.startswith(keyword_normalized):
                        return Decision(True, "blocked-search-query", keyword)

        for term in self.blocked_search_terms:
            if term and term in normalized:
                return Decision(True, "blocked-search-query", term)

            if term and _has_obfuscation(text) and len(term) >= 2 and len(normalized) >= 2:
                if term.startswith(normalized) or normalized.startswith(term):
                    return Decision(True, "blocked-search-query", term)

        return Decision(False, "search-text-allowed")

    def match_url(
        self,
        raw_url: str,
        host_hint: str = "",
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Decision:
        parsed = urlsplit(raw_url)
        host = parsed.hostname or host_hint
        host_decision = self.match_host(host)
        if host_decision.blocked:
            return host_decision
        if host_decision.reason == "allowlisted":
            return host_decision
        if not self.is_search_host(host):
            return Decision(False, "url-allowed")

        query = parse_qs(parsed.query, keep_blank_values=True)
        for key in SEARCH_QUERY_KEYS:
            for value in query.get(key, []):
                decision = self.match_search_text(value)
                if decision.blocked:
                    return decision

        if body is not None:
            content_type = (headers or {}).get("content-type", "").lower()
            if "application/x-www-form-urlencoded" in content_type:
                try:
                    body_text = body.decode("utf-8", errors="ignore")
                except Exception:
                    body_text = ""
                form_query = parse_qs(body_text, keep_blank_values=True)
                for key in SEARCH_QUERY_KEYS:
                    for value in form_query.get(key, []):
                        decision = self.match_search_text(value)
                        if decision.blocked:
                            return decision

        return Decision(False, "url-allowed")
