from prevent_visit.config import AppConfig
from prevent_visit.rules import RuleSet


def build_rules() -> RuleSet:
    return RuleSet(AppConfig())


def test_blocks_direct_domain() -> None:
    rules = build_rules()
    decision = rules.match_host("www.pornhub.com")
    assert decision.blocked is False
    assert decision.reason == "search-only-host-allowed"


def test_blocks_keyword_in_search_query() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/search?q=hentai+comic")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_does_not_treat_google_service_subdomain_as_search_host() -> None:
    rules = build_rules()
    decision = rules.match_url("https://mail.google.com/mail/u/0/#search/hentai")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_blocks_spaced_brand_name_search_query() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/search?q=rule+34+art")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"
    assert decision.matched_value == "rule34"


def test_allowlisted_edge_start_page_skips_keyword_scan() -> None:
    config = AppConfig(allow_domains=["ntp.msn.com"])
    rules = RuleSet(config)
    decision = rules.match_url("https://ntp.msn.com/edge/ntp?q=rule34")
    assert decision.blocked is False
    assert decision.reason == "allowlisted"


def test_non_search_site_with_explicit_path_is_allowed() -> None:
    rules = build_rules()
    decision = rules.match_url("https://example.com/library/hentai-art-history")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_non_search_site_query_is_not_treated_like_search_engine() -> None:
    rules = build_rules()
    decision = rules.match_url("https://hdhub4u.example/find?q=hentai")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_allows_safe_domain() -> None:
    rules = build_rules()
    decision = rules.match_url("https://docs.python.org/3/")
    assert decision.blocked is False


def test_blocks_masked_explicit_keyword_in_search_query() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/search?q=po**")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_masked_xhamster_search_query() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/search?q=xham***")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_can_still_block_direct_domain_when_search_only_disabled() -> None:
    config = AppConfig(search_only_mode=False)
    rules = RuleSet(config)
    decision = rules.match_host("www.pornhub.com")
    assert decision.blocked is True
    assert decision.reason == "blocked-domain"
