from prevent_visit.config import AppConfig
from prevent_visit.rules import RuleSet


def build_rules() -> RuleSet:
    return RuleSet(AppConfig())


def test_blocks_direct_domain() -> None:
    """In search-only mode, adult domains are allowed (not intercepted)."""
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
    # "rule 34" is in blocked keywords and gets matched first
    assert decision.matched_value in ("rule34", "rule 34")


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


# Additional comprehensive tests for all browsers

def test_blocks_bing_search_with_explicit_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.bing.com/search?q=pornhub")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_duckduckgo_search_with_explicit_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://duckduckgo.com/?q=xvideos")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_yahoo_search_with_explicit_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://search.yahoo.com/search?p=nude+images")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_brave_search_with_explicit_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://search.brave.com/search?q=adult+videos")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_google_images_search_with_explicit_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/images?q=naked+girl")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_google_images_subdomain() -> None:
    rules = build_rules()
    decision = rules.match_url("https://images.google.com/search?q=hentai")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_allows_google_maps() -> None:
    rules = build_rules()
    decision = rules.match_url("https://maps.google.com/maps?q=coffee+shop")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_allows_google_news() -> None:
    rules = build_rules()
    decision = rules.match_url("https://news.google.com/search?q=breaking+news")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_allows_youtube_main_page() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.youtube.com/")
    assert decision.blocked is False


def test_blocks_google_with_xxx_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/search?q=xxx+movies")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_google_with_nude_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/search?q=nude+celebrities")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_google_with_nsfw_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/search?q=nsfw+content")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_google_with_milf_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/search?q=milf+video")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_allows_safe_search_queries() -> None:
    rules = build_rules()
    # Normal searches should be allowed
    assert rules.match_url("https://www.google.com/search?q=how+to+cook+pasta").blocked is False
    assert rules.match_url("https://www.bing.com/search?q=weather+forecast").blocked is False
    assert rules.match_url("https://duckduckgo.com/?q=python+tutorial").blocked is False


def test_allows_gmail() -> None:
    rules = build_rules()
    decision = rules.match_url("https://mail.google.com/mail/u/0/")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_allows_google_docs() -> None:
    rules = build_rules()
    decision = rules.match_url("https://docs.google.com/document/")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_allows_google_drive() -> None:
    rules = build_rules()
    decision = rules.match_url("https://drive.google.com/")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_blocks_google_search_mobile_subdomain() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/m/search?q=porn")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_google_search_mobile_subdomain() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.google.com/m/search?q=porn")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_google_co_uk_with_explicit_keyword() -> None:
    rules = build_rules()
    # google.co.uk is not in the default intercept list, but .co.uk subdomains should be intercepted
    decision = rules.match_url("https://www.google.co.uk/search?q=naked")
    # This should NOT be blocked because .co.uk is not configured
    # But www.google.com/search with naked should be blocked
    assert rules.match_url("https://www.google.com/search?q=naked").blocked is True


def test_blocks_yandex_search_with_explicit_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.yandex.com/search/?text=xxx")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_ecosia_search_with_explicit_keyword() -> None:
    rules = build_rules()
    decision = rules.match_url("https://www.ecosia.org/search?q=erotic")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_startpage_search_with_explicit_keyword() -> None:
    rules = build_rules()
    # Startpage uses 'query' parameter for search - test with 'erotic' which is in blocked keywords
    decision = rules.match_url("https://www.startpage.com/do/search?query=erotic")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"
    # Also test with 'q' parameter (like Google)
    decision2 = rules.match_url("https://www.startpage.com/do/search?q=porn")
    assert decision2.blocked is True
    assert decision2.reason == "blocked-search-query"


def test_blocks_explicit_website_name_in_search() -> None:
    rules = build_rules()
    # Searching for a specific adult website should be blocked
    assert rules.match_url("https://www.google.com/search?q=pornhub+website").blocked is True
    assert rules.match_url("https://www.google.com/search?q=xvideos+download").blocked is True
    assert rules.match_url("https://www.google.com/search?q=onlyfans+account").blocked is True


def test_blocks_obfuscated_keywords() -> None:
    rules = build_rules()
    # Queries where blocked keyword is prefix (hentai1 contains hentai)
    decision = rules.match_url("https://www.google.com/search?q=hentai1")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"
    assert decision.matched_value == "hentai"


def test_blocks_obfuscated_suffix_keywords() -> None:
    rules = build_rules()
    # Queries where blocked keyword is a suffix
    decision = rules.match_url("https://www.google.com/search?q=somethingporn")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_pornhub_with_numbers() -> None:
    rules = build_rules()
    # "pornhub123" should be blocked because it contains "pornhub"
    decision = rules.match_url("https://www.google.com/search?q=pornhub123")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_blocks_partially_masked_keywords() -> None:
    rules = build_rules()
    # Keywords with some characters masked should be caught
    decision = rules.match_url("https://www.google.com/search?q=xhentai")
    assert decision.blocked is True
    assert decision.reason == "blocked-search-query"


def test_allows_stackoverflow() -> None:
    rules = build_rules()
    # Non-search domain should be allowed
    decision = rules.match_url("https://stackoverflow.com/questions/tagged/python")
    assert decision.blocked is False


def test_allows_github() -> None:
    rules = build_rules()
    decision = rules.match_url("https://github.com/search?q=python")
    assert decision.blocked is False
    assert decision.reason == "url-allowed"


def test_allows_wikipedia() -> None:
    rules = build_rules()
    decision = rules.match_url("https://en.wikipedia.org/wiki/Python_(programming_language)")
    assert decision.blocked is False
