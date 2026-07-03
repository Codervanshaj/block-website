function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (
    dnsDomainIs(host, "bing.com") ||
    dnsDomainIs(host, "duckduckgo.com") ||
    dnsDomainIs(host, "google.co.in") ||
    dnsDomainIs(host, "google.com") ||
    dnsDomainIs(host, "search.brave.com") ||
    dnsDomainIs(host, "search.yahoo.com") ||
    dnsDomainIs(host, "www.bing.com") ||
    dnsDomainIs(host, "www.duckduckgo.com") ||
    dnsDomainIs(host, "www.ecosia.org") ||
    dnsDomainIs(host, "www.google.co.in") ||
    dnsDomainIs(host, "www.google.com") ||
    dnsDomainIs(host, "www.startpage.com") ||
    dnsDomainIs(host, "www.yandex.com") ||
    dnsDomainIs(host, "yandex.com")
  ) {
    return "PROXY 127.0.0.1:8877";
  }
  return "DIRECT";
}
