from .feeds import RSSSource, ScrapeSource
from .finance import CompanyNewsSource, EarningsSource, QuotesSource, SECEdgarSource
from .vulns import EPSSSource, GHSASource, KEVSource, NVDSource

TYPES = {
    "rss": RSSSource,
    "scrape": ScrapeSource,
    "nvd": NVDSource,
    "kev": KEVSource,
    "ghsa": GHSASource,
    "epss": EPSSSource,
    "sec_edgar": SECEdgarSource,
    "quotes": QuotesSource,
    "earnings": EarningsSource,
    "company_news": CompanyNewsSource,
}


def build_sources(app):
    sources = []
    for sc in app.cfg["sources"]:
        if not sc.get("enabled", True):
            continue
        cls = TYPES.get(sc.get("type", "rss"))
        if cls is None:
            raise ValueError(f"unknown source type {sc.get('type')!r} for source {sc['id']!r}")
        sources.append(cls(app, sc))
    return sources
