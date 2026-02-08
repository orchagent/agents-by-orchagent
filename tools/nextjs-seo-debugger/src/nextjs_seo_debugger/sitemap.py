"""Sitemap.xml checker for the Next.js SEO debugger."""

from urllib.parse import urljoin
from xml.etree import ElementTree

import httpx

from nextjs_seo_debugger.models import SitemapResult

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
REQUEST_TIMEOUT = 10.0


async def check_sitemap(base_url: str, client: httpx.AsyncClient) -> SitemapResult:
    """Fetch and analyze sitemap.xml.

    Checks:
    - Sitemap exists and is reachable
    - Sitemap is valid XML
    - URLs in sitemap return 200
    - Common issues (empty, missing lastmod, etc.)

    Args:
        base_url: The base URL of the site (e.g., https://example.com).
        client: The httpx AsyncClient to use.

    Returns:
        SitemapResult with analysis.
    """
    sitemap_url = urljoin(base_url.rstrip("/") + "/", "sitemap.xml")
    issues: list[str] = []

    try:
        response = await client.get(
            sitemap_url,
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT,
        )
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return SitemapResult(
            found=False,
            url=sitemap_url,
            page_count=0,
            issues=[f"Could not fetch sitemap.xml: {str(e)}"],
        )
    except Exception as e:
        return SitemapResult(
            found=False,
            url=sitemap_url,
            page_count=0,
            issues=[f"Error fetching sitemap.xml: {str(e)}"],
        )

    if response.status_code != 200:
        return SitemapResult(
            found=False,
            url=sitemap_url,
            page_count=0,
            issues=[
                f"sitemap.xml returned HTTP {response.status_code}. "
                "Next.js does not generate a sitemap by default - you need to create one."
            ],
        )

    # Check content type
    content_type = response.headers.get("content-type", "")
    if "xml" not in content_type and "text" not in content_type:
        issues.append(
            f"Sitemap Content-Type is '{content_type}', expected application/xml. "
            "Some crawlers may not parse it correctly."
        )

    # Parse XML
    try:
        root = ElementTree.fromstring(response.text)
    except ElementTree.ParseError as e:
        return SitemapResult(
            found=True,
            url=sitemap_url,
            page_count=0,
            issues=[f"Sitemap XML is malformed: {str(e)}"],
        )

    # Handle sitemap index
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    sitemap_tags = root.findall(".//sm:sitemap", ns)
    if sitemap_tags:
        # This is a sitemap index
        sub_count = len(sitemap_tags)
        issues.append(
            f"Sitemap index found with {sub_count} sub-sitemap(s). "
            "Only the index was analyzed, not individual sub-sitemaps."
        )
        return SitemapResult(
            found=True,
            url=sitemap_url,
            page_count=sub_count,
            issues=issues,
        )

    # Parse URL entries
    url_tags = root.findall(".//sm:url", ns)
    # Also try without namespace (some sitemaps don't use it)
    if not url_tags:
        url_tags = root.findall(".//url")

    page_count = len(url_tags)

    if page_count == 0:
        issues.append(
            "Sitemap is empty (no <url> entries). "
            "Google won't discover any pages through this sitemap."
        )
        return SitemapResult(
            found=True,
            url=sitemap_url,
            page_count=0,
            issues=issues,
        )

    # Check for common issues
    urls_with_lastmod = 0
    urls_with_loc = 0
    sample_urls: list[str] = []

    for url_tag in url_tags:
        loc = url_tag.find("sm:loc", ns)
        if loc is None:
            loc = url_tag.find("loc")

        if loc is not None and loc.text:
            urls_with_loc += 1
            if len(sample_urls) < 5:
                sample_urls.append(loc.text.strip())

        lastmod = url_tag.find("sm:lastmod", ns)
        if lastmod is None:
            lastmod = url_tag.find("lastmod")
        if lastmod is not None and lastmod.text:
            urls_with_lastmod += 1

    if urls_with_loc < page_count:
        issues.append(
            f"{page_count - urls_with_loc} URL entries are missing <loc> tags."
        )

    if urls_with_lastmod == 0:
        issues.append(
            "No <lastmod> dates found in sitemap. Adding lastmod helps Google "
            "prioritize crawling recently updated pages."
        )
    elif urls_with_lastmod < page_count:
        issues.append(
            f"Only {urls_with_lastmod}/{page_count} URLs have <lastmod> dates. "
            "Consider adding lastmod to all entries."
        )

    # Spot-check a few URLs for accessibility (up to 3)
    spot_check_count = min(3, len(sample_urls))
    for url in sample_urls[:spot_check_count]:
        try:
            check_resp = await client.head(
                url,
                follow_redirects=True,
                timeout=5.0,
            )
            if check_resp.status_code != 200:
                issues.append(
                    f"Sitemap URL returns HTTP {check_resp.status_code}: {url}"
                )
        except Exception:
            issues.append(f"Sitemap URL is unreachable: {url}")

    return SitemapResult(
        found=True,
        url=sitemap_url,
        page_count=page_count,
        issues=issues,
    )
