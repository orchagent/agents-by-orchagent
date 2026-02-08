"""Core crawler for the Next.js SEO debugger.

Uses httpx to fetch pages with a Googlebot-like User-Agent and manually
follows redirects to capture the full redirect chain.
"""

from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from nextjs_seo_debugger.checks import (
    check_canonical,
    check_meta_tags,
    check_nextjs_issues,
    check_og_tags,
    check_redirect_chain,
    check_status_code,
)
from nextjs_seo_debugger.models import (
    PageResult,
    RedirectChain,
    RedirectHop,
    SEOCheck,
)

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
REQUEST_TIMEOUT = 10.0
MAX_REDIRECTS = 10


async def fetch_page(
    url: str,
    client: httpx.AsyncClient,
    follow_redirects: bool = True,
) -> tuple[Optional[httpx.Response], RedirectChain]:
    """Fetch a page with Googlebot User-Agent, manually following redirects.

    Args:
        url: The URL to fetch.
        client: The httpx AsyncClient to use.
        follow_redirects: Whether to follow redirects manually.

    Returns:
        Tuple of (final response or None on error, redirect chain).
    """
    hops: list[RedirectHop] = []
    current_url = url
    response = None

    for _ in range(MAX_REDIRECTS):
        try:
            response = await client.get(
                current_url,
                follow_redirects=False,
                timeout=REQUEST_TIMEOUT,
            )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout) as e:
            chain = RedirectChain(
                hops=hops,
                final_url=current_url,
                is_problematic=True,
                issue=f"Connection error: {str(e)}",
            )
            return None, chain
        except Exception as e:
            chain = RedirectChain(
                hops=hops,
                final_url=current_url,
                is_problematic=True,
                issue=f"Unexpected error: {str(e)}",
            )
            return None, chain

        if response.is_redirect and follow_redirects:
            location = response.headers.get("location", "")
            if not location:
                break

            # Resolve relative redirects
            resolved_location = urljoin(current_url, location)

            hops.append(
                RedirectHop(
                    url=current_url,
                    status_code=response.status_code,
                    location=resolved_location,
                )
            )
            current_url = resolved_location
        else:
            break

    is_problematic = False
    issue = None

    if len(hops) > 2:
        is_problematic = True
        issue = f"Redirect chain has {len(hops)} hops (more than 2)"
    elif len(hops) > 0:
        # Check for problematic redirect patterns
        for hop in hops:
            if hop.status_code == 302:
                is_problematic = True
                issue = "Uses 302 (temporary) redirect instead of 301 (permanent) - Google may not pass link equity"
                break
            if hop.status_code == 308:
                is_problematic = True
                issue = "Uses 308 redirect - common Next.js/Vercel trailing slash issue that can confuse Googlebot"
                break

    chain = RedirectChain(
        hops=hops,
        final_url=current_url,
        is_problematic=is_problematic,
        issue=issue,
    )
    return response, chain


def parse_meta_tags(html: str) -> dict:
    """Extract SEO-relevant meta tags from HTML.

    Args:
        html: The HTML content to parse.

    Returns:
        Dict containing title, description, canonical, robots, og:* tags.
    """
    soup = BeautifulSoup(html, "lxml")
    meta: dict = {}

    # Title
    title_tag = soup.find("title")
    meta["title"] = title_tag.get_text(strip=True) if title_tag else None

    # Meta description
    desc_tag = soup.find("meta", attrs={"name": "description"})
    meta["description"] = desc_tag.get("content", "") if desc_tag else None

    # Canonical link
    canonical_tag = soup.find("link", attrs={"rel": "canonical"})
    meta["canonical"] = canonical_tag.get("href", "") if canonical_tag else None

    # Robots meta
    robots_tag = soup.find("meta", attrs={"name": "robots"})
    meta["robots"] = robots_tag.get("content", "") if robots_tag else None

    # Googlebot-specific meta
    googlebot_tag = soup.find("meta", attrs={"name": "googlebot"})
    meta["googlebot"] = googlebot_tag.get("content", "") if googlebot_tag else None

    # Open Graph tags
    og_tags: dict[str, str] = {}
    for tag in soup.find_all("meta", attrs={"property": True}):
        prop = tag.get("property", "")
        if prop.startswith("og:"):
            og_tags[prop] = tag.get("content", "")
    meta["og_tags"] = og_tags

    return meta


def find_internal_links(html: str, base_url: str) -> list[str]:
    """Extract internal links from HTML for crawling additional pages.

    Args:
        html: The HTML content to parse.
        base_url: The base URL to resolve relative links against.

    Returns:
        List of unique internal URLs found.
    """
    soup = BeautifulSoup(html, "lxml")
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc
    seen: set[str] = set()
    links: list[str] = []

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]

        # Skip fragment-only links, javascript:, mailto:, tel:
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        # Resolve relative URLs
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)

        # Only include same-domain links
        if parsed.netloc != base_domain:
            continue

        # Normalize: strip fragment, keep path and query
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"

        # Skip common non-page resources
        path_lower = parsed.path.lower()
        skip_extensions = (
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
            ".css", ".js", ".pdf", ".zip", ".xml", ".json",
        )
        if any(path_lower.endswith(ext) for ext in skip_extensions):
            continue

        if normalized not in seen:
            seen.add(normalized)
            links.append(normalized)

    return links


async def check_page(
    url: str,
    client: httpx.AsyncClient,
    follow_redirects: bool = True,
) -> PageResult:
    """Perform a full SEO check on a single page.

    Args:
        url: The URL to check.
        client: The httpx AsyncClient to use.
        follow_redirects: Whether to follow redirects.

    Returns:
        PageResult with all check results.
    """
    response, redirect_chain = await fetch_page(url, client, follow_redirects)

    if response is None:
        return PageResult(
            url=url,
            status_code=0,
            checks=[
                SEOCheck(
                    name="connectivity",
                    status="fail",
                    message=f"Could not connect to {url}",
                    details=redirect_chain.issue,
                    fix="Verify the URL is correct and the server is running.",
                )
            ],
            redirect_chain=redirect_chain,
        )

    html = response.text
    headers = dict(response.headers)
    status_code = response.status_code

    # Parse meta tags
    meta = parse_meta_tags(html)

    # Run all checks
    checks: list[SEOCheck] = []

    # Status code check
    checks.append(check_status_code(status_code))

    # Redirect chain check
    if redirect_chain.hops:
        checks.append(check_redirect_chain(redirect_chain))

    # Canonical check
    checks.append(check_canonical(redirect_chain.final_url, meta.get("canonical")))

    # Meta tag checks
    checks.extend(check_meta_tags(meta))

    # OG tag checks
    checks.append(check_og_tags(meta.get("og_tags", {})))

    # Next.js specific checks
    checks.extend(check_nextjs_issues(html, headers))

    return PageResult(
        url=url,
        status_code=status_code,
        title=meta.get("title"),
        meta_description=meta.get("description"),
        canonical=meta.get("canonical"),
        og_tags=meta.get("og_tags", {}),
        checks=checks,
        redirect_chain=redirect_chain if redirect_chain.hops else None,
    )
