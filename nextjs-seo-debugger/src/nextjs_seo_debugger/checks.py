"""Individual SEO check functions for the Next.js SEO debugger.

Each function returns one or more SEOCheck objects with pass/fail/warn/info status.
"""

from urllib.parse import urlparse

from nextjs_seo_debugger.models import CheckStatus, RedirectChain, SEOCheck


def check_redirect_chain(chain: RedirectChain) -> SEOCheck:
    """Check if a redirect chain has problematic patterns.

    Flags:
    - More than 2 hops
    - 302 (temporary) instead of 301 (permanent)
    - 308 redirects (common Next.js trailing slash issue)
    - Protocol mixing (http -> https or vice versa)
    - Trailing slash inconsistency

    Args:
        chain: The redirect chain to analyze.

    Returns:
        SEOCheck result.
    """
    issues: list[str] = []
    severity = CheckStatus.PASS

    if len(chain.hops) > 2:
        issues.append(
            f"Redirect chain has {len(chain.hops)} hops. "
            "Google may stop following after 5 hops and lose link equity with each hop."
        )
        severity = CheckStatus.FAIL

    for hop in chain.hops:
        if hop.status_code == 302:
            issues.append(
                f"302 (temporary) redirect at {hop.url}. "
                "Google treats 302s differently from 301s - link equity may not be fully passed."
            )
            if severity != CheckStatus.FAIL:
                severity = CheckStatus.WARN

        if hop.status_code == 308:
            issues.append(
                f"308 (permanent with method preservation) redirect at {hop.url}. "
                "This is a common Next.js/Vercel trailing slash issue. "
                "Googlebot may not handle 308 redirects correctly in all cases."
            )
            severity = CheckStatus.FAIL

        # Check protocol mixing
        src_parsed = urlparse(hop.url)
        dst_parsed = urlparse(hop.location) if hop.location else None
        if dst_parsed and src_parsed.scheme == "https" and dst_parsed.scheme == "http":
            issues.append(
                f"HTTPS to HTTP downgrade redirect at {hop.url}. "
                "This is a security issue and Google penalizes it."
            )
            severity = CheckStatus.FAIL

        # Check trailing slash mismatch
        if dst_parsed:
            src_path = src_parsed.path.rstrip("/")
            dst_path = dst_parsed.path.rstrip("/")
        else:
            src_path = dst_path = ""
        if (
            dst_parsed
            and src_parsed.netloc == dst_parsed.netloc
            and src_path == dst_path
            and src_parsed.path != dst_parsed.path
        ):
            issues.append(
                f"Trailing slash redirect at {hop.url} -> {hop.location}. "
                "Configure trailingSlash in next.config.js to be consistent."
            )
            if severity == CheckStatus.PASS:
                severity = CheckStatus.WARN

    if not issues:
        return SEOCheck(
            name="redirect_chain",
            status=CheckStatus.PASS,
            message="Redirect chain is clean.",
        )

    return SEOCheck(
        name="redirect_chain",
        status=severity,
        message=f"Redirect chain has {len(issues)} issue(s).",
        details="\n".join(issues),
        fix="Review your Next.js redirects configuration and next.config.js trailingSlash setting. "
        "Use 301 redirects for permanent moves. Minimize redirect hops.",
    )


def check_canonical(page_url: str, canonical_value: str | None) -> SEOCheck:
    """Verify the canonical tag is correct.

    Checks:
    - Canonical tag exists
    - Canonical matches the page URL
    - Canonical doesn't point to a different domain
    - Trailing slash consistency between canonical and page URL

    Args:
        page_url: The actual URL of the page (after redirects).
        canonical_value: The canonical URL from the page's meta tags.

    Returns:
        SEOCheck result.
    """
    if canonical_value is None or canonical_value.strip() == "":
        return SEOCheck(
            name="canonical",
            status=CheckStatus.FAIL,
            message="Missing canonical tag.",
            details="Google may choose its own canonical URL, which might not be what you want. "
            "This can lead to duplicate content issues and wasted crawl budget.",
            fix="Add <link rel=\"canonical\" href=\"{url}\" /> to the <head> of every page. "
            "In Next.js, use the metadata API or next/head.",
        )

    canonical = canonical_value.strip()
    parsed_page = urlparse(page_url)
    parsed_canonical = urlparse(canonical)

    # Check domain mismatch
    if parsed_canonical.netloc and parsed_canonical.netloc != parsed_page.netloc:
        return SEOCheck(
            name="canonical",
            status=CheckStatus.FAIL,
            message=f"Canonical points to different domain: {parsed_canonical.netloc}",
            details=f"Page URL: {page_url}\nCanonical: {canonical}\n"
            "This tells Google the content lives on another domain, "
            "which will prevent this page from being indexed.",
            fix="Update the canonical tag to point to the correct domain.",
        )

    # Normalize paths for comparison
    page_path = parsed_page.path.rstrip("/") or "/"
    canonical_path = parsed_canonical.path.rstrip("/") or "/"

    # Check path mismatch (ignoring trailing slash)
    if page_path != canonical_path:
        return SEOCheck(
            name="canonical",
            status=CheckStatus.WARN,
            message="Canonical URL path differs from page URL.",
            details=f"Page URL: {page_url}\nCanonical: {canonical}\n"
            "If intentional (e.g., consolidating paginated pages), this is fine. "
            "Otherwise, it may prevent this specific URL from being indexed.",
            fix="Ensure the canonical URL matches the page URL, or verify "
            "the mismatch is intentional.",
        )

    # Check trailing slash inconsistency
    if parsed_page.path != parsed_canonical.path:
        return SEOCheck(
            name="canonical",
            status=CheckStatus.WARN,
            message="Trailing slash mismatch between page URL and canonical.",
            details=f"Page URL: {page_url}\nCanonical: {canonical}\n"
            "While Google usually handles this, it can cause confusion. "
            "Next.js trailingSlash config should match your canonical URLs.",
            fix="Set trailingSlash in next.config.js to match your canonical URLs.",
        )

    return SEOCheck(
        name="canonical",
        status=CheckStatus.PASS,
        message="Canonical tag is correctly set.",
    )


def check_meta_tags(meta: dict) -> list[SEOCheck]:
    """Check meta tags for SEO best practices.

    Validates:
    - Title exists and is within optimal length (50-60 chars)
    - Meta description exists and is within optimal length (150-160 chars)
    - No robots noindex directives

    Args:
        meta: Dict of parsed meta tags from parse_meta_tags().

    Returns:
        List of SEOCheck results.
    """
    checks: list[SEOCheck] = []

    # Title check
    title = meta.get("title")
    if not title:
        checks.append(
            SEOCheck(
                name="title",
                status=CheckStatus.FAIL,
                message="Missing <title> tag.",
                details="Google uses the title tag as the primary text in search results. "
                "Without it, Google will try to generate one, often poorly.",
                fix="Add a unique, descriptive title to every page using Next.js metadata API.",
            )
        )
    else:
        title_len = len(title)
        if title_len < 30:
            checks.append(
                SEOCheck(
                    name="title",
                    status=CheckStatus.WARN,
                    message=f"Title is too short ({title_len} chars). Aim for 50-60 characters.",
                    details=f"Current title: \"{title}\"",
                    fix="Expand the title to include relevant keywords. Aim for 50-60 characters.",
                )
            )
        elif title_len > 60:
            checks.append(
                SEOCheck(
                    name="title",
                    status=CheckStatus.WARN,
                    message=f"Title is too long ({title_len} chars). Google may truncate it.",
                    details=f"Current title: \"{title}\"",
                    fix="Shorten the title to 60 characters or fewer to prevent truncation in search results.",
                )
            )
        else:
            checks.append(
                SEOCheck(
                    name="title",
                    status=CheckStatus.PASS,
                    message=f"Title length is good ({title_len} chars).",
                )
            )

    # Meta description check
    description = meta.get("description")
    if not description:
        checks.append(
            SEOCheck(
                name="meta_description",
                status=CheckStatus.WARN,
                message="Missing meta description.",
                details="While Google may generate its own snippet, a well-crafted meta description "
                "gives you control over how your page appears in search results.",
                fix="Add a meta description using Next.js metadata API. Aim for 150-160 characters.",
            )
        )
    else:
        desc_len = len(description)
        if desc_len < 70:
            checks.append(
                SEOCheck(
                    name="meta_description",
                    status=CheckStatus.WARN,
                    message=f"Meta description is short ({desc_len} chars). Aim for 150-160.",
                    details=f"Current description: \"{description}\"",
                    fix="Expand the description to 150-160 characters for better search result visibility.",
                )
            )
        elif desc_len > 160:
            checks.append(
                SEOCheck(
                    name="meta_description",
                    status=CheckStatus.WARN,
                    message=f"Meta description is long ({desc_len} chars). May be truncated.",
                    details=f"Current description: \"{description[:100]}...\"",
                    fix="Shorten the description to 160 characters or fewer.",
                )
            )
        else:
            checks.append(
                SEOCheck(
                    name="meta_description",
                    status=CheckStatus.PASS,
                    message=f"Meta description length is good ({desc_len} chars).",
                )
            )

    # Robots noindex check
    robots = meta.get("robots", "") or ""
    googlebot = meta.get("googlebot", "") or ""
    combined_robots = f"{robots} {googlebot}".lower()

    if "noindex" in combined_robots:
        checks.append(
            SEOCheck(
                name="robots_noindex",
                status=CheckStatus.FAIL,
                message="Page has a noindex directive. Google will NOT index this page.",
                details=f"robots meta: \"{robots}\"\ngooglebot meta: \"{googlebot}\"",
                fix="Remove the noindex directive unless you intentionally want to exclude "
                "this page from search results. Check your Next.js metadata configuration.",
            )
        )
    elif "nofollow" in combined_robots:
        checks.append(
            SEOCheck(
                name="robots_nofollow",
                status=CheckStatus.WARN,
                message="Page has a nofollow directive. Google won't follow links on this page.",
                details=f"robots meta: \"{robots}\"",
                fix="Remove nofollow unless intentional. This prevents link equity from flowing to linked pages.",
            )
        )
    else:
        checks.append(
            SEOCheck(
                name="robots_meta",
                status=CheckStatus.PASS,
                message="No blocking robots meta directives found.",
            )
        )

    return checks


def check_og_tags(og_tags: dict[str, str]) -> SEOCheck:
    """Verify Open Graph tags for social sharing.

    Checks for og:title, og:description, og:image.

    Args:
        og_tags: Dict of Open Graph tags found on the page.

    Returns:
        SEOCheck result.
    """
    missing: list[str] = []
    required = ["og:title", "og:description", "og:image"]

    for tag in required:
        if tag not in og_tags or not og_tags[tag].strip():
            missing.append(tag)

    if not missing:
        return SEOCheck(
            name="og_tags",
            status=CheckStatus.PASS,
            message="All essential Open Graph tags present.",
        )

    if len(missing) == len(required):
        return SEOCheck(
            name="og_tags",
            status=CheckStatus.WARN,
            message="No Open Graph tags found.",
            details="Missing: " + ", ".join(missing) + "\n"
            "OG tags improve how your site appears when shared on social media "
            "and can indirectly affect SEO through engagement.",
            fix="Add Open Graph tags using Next.js metadata API: "
            "openGraph: { title, description, images }",
        )

    return SEOCheck(
        name="og_tags",
        status=CheckStatus.WARN,
        message=f"Missing Open Graph tags: {', '.join(missing)}",
        details="OG tags improve social sharing appearance and can indirectly benefit SEO.",
        fix="Add the missing OG tags using Next.js metadata API.",
    )


def check_status_code(code: int) -> SEOCheck:
    """Check if the HTTP status code is SEO-friendly.

    Args:
        code: The HTTP status code.

    Returns:
        SEOCheck result.
    """
    if code == 200:
        return SEOCheck(
            name="status_code",
            status=CheckStatus.PASS,
            message="Page returns 200 OK.",
        )
    elif code == 404:
        return SEOCheck(
            name="status_code",
            status=CheckStatus.FAIL,
            message="Page returns 404 Not Found.",
            details="Google will de-index pages that return 404.",
            fix="Ensure the page exists and returns 200. Check your Next.js routing configuration.",
        )
    elif code == 500:
        return SEOCheck(
            name="status_code",
            status=CheckStatus.FAIL,
            message="Page returns 500 Internal Server Error.",
            details="Server errors prevent Google from crawling the page. "
            "If persistent, Google will de-index the page.",
            fix="Fix the server error. Check your Next.js server-side code and error boundaries.",
        )
    elif code == 403:
        return SEOCheck(
            name="status_code",
            status=CheckStatus.FAIL,
            message="Page returns 403 Forbidden.",
            details="Google cannot access this page. It will not be indexed.",
            fix="Check if your server is blocking Googlebot by User-Agent or IP. "
            "Review Vercel firewall/middleware rules.",
        )
    elif 300 <= code < 400:
        return SEOCheck(
            name="status_code",
            status=CheckStatus.INFO,
            message=f"Page returns {code} redirect.",
            details="Redirects are handled separately in the redirect chain check.",
        )
    else:
        return SEOCheck(
            name="status_code",
            status=CheckStatus.WARN,
            message=f"Unexpected status code: {code}.",
            details="Non-standard status codes may confuse Googlebot.",
            fix="Ensure your pages return standard HTTP status codes (200, 301, 404).",
        )


def check_nextjs_issues(html: str, headers: dict) -> list[SEOCheck]:
    """Check for Next.js and Vercel-specific SEO issues.

    Detects:
    - Missing SSR (empty shell with __next div but no content)
    - x-powered-by header revealing framework
    - Client-side only rendering indicators
    - Missing __NEXT_DATA__ or __next-route-announcer
    - Vercel-specific headers

    Args:
        html: The page HTML content.
        headers: The response headers dict.

    Returns:
        List of SEOCheck results.
    """
    checks: list[SEOCheck] = []
    html_lower = html.lower()

    # Check for empty Next.js shell (CSR-only, no SSR)
    has_next_div = 'id="__next"' in html or "id='__next'" in html
    if has_next_div:
        # Check if __next div is essentially empty (CSR-only)
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "lxml")
        next_div = soup.find(id="__next")
        if next_div:
            # Get text content, excluding script tags
            for script in next_div.find_all("script"):
                script.decompose()
            text_content = next_div.get_text(strip=True)

            if len(text_content) < 50:
                checks.append(
                    SEOCheck(
                        name="nextjs_ssr",
                        status=CheckStatus.FAIL,
                        message="Page appears to be client-side rendered only (no SSR).",
                        details="The #__next div is nearly empty, suggesting the page relies on "
                        "client-side JavaScript to render content. Googlebot may not wait "
                        "for JS execution, resulting in an empty page being indexed.\n"
                        f"Text content in #__next: {len(text_content)} characters.",
                        fix="Use getServerSideProps, getStaticProps, or the App Router with "
                        "Server Components to ensure content is server-rendered. "
                        "Avoid 'use client' on layout/page components that contain critical content.",
                    )
                )
            else:
                checks.append(
                    SEOCheck(
                        name="nextjs_ssr",
                        status=CheckStatus.PASS,
                        message="Page has server-rendered content in #__next div.",
                    )
                )

    # Check for __NEXT_DATA__ (Pages Router SSR indicator)
    has_next_data = "__next_data__" in html_lower or '__next_data__' in html_lower
    # More accurate check
    has_next_data = 'id="__NEXT_DATA__"' in html

    # Check for Next.js route announcer (accessibility/SSR indicator)
    has_route_announcer = "__next-route-announcer" in html

    if has_next_div and not has_next_data and not has_route_announcer:
        # Could be App Router (which doesn't use __NEXT_DATA__)
        # or could be missing SSR
        if "/_next/static" not in html:
            checks.append(
                SEOCheck(
                    name="nextjs_detection",
                    status=CheckStatus.INFO,
                    message="Could not confirm Next.js SSR setup.",
                    details="The page has a #__next div but no __NEXT_DATA__ script or "
                    "route announcer. This might be an App Router page (which is fine) "
                    "or a misconfigured setup.",
                )
            )

    # Check x-powered-by header
    powered_by = headers.get("x-powered-by", "")
    if "next.js" in powered_by.lower():
        checks.append(
            SEOCheck(
                name="x_powered_by",
                status=CheckStatus.INFO,
                message=f"x-powered-by header reveals Next.js ({powered_by}).",
                details="While not directly an SEO issue, exposing framework information "
                "is a minor security concern.",
                fix="Set poweredByHeader: false in next.config.js to remove this header.",
            )
        )

    # Check for Vercel deployment
    is_vercel = False
    vercel_headers = []
    for key in headers:
        if key.lower().startswith("x-vercel"):
            is_vercel = True
            vercel_headers.append(f"{key}: {headers[key]}")

    if is_vercel:
        checks.append(
            SEOCheck(
                name="vercel_deployment",
                status=CheckStatus.INFO,
                message="Site is deployed on Vercel.",
                details="Detected Vercel headers: " + ", ".join(vercel_headers),
            )
        )

    # Check for client-side rendering indicators
    csr_indicators = [
        ("loading...", "Generic loading placeholder"),
        ("loading spinner", "Loading spinner text"),
        ('class="loading"', "Loading CSS class"),
        ("skeleton", "Skeleton screen indicator"),
        ("data-reactroot", "React root without SSR content"),
    ]

    for indicator, description in csr_indicators:
        if indicator in html_lower:
            # Only flag if it seems like the main content area
            checks.append(
                SEOCheck(
                    name="csr_indicator",
                    status=CheckStatus.WARN,
                    message=f"Possible client-side rendering indicator found: {description}.",
                    details=f"Found \"{indicator}\" in page HTML. If this is placeholder content "
                    "that gets replaced by JavaScript, Googlebot may index the placeholder instead.",
                    fix="Ensure critical content is server-rendered. Move data fetching to "
                    "server components or getServerSideProps/getStaticProps.",
                )
            )
            break  # Only report one CSR indicator to avoid noise

    # Check for soft 404 (200 status but error page content)
    soft_404_indicators = [
        "this page could not be found",
        "page not found",
        "404 - page not found",
        "this page doesn't exist",
    ]
    for indicator in soft_404_indicators:
        if indicator in html_lower:
            checks.append(
                SEOCheck(
                    name="soft_404",
                    status=CheckStatus.FAIL,
                    message="Possible soft 404 detected.",
                    details=f"Page returns 200 OK but contains \"{indicator}\" text. "
                    "Google's systems detect soft 404s and may de-index these pages.",
                    fix="Return a proper 404 status code for pages that don't exist. "
                    "In Next.js, use notFound() in getServerSideProps or the not-found.tsx convention.",
                )
            )
            break

    return checks
