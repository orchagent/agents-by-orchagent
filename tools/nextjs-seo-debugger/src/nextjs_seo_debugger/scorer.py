"""Score calculator and recommendation generator for the Next.js SEO debugger."""

from nextjs_seo_debugger.models import CheckStatus, DebugReport


def calculate_score(report: DebugReport) -> int:
    """Calculate an overall SEO health score from 0-100.

    Scoring breakdown:
    - Starts at 100
    - Each FAIL check: -10 points
    - Each WARN check: -3 points
    - No pages accessible: 0
    - Robots blocks Googlebot: cap at 10
    - Sitemap missing: -5

    Args:
        report: The DebugReport to score.

    Returns:
        Integer score from 0 to 100.
    """
    if not report.pages:
        return 0

    score = 100

    # Deduct for page-level check failures
    for page in report.pages:
        for check in page.checks:
            if check.status == CheckStatus.FAIL:
                score -= 10
            elif check.status == CheckStatus.WARN:
                score -= 3

    # Robots.txt penalties
    if not report.robots.allows_googlebot:
        score = min(score, 10)  # Cap at 10 if Googlebot is blocked

    if report.robots.issues:
        score -= 2 * len(report.robots.issues)

    # Sitemap penalties
    if not report.sitemap.found:
        score -= 5
    elif report.sitemap.page_count == 0:
        score -= 5

    if report.sitemap.issues:
        score -= len(report.sitemap.issues)

    # Clamp to 0-100
    return max(0, min(100, score))


def generate_recommendations(report: DebugReport) -> list[str]:
    """Generate prioritized recommendations based on the debug report.

    Returns the top 5 most important recommendations, ordered by severity.

    Args:
        report: The DebugReport to analyze.

    Returns:
        List of recommendation strings (up to 5).
    """
    critical: list[str] = []
    important: list[str] = []
    nice_to_have: list[str] = []

    # Check if Googlebot is blocked (highest priority)
    if not report.robots.allows_googlebot:
        critical.append(
            "CRITICAL: robots.txt is blocking Googlebot from your entire site. "
            "Remove or modify the 'Disallow: /' rule to allow indexing."
        )

    # Check for noindex directives
    for page in report.pages:
        for check in page.checks:
            if check.name == "robots_noindex" and check.status == CheckStatus.FAIL:
                critical.append(
                    f"CRITICAL: {page.url} has a noindex meta tag. Remove it to allow Google indexing."
                )
                break

    # Check for SSR issues
    for page in report.pages:
        for check in page.checks:
            if check.name == "nextjs_ssr" and check.status == CheckStatus.FAIL:
                critical.append(
                    "CRITICAL: Pages are client-side rendered only. Google may see empty pages. "
                    "Switch to Server Components (App Router) or use getServerSideProps/getStaticProps."
                )
                break
        else:
            continue
        break

    # Check for redirect issues
    redirect_issues_found = False
    for page in report.pages:
        if page.redirect_chain and page.redirect_chain.is_problematic:
            redirect_issues_found = True
            break
    if redirect_issues_found:
        important.append(
            "Fix redirect chain issues. Ensure redirects use 301 status codes, "
            "minimize redirect hops, and configure trailingSlash consistently in next.config.js."
        )

    # Check for missing canonicals
    missing_canonical = False
    for page in report.pages:
        for check in page.checks:
            if check.name == "canonical" and check.status == CheckStatus.FAIL:
                missing_canonical = True
                break
    if missing_canonical:
        important.append(
            "Add canonical tags to all pages. Use Next.js metadata API: "
            "alternates: { canonical: 'https://yoursite.com/page' }"
        )

    # Check for missing titles
    missing_title = False
    for page in report.pages:
        for check in page.checks:
            if check.name == "title" and check.status == CheckStatus.FAIL:
                missing_title = True
                break
    if missing_title:
        important.append(
            "Add unique <title> tags to all pages. "
            "Titles are the most important on-page SEO element."
        )

    # Check for missing sitemap
    if not report.sitemap.found:
        important.append(
            "Create a sitemap.xml. In Next.js App Router, add a sitemap.ts file. "
            "For Pages Router, use next-sitemap package."
        )
    elif report.sitemap.page_count == 0:
        important.append(
            "Your sitemap.xml is empty. Ensure it contains URLs for all indexable pages."
        )

    # Check for missing sitemap reference in robots.txt
    if report.robots.found and not report.robots.sitemap_referenced:
        nice_to_have.append(
            "Add a Sitemap directive to robots.txt: Sitemap: https://yoursite.com/sitemap.xml"
        )

    # Check for missing OG tags
    missing_og = False
    for page in report.pages:
        for check in page.checks:
            if check.name == "og_tags" and check.status == CheckStatus.WARN:
                missing_og = True
                break
    if missing_og:
        nice_to_have.append(
            "Add Open Graph tags (og:title, og:description, og:image) for better social sharing."
        )

    # Check for soft 404s
    soft_404_found = False
    for page in report.pages:
        for check in page.checks:
            if check.name == "soft_404" and check.status == CheckStatus.FAIL:
                soft_404_found = True
                break
    if soft_404_found:
        important.append(
            "Fix soft 404 pages. Return proper 404 status codes for pages that don't exist. "
            "Use notFound() in Next.js server-side functions."
        )

    # Combine and limit to top 5
    all_recs = critical + important + nice_to_have
    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for rec in all_recs:
        if rec not in seen:
            seen.add(rec)
            unique.append(rec)

    return unique[:5]
