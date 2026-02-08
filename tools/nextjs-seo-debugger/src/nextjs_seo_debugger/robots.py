"""robots.txt checker for the Next.js SEO debugger."""

from urllib.parse import urljoin

import httpx

from nextjs_seo_debugger.models import RobotsResult

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
REQUEST_TIMEOUT = 10.0


async def check_robots(base_url: str, client: httpx.AsyncClient) -> RobotsResult:
    """Fetch and analyze robots.txt.

    Checks:
    - robots.txt exists
    - Googlebot is not blocked
    - Sitemap is referenced
    - No overly broad Disallow rules
    - Common Next.js specific issues

    Args:
        base_url: The base URL of the site (e.g., https://example.com).
        client: The httpx AsyncClient to use.

    Returns:
        RobotsResult with analysis.
    """
    robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    issues: list[str] = []

    try:
        response = await client.get(
            robots_url,
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT,
        )
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return RobotsResult(
            found=False,
            allows_googlebot=True,  # No robots.txt means everything is allowed
            sitemap_referenced=False,
            issues=[f"Could not fetch robots.txt: {str(e)}"],
        )
    except Exception as e:
        return RobotsResult(
            found=False,
            allows_googlebot=True,
            sitemap_referenced=False,
            issues=[f"Error fetching robots.txt: {str(e)}"],
        )

    if response.status_code != 200:
        return RobotsResult(
            found=False,
            allows_googlebot=True,
            sitemap_referenced=False,
            issues=[
                f"robots.txt returned HTTP {response.status_code}. "
                "Without a robots.txt, Google will crawl everything (which is usually fine)."
            ],
        )

    content = response.text
    lines = content.strip().split("\n")

    allows_googlebot = True
    sitemap_referenced = False
    current_agent = None
    googlebot_rules: list[tuple[str, str]] = []  # (directive, value)
    wildcard_rules: list[tuple[str, str]] = []

    for raw_line in lines:
        # Strip comments
        line = raw_line.split("#")[0].strip()
        if not line:
            continue

        # Parse directive
        if ":" not in line:
            continue

        directive, _, value = line.partition(":")
        directive = directive.strip().lower()
        value = value.strip()

        if directive == "user-agent":
            current_agent = value.lower()
        elif directive == "sitemap":
            sitemap_referenced = True
        elif directive in ("disallow", "allow"):
            if current_agent == "googlebot":
                googlebot_rules.append((directive, value))
            elif current_agent == "*":
                wildcard_rules.append((directive, value))

    # Determine which rules apply to Googlebot
    # Googlebot-specific rules take precedence over wildcard rules
    effective_rules = googlebot_rules if googlebot_rules else wildcard_rules

    # Check for blocking rules
    for directive, value in effective_rules:
        if directive == "disallow":
            if value == "/" or value == "/*":
                allows_googlebot = False
                issues.append(
                    "robots.txt blocks Googlebot from the entire site with 'Disallow: /'. "
                    "This is the #1 reason Google won't index your site."
                )
            elif value == "":
                # Empty disallow = allow all (explicit)
                pass
            elif value in ("/_next/", "/_next/*"):
                issues.append(
                    f"Disallow rule for '{value}' may block Next.js static assets. "
                    "While generally fine, ensure it's not blocking critical CSS/JS "
                    "that Googlebot needs for rendering."
                )
            elif value == "/api/" or value == "/api/*":
                # Blocking /api/ is usually fine
                pass
            else:
                # Check for overly broad rules
                if len(value) <= 3 and value.startswith("/"):
                    issues.append(
                        f"Broad Disallow rule: '{value}'. "
                        "This may block more pages than intended."
                    )

    # Check if sitemap is referenced
    if not sitemap_referenced:
        issues.append(
            "No Sitemap directive in robots.txt. "
            "Add 'Sitemap: https://yoursite.com/sitemap.xml' to help Google discover your sitemap."
        )

    # Check for common Next.js issues
    if any("/_next/static" in rule[1] for rule in effective_rules if rule[0] == "disallow"):
        issues.append(
            "Blocking /_next/static/ prevents Googlebot from loading CSS and JavaScript. "
            "This can cause Google to see a broken/unstyled version of your page."
        )

    if any("/_next/image" in rule[1] for rule in effective_rules if rule[0] == "disallow"):
        issues.append(
            "Blocking /_next/image/ prevents Googlebot from loading optimized images. "
            "Images won't appear in Google Image search results."
        )

    return RobotsResult(
        found=True,
        allows_googlebot=allows_googlebot,
        sitemap_referenced=sitemap_referenced,
        issues=issues,
    )
