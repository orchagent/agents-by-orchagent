#!/usr/bin/env python3
"""Main entrypoint for nextjs-seo-debugger.

This script reads JSON input from stdin (DebugInput model), crawls the target URL
like Googlebot, runs all SEO checks, and outputs a DebugReport as JSON to stdout.
"""

import asyncio
import json
import sys
from datetime import datetime, timezone

# Add src directory to path for imports
sys.path.insert(0, "src")

from nextjs_seo_debugger.models import (
    DebugInput,
    DebugReport,
    PageResult,
    RobotsResult,
    SEOCheck,
    SitemapResult,
)

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


async def run_debug(debug_input: DebugInput) -> DebugReport:
    """Run the full SEO debug scan.

    Args:
        debug_input: The validated input parameters.

    Returns:
        Complete DebugReport.
    """
    import httpx

    from nextjs_seo_debugger.crawler import check_page, find_internal_links
    from nextjs_seo_debugger.robots import check_robots
    from nextjs_seo_debugger.scorer import calculate_score, generate_recommendations
    from nextjs_seo_debugger.sitemap import check_sitemap

    url = debug_input.url.strip()

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scan_time = datetime.now(timezone.utc).isoformat()
    pages: list[PageResult] = []
    sitemap_result = SitemapResult()
    robots_result = RobotsResult()

    headers = {
        "User-Agent": GOOGLEBOT_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }

    async with httpx.AsyncClient(
        headers=headers,
        verify=False,  # Handle SSL errors gracefully
        timeout=15.0,
    ) as client:
        # 1. Check the main page
        try:
            main_page = await check_page(url, client, debug_input.follow_redirects)
            pages.append(main_page)
        except Exception as e:
            pages.append(
                PageResult(
                    url=url,
                    status_code=0,
                    checks=[
                        SEOCheck(
                            name="connectivity",
                            status="fail",
                            message=f"Failed to check main page: {str(e)}",
                            fix="Verify the URL is correct and the server is accessible.",
                        )
                    ],
                )
            )

        # 2. Crawl internal pages (if main page was successful)
        if pages and pages[0].status_code == 200 and debug_input.max_pages > 1:
            try:
                # Fetch main page HTML for link extraction
                resp = await client.get(url, follow_redirects=True, timeout=10.0)
                internal_links = find_internal_links(resp.text, url)

                # Limit to max_pages - 1 (main page already checked)
                links_to_check = internal_links[: debug_input.max_pages - 1]

                for link in links_to_check:
                    try:
                        page_result = await check_page(
                            link, client, debug_input.follow_redirects
                        )
                        pages.append(page_result)
                    except Exception as e:
                        pages.append(
                            PageResult(
                                url=link,
                                status_code=0,
                                checks=[
                                    SEOCheck(
                                        name="connectivity",
                                        status="fail",
                                        message=f"Error checking page: {str(e)}",
                                    )
                                ],
                            )
                        )
            except Exception:
                pass  # Failed to extract links, continue with just the main page

        # 3. Check sitemap
        if debug_input.check_sitemap:
            try:
                sitemap_result = await check_sitemap(url, client)
            except Exception as e:
                sitemap_result = SitemapResult(
                    found=False,
                    url=url + "/sitemap.xml",
                    issues=[f"Error checking sitemap: {str(e)}"],
                )

        # 4. Check robots.txt
        try:
            robots_result = await check_robots(url, client)
        except Exception as e:
            robots_result = RobotsResult(
                found=False,
                issues=[f"Error checking robots.txt: {str(e)}"],
            )

    # 5. Build report
    report = DebugReport(
        url=url,
        scan_time=scan_time,
        pages=pages,
        sitemap=sitemap_result,
        robots=robots_result,
        overall_score=0,
        critical_issues=[],
        recommendations=[],
    )

    # 6. Calculate score and generate recommendations
    report.overall_score = calculate_score(report)
    report.recommendations = generate_recommendations(report)

    # 7. Collect critical issues
    critical: list[str] = []
    for page in pages:
        for check in page.checks:
            if check.status == "fail":
                critical.append(f"[{page.url}] {check.name}: {check.message}")
    if not robots_result.allows_googlebot:
        critical.insert(0, "robots.txt is blocking Googlebot from the entire site")
    report.critical_issues = critical

    return report


def main() -> int:
    """Main entry point.

    Reads DebugInput from stdin, runs all checks, outputs DebugReport as JSON to stdout.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    # Read input from stdin
    try:
        input_data = sys.stdin.read()
        if input_data.strip():
            debug_input = DebugInput.model_validate_json(input_data)
        else:
            # No input provided
            error_result = {
                "error": "No input provided. Please provide a JSON object with a 'url' field.",
                "expected_format": {
                    "url": "https://example.com",
                    "check_sitemap": True,
                    "follow_redirects": True,
                    "max_pages": 10,
                },
            }
            print(json.dumps(error_result), file=sys.stdout)
            return 1
    except Exception as e:
        error_result = {
            "error": f"Failed to parse input: {str(e)}",
            "expected_format": {
                "url": "https://example.com",
                "check_sitemap": True,
                "follow_redirects": True,
                "max_pages": 10,
            },
        }
        print(json.dumps(error_result), file=sys.stdout)
        return 1

    # Run the debug scan
    try:
        report = asyncio.run(run_debug(debug_input))
        print(report.model_dump_json(indent=2))
        return 0
    except Exception as e:
        error_result = {
            "error": f"Scan failed: {str(e)}",
            "url": debug_input.url,
        }
        print(json.dumps(error_result), file=sys.stdout)
        return 1


if __name__ == "__main__":
    sys.exit(main())
