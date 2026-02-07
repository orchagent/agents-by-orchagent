"""Pydantic models for the Next.js SEO debugger."""

from datetime import datetime
from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, Field


class DebugInput(BaseModel):
    """Input parameters for the SEO debug scan."""

    url: str = Field(..., description="URL of the Next.js site to debug")
    check_sitemap: bool = Field(default=True, description="Whether to check sitemap.xml")
    follow_redirects: bool = Field(
        default=True, description="Whether to follow and report redirect chains"
    )
    max_pages: int = Field(
        default=10, ge=1, le=50, description="Maximum number of internal pages to check"
    )


class CheckStatus(str, Enum):
    """Status of an individual SEO check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"


class SEOCheck(BaseModel):
    """Result of a single SEO check."""

    name: str
    status: CheckStatus
    message: str
    details: Optional[str] = None
    fix: Optional[str] = None


class RedirectHop(BaseModel):
    """A single hop in a redirect chain."""

    url: str
    status_code: int
    location: Optional[str] = None


class RedirectChain(BaseModel):
    """Full redirect chain for a URL."""

    hops: list[RedirectHop] = Field(default_factory=list)
    final_url: str
    is_problematic: bool = False
    issue: Optional[str] = None


class PageResult(BaseModel):
    """SEO analysis result for a single page."""

    url: str
    status_code: int
    title: Optional[str] = None
    meta_description: Optional[str] = None
    canonical: Optional[str] = None
    og_tags: dict[str, str] = Field(default_factory=dict)
    checks: list[SEOCheck] = Field(default_factory=list)
    redirect_chain: Optional[RedirectChain] = None


class SitemapResult(BaseModel):
    """Result of sitemap.xml analysis."""

    found: bool = False
    url: str = ""
    page_count: int = 0
    issues: list[str] = Field(default_factory=list)


class RobotsResult(BaseModel):
    """Result of robots.txt analysis."""

    found: bool = False
    allows_googlebot: bool = True
    sitemap_referenced: bool = False
    issues: list[str] = Field(default_factory=list)


class DebugReport(BaseModel):
    """Complete SEO debug report."""

    url: str
    scan_time: Union[str, datetime]
    pages: list[PageResult] = Field(default_factory=list)
    sitemap: SitemapResult = Field(default_factory=SitemapResult)
    robots: RobotsResult = Field(default_factory=RobotsResult)
    overall_score: int = Field(default=0, ge=0, le=100)
    critical_issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
