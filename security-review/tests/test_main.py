"""Tests for security-review main API and scanners."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

from httpx import AsyncClient, ASGITransport

from security_review.main import app
from security_review.models import (
    FindingsCollection,
    SecretFinding,
    DependencyFinding,
    PatternFinding,
    ReviewSummary,
    ReviewResponse,
)
from security_review.scanners.frontend import scan_frontend_patterns, scan_file as scan_frontend_file
from security_review.scanners.api import scan_api_patterns, scan_file as scan_api_file
from security_review.scanners.logging import scan_logging_patterns
from security_review.recommendations import generate_recommendations


@pytest.fixture
def test_client():
    """Create async test client for FastAPI."""
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestHealthEndpoint:
    """Test /health endpoint."""

    async def test_health_returns_ok(self, test_client):
        """Test that /health endpoint returns status ok."""
        async with test_client as client:
            response = await client.get("/health")

            assert response.status_code == 200
            assert response.json() == {"status": "ok"}


class TestReviewEndpoint:
    """Test /review endpoint."""

    async def test_review_with_mocked_agent_calls(self, test_client):
        """Test /review endpoint with mocked agent calls."""
        # Mock responses from external agents
        mock_leak_finder_response = {
            "scan_id": "leak-123",
            "findings": [
                {
                    "type": "aws_access_key",
                    "severity": "critical",
                    "file": "config.py",
                    "line": 10,
                    "preview": "AKIA***REDACTED***",
                    "recommendation": "Rotate the key",
                }
            ],
            "history_findings": [],
        }
        mock_dep_scanner_response = {
            "scan_id": "dep-456",
            "findings": [
                {
                    "package": "requests",
                    "version": "2.25.0",
                    "severity": "high",
                    "cve": "CVE-2023-32681",
                    "title": "Proxy header leak",
                    "fixed_in": "2.31.0",
                    "recommendation": "pip install --upgrade requests",
                }
            ],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        }

        with patch("security_review.main.AgentClient") as MockClient:
            # Setup mock client
            mock_client_instance = AsyncMock()
            mock_client_instance.call_leak_finder = AsyncMock(
                return_value=mock_leak_finder_response
            )
            mock_client_instance.call_dep_scanner = AsyncMock(
                return_value=mock_dep_scanner_response
            )
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            # Mock cloned_repo to avoid actual git clone
            with patch("security_review.main.cloned_repo") as mock_cloned_repo:
                mock_cloned_repo.return_value.__enter__ = MagicMock(return_value="/tmp/fake_repo")
                mock_cloned_repo.return_value.__exit__ = MagicMock(return_value=None)

                # Mock pattern scanners
                with patch("security_review.main.scan_frontend_patterns", return_value=[]):
                    with patch("security_review.main.scan_api_patterns", return_value=[]):
                        with patch("security_review.main.scan_logging_patterns", return_value=[]):
                            async with test_client as client:
                                response = await client.post(
                                    "/review",
                                    json={"repo_url": "https://github.com/example/repo.git"},
                                )

                                assert response.status_code == 200
                                data = response.json()
                                assert "scan_id" in data
                                assert "findings" in data
                                assert "summary" in data
                                # Should have findings from leak-finder
                                assert len(data["findings"]["secrets"]) == 1
                                assert data["findings"]["secrets"][0]["type"] == "aws_access_key"
                                # Should have findings from dep-scanner
                                assert len(data["findings"]["dependencies"]) == 1
                                assert data["findings"]["dependencies"][0]["package"] == "requests"

    async def test_review_secrets_only_mode(self, test_client):
        """Test /review endpoint with secrets-only scan mode."""
        mock_leak_finder_response = {
            "findings": [
                {
                    "type": "github_token",
                    "severity": "critical",
                    "file": ".env",
                    "line": 1,
                    "preview": "ghp_***",
                    "recommendation": "Rotate token",
                }
            ],
            "history_findings": [],
        }

        with patch("security_review.main.AgentClient") as MockClient:
            mock_client_instance = AsyncMock()
            mock_client_instance.call_leak_finder = AsyncMock(
                return_value=mock_leak_finder_response
            )
            # dep_scanner should NOT be called in secrets-only mode
            mock_client_instance.call_dep_scanner = AsyncMock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            async with test_client as client:
                response = await client.post(
                    "/review",
                    json={
                        "repo_url": "https://github.com/example/repo.git",
                        "scan_mode": "secrets-only",
                    },
                )

                assert response.status_code == 200
                data = response.json()
                assert len(data["findings"]["secrets"]) == 1
                # No dependencies should be scanned
                assert len(data["findings"]["dependencies"]) == 0
                # dep_scanner should not have been called
                mock_client_instance.call_dep_scanner.assert_not_called()

    async def test_review_patterns_only_mode(self, test_client):
        """Test /review endpoint with patterns-only scan mode."""
        mock_pattern_findings = [
            PatternFinding(
                category="frontend_security",
                pattern="supabase_client_in_component",
                severity="high",
                file="components/Auth.tsx",
                line=5,
                snippet="import { createClient } from '@supabase/supabase-js'",
                recommendation="Move Supabase calls to server-side",
            )
        ]

        with patch("security_review.main.AgentClient") as MockClient:
            mock_client_instance = AsyncMock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            with patch("security_review.main.cloned_repo") as mock_cloned_repo:
                mock_cloned_repo.return_value.__enter__ = MagicMock(return_value="/tmp/fake_repo")
                mock_cloned_repo.return_value.__exit__ = MagicMock(return_value=None)

                with patch(
                    "security_review.main.scan_frontend_patterns",
                    return_value=mock_pattern_findings,
                ):
                    with patch("security_review.main.scan_api_patterns", return_value=[]):
                        with patch("security_review.main.scan_logging_patterns", return_value=[]):
                            async with test_client as client:
                                response = await client.post(
                                    "/review",
                                    json={
                                        "repo_url": "https://github.com/example/repo.git",
                                        "scan_mode": "patterns-only",
                                    },
                                )

                                assert response.status_code == 200
                                data = response.json()
                                # No secrets or deps in patterns-only mode
                                assert len(data["findings"]["secrets"]) == 0
                                assert len(data["findings"]["dependencies"]) == 0
                                # Should have pattern findings
                                assert len(data["findings"]["frontend_security"]) == 1
                                assert (
                                    data["findings"]["frontend_security"][0]["pattern"]
                                    == "supabase_client_in_component"
                                )

    async def test_review_with_agent_failure(self, test_client):
        """Test /review handles agent call failures gracefully."""
        with patch("security_review.main.AgentClient") as MockClient:
            mock_client_instance = AsyncMock()
            # Simulate leak-finder failing
            mock_client_instance.call_leak_finder = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            mock_client_instance.call_dep_scanner = AsyncMock(return_value={"findings": []})
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            with patch("security_review.main.cloned_repo") as mock_cloned_repo:
                mock_cloned_repo.return_value.__enter__ = MagicMock(return_value="/tmp/fake_repo")
                mock_cloned_repo.return_value.__exit__ = MagicMock(return_value=None)

                with patch("security_review.main.scan_frontend_patterns", return_value=[]):
                    with patch("security_review.main.scan_api_patterns", return_value=[]):
                        with patch("security_review.main.scan_logging_patterns", return_value=[]):
                            async with test_client as client:
                                response = await client.post(
                                    "/review",
                                    json={"repo_url": "https://github.com/example/repo.git"},
                                )

                                # Should still return 200, just with empty secrets
                                assert response.status_code == 200
                                data = response.json()
                                assert len(data["findings"]["secrets"]) == 0

    async def test_review_with_invalid_repo(self, test_client):
        """Test /review with invalid repository URL returns 400."""
        from git.exc import GitCommandError

        with patch("security_review.main.AgentClient") as MockClient:
            mock_client_instance = AsyncMock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            with patch("security_review.main.cloned_repo") as mock_cloned_repo:
                mock_cloned_repo.return_value.__enter__ = MagicMock(
                    side_effect=GitCommandError("git clone", 128)
                )

                async with test_client as client:
                    response = await client.post(
                        "/review",
                        json={
                            "repo_url": "https://github.com/invalid/repo.git",
                            "scan_mode": "patterns-only",
                        },
                    )

                    assert response.status_code == 400
                    assert "Failed to clone repository" in response.json()["detail"]


class TestFrontendPatternScanner:
    """Test frontend security pattern scanner."""

    def test_detects_supabase_client_in_component(self, temp_dir):
        """Test detection of Supabase client usage in frontend components."""
        components_dir = temp_dir / "src" / "components"
        components_dir.mkdir(parents=True)

        test_file = components_dir / "Auth.tsx"
        test_file.write_text("""
import { createClient } from '@supabase/supabase-js';

export function Auth() {
    const supabase = createClient('url', 'key');
    return <div>Auth Component</div>;
}
""")

        findings = scan_frontend_patterns(temp_dir)

        assert len(findings) >= 1
        supabase_findings = [f for f in findings if "supabase" in f.pattern]
        assert len(supabase_findings) >= 1
        assert supabase_findings[0].severity == "high"

    def test_detects_localstorage_auth_token(self, temp_dir):
        """Test detection of localStorage auth token pattern."""
        src_dir = temp_dir / "src" / "hooks"
        src_dir.mkdir(parents=True)

        test_file = src_dir / "useAuth.tsx"
        test_file.write_text("""
export function useAuth() {
    const token = localStorage.getItem('accessToken');
    return { token };
}
""")

        findings = scan_frontend_patterns(temp_dir)

        assert len(findings) >= 1
        localstorage_findings = [f for f in findings if "localstorage" in f.pattern.lower()]
        assert len(localstorage_findings) >= 1

    def test_detects_client_side_premium_check(self, temp_dir):
        """Test detection of client-side premium checks."""
        pages_dir = temp_dir / "src" / "pages"
        pages_dir.mkdir(parents=True)

        test_file = pages_dir / "Premium.tsx"
        test_file.write_text("""
export function PremiumPage({ user }) {
    if (user.isPremium) {
        return <div>Premium Content</div>;
    }
    return <div>Upgrade to access</div>;
}
""")

        findings = scan_frontend_patterns(temp_dir)

        assert len(findings) >= 1
        premium_findings = [f for f in findings if "premium" in f.pattern.lower()]
        assert len(premium_findings) >= 1
        assert premium_findings[0].severity == "high"

    def test_skips_backend_files(self, temp_dir):
        """Test that backend API files are skipped."""
        api_dir = temp_dir / "src" / "api"
        api_dir.mkdir(parents=True)

        # This is in /api/ path so should be skipped
        test_file = api_dir / "auth.ts"
        test_file.write_text("""
import { createClient } from '@supabase/supabase-js';

export async function handler() {
    const supabase = createClient(process.env.URL, process.env.KEY);
    return supabase.auth.getUser();
}
""")

        findings = scan_frontend_patterns(temp_dir)

        # Should have no findings since it's in /api/ directory
        assert len(findings) == 0

    def test_handles_nonexistent_directory(self):
        """Test scanner handles nonexistent directory gracefully."""
        findings = scan_frontend_patterns("/nonexistent/path")
        assert findings == []


class TestApiPatternScanner:
    """Test API security pattern scanner."""

    def test_detects_fastapi_missing_auth(self, temp_dir):
        """Test detection of FastAPI routes without authentication."""
        routes_dir = temp_dir / "api" / "routes"
        routes_dir.mkdir(parents=True)

        test_file = routes_dir / "users.py"
        test_file.write_text("""
from fastapi import APIRouter

router = APIRouter()

@router.get("/users")
async def get_users():
    return {"users": []}

@router.post("/users")
async def create_user(data: dict):
    return {"id": 1}
""")

        findings = scan_api_patterns(temp_dir)

        assert len(findings) >= 1
        auth_findings = [f for f in findings if "missing_auth" in f.pattern.lower()]
        assert len(auth_findings) >= 2

    def test_ignores_health_endpoints(self, temp_dir):
        """Test that health check endpoints don't trigger missing auth warnings."""
        api_dir = temp_dir / "api"
        api_dir.mkdir(parents=True)

        test_file = api_dir / "main.py"
        test_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/ping")
async def ping():
    return "pong"
""")

        findings = scan_api_patterns(temp_dir)

        # Health/ping endpoints should not trigger missing auth warnings
        auth_findings = [f for f in findings if "missing_auth" in f.pattern.lower()]
        assert len(auth_findings) == 0

    def test_detects_missing_rate_limiter(self, temp_dir):
        """Test detection of missing rate limiter in API entry points."""
        api_dir = temp_dir / "api"
        api_dir.mkdir(parents=True)

        test_file = api_dir / "main.py"
        test_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok"}
""")

        findings = scan_api_patterns(temp_dir)

        rate_limit_findings = [f for f in findings if "rate_limiter" in f.pattern.lower()]
        assert len(rate_limit_findings) >= 1
        assert rate_limit_findings[0].severity == "medium"

    def test_detects_express_missing_auth(self, temp_dir):
        """Test detection of Express routes without authentication middleware."""
        routes_dir = temp_dir / "routes"
        routes_dir.mkdir(parents=True)

        test_file = routes_dir / "api.js"
        test_file.write_text("""
const express = require('express');
const router = express.Router();

router.get('/users', (req, res) => {
    res.json({ users: [] });
});

router.post('/users', (req, res) => {
    res.json({ id: 1 });
});

module.exports = router;
""")

        findings = scan_api_patterns(temp_dir)

        auth_findings = [f for f in findings if "express_missing_auth" in f.pattern.lower()]
        assert len(auth_findings) >= 2

    def test_skips_test_files(self, temp_dir):
        """Test that test files are skipped."""
        tests_dir = temp_dir / "tests"
        tests_dir.mkdir(parents=True)

        test_file = tests_dir / "test_api.py"
        test_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/test-endpoint")
async def test_endpoint():
    return {"test": True}
""")

        findings = scan_api_patterns(temp_dir)

        # Should have no findings since it's in /tests/ directory
        assert len(findings) == 0


class TestLoggingPatternScanner:
    """Test logging security pattern scanner."""

    def test_detects_console_log_password(self, temp_dir):
        """Test detection of password logging in JavaScript."""
        src_dir = temp_dir / "src"
        src_dir.mkdir(parents=True)

        test_file = src_dir / "auth.js"
        test_file.write_text("""
function login(username, password) {
    console.log('Logging in with password:', password);
    return authenticate(username, password);
}
""")

        findings = scan_logging_patterns(temp_dir)

        assert len(findings) >= 1
        password_findings = [f for f in findings if "password" in f.pattern.lower()]
        assert len(password_findings) >= 1
        assert password_findings[0].severity == "high"

    def test_detects_python_logger_secret(self, temp_dir):
        """Test detection of secret logging in Python."""
        src_dir = temp_dir / "src"
        src_dir.mkdir(parents=True)

        test_file = src_dir / "service.py"
        test_file.write_text("""
import logging

logger = logging.getLogger(__name__)

def call_api(api_key):
    logger.info(f"Calling API with key: {api_key}")
    return make_request(api_key)
""")

        findings = scan_logging_patterns(temp_dir)

        assert len(findings) >= 1
        secret_findings = [f for f in findings if "secret" in f.pattern.lower()]
        assert len(secret_findings) >= 1

    def test_detects_stack_trace_in_response(self, temp_dir):
        """Test detection of stack trace exposed in API response."""
        api_dir = temp_dir / "api"
        api_dir.mkdir(parents=True)

        test_file = api_dir / "handler.js"
        test_file.write_text("""
app.get('/data', (req, res) => {
    try {
        const data = getData();
        res.json(data);
    } catch (err) {
        res.json({ error: err.stack });
    }
});
""")

        findings = scan_logging_patterns(temp_dir)

        stack_findings = [f for f in findings if "stack" in f.pattern.lower()]
        assert len(stack_findings) >= 1
        assert stack_findings[0].severity == "high"

    def test_lowers_severity_for_test_files(self, temp_dir):
        """Test that severity is lowered for findings in test files."""
        tests_dir = temp_dir / "tests"
        tests_dir.mkdir(parents=True)

        test_file = tests_dir / "test_auth.py"
        test_file.write_text("""
def test_login():
    password = "test123"
    print(f"Testing with password: {password}")
    assert login("user", password)
""")

        findings = scan_logging_patterns(temp_dir)

        assert len(findings) >= 1
        # Severity should be lowered to "low" for test files
        assert all(f.severity == "low" for f in findings)

    def test_detects_fastapi_exception_detail(self, temp_dir):
        """Test detection of exception details in FastAPI HTTPException."""
        api_dir = temp_dir / "api"
        api_dir.mkdir(parents=True)

        test_file = api_dir / "endpoints.py"
        test_file.write_text("""
from fastapi import HTTPException

async def get_data():
    try:
        return fetch_data()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
""")

        findings = scan_logging_patterns(temp_dir)

        exception_findings = [f for f in findings if "exception" in f.pattern.lower()]
        assert len(exception_findings) >= 1


class TestRecommendationGeneration:
    """Test recommendation generation logic."""

    def test_generates_secret_recommendations(self):
        """Test that secret findings generate appropriate recommendations."""
        findings = FindingsCollection(
            secrets=[
                SecretFinding(
                    type="aws_access_key",
                    severity="critical",
                    file="config.py",
                    line=10,
                    preview="AKIA***",
                    recommendation="",
                ),
                SecretFinding(
                    type="aws_access_key",
                    severity="critical",
                    file=".env",
                    line=2,
                    preview="AKIA***",
                    recommendation="",
                ),
            ]
        )

        recommendations = generate_recommendations(findings)

        assert len(recommendations) >= 1
        assert any("AWS" in rec.lower() or "access key" in rec.lower() for rec in recommendations)

    def test_generates_dependency_recommendations(self):
        """Test that dependency findings generate appropriate recommendations."""
        findings = FindingsCollection(
            dependencies=[
                DependencyFinding(
                    package="requests",
                    version="2.25.0",
                    severity="high",
                    cve="CVE-2023-32681",
                    title="Proxy header leak",
                    fixed_in="2.31.0",
                    recommendation="",
                ),
            ]
        )

        recommendations = generate_recommendations(findings)

        assert len(recommendations) >= 1
        assert any("high" in rec.lower() or "update" in rec.lower() for rec in recommendations)

    def test_generates_pattern_recommendations(self):
        """Test that pattern findings generate appropriate recommendations."""
        findings = FindingsCollection(
            api_security=[
                PatternFinding(
                    category="api_security",
                    pattern="fastapi_missing_auth",
                    severity="high",
                    file="api/users.py",
                    line=10,
                    snippet="@app.get('/users')",
                    recommendation="",
                ),
                PatternFinding(
                    category="api_security",
                    pattern="fastapi_missing_auth",
                    severity="high",
                    file="api/users.py",
                    line=15,
                    snippet="@app.post('/users')",
                    recommendation="",
                ),
            ]
        )

        recommendations = generate_recommendations(findings)

        assert len(recommendations) >= 1

    def test_returns_empty_for_no_findings(self):
        """Test that empty findings return empty recommendations."""
        findings = FindingsCollection()

        recommendations = generate_recommendations(findings)

        assert recommendations == []

    def test_respects_max_recommendations(self):
        """Test that max_recommendations is respected."""
        findings = FindingsCollection(
            secrets=[
                SecretFinding(
                    type="aws_access_key", severity="critical", file="a.py", line=1, preview="", recommendation=""
                ),
                SecretFinding(
                    type="github_token", severity="critical", file="b.py", line=1, preview="", recommendation=""
                ),
                SecretFinding(
                    type="openai_api_key", severity="critical", file="c.py", line=1, preview="", recommendation=""
                ),
                SecretFinding(
                    type="stripe_key", severity="critical", file="d.py", line=1, preview="", recommendation=""
                ),
            ]
        )

        recommendations = generate_recommendations(findings, max_recommendations=2)

        assert len(recommendations) <= 2


class TestSummaryCalculation:
    """Test summary calculation from findings."""

    async def test_calculates_correct_summary(self, test_client):
        """Test that summary correctly counts findings by severity."""
        mock_findings = FindingsCollection(
            secrets=[
                SecretFinding(
                    type="aws_key", severity="critical", file="a.py", line=1, preview="", recommendation=""
                )
            ],
            dependencies=[
                DependencyFinding(
                    package="pkg", version="1.0", severity="high", cve="", title="", fixed_in="", recommendation=""
                )
            ],
            frontend_security=[
                PatternFinding(
                    category="frontend", pattern="test", severity="medium", file="b.tsx", line=1, snippet="", recommendation=""
                )
            ],
            logging=[
                PatternFinding(
                    category="logging", pattern="test", severity="low", file="c.py", line=1, snippet="", recommendation=""
                )
            ],
        )

        # Test the _calculate_summary function directly
        from security_review.main import _calculate_summary

        summary = _calculate_summary(mock_findings)

        assert summary.critical == 1
        assert summary.high == 1
        assert summary.medium == 1
        assert summary.low == 1
