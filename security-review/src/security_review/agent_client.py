"""Client for calling other OrchAgent agents."""

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class AgentClient:
    """HTTP client for calling OrchAgent agents.

    This client is used by orchestrator agents to call their dependencies.
    The base URL can be configured via ORCHAGENT_API_URL environment variable.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 60.0,
        service_key: str | None = None,
    ):
        """Initialize the agent client.

        Args:
            base_url: Base URL for the OrchAgent API. Defaults to ORCHAGENT_API_URL
                      env var or http://localhost:8000.
            timeout: Request timeout in seconds.
            service_key: Service key for authentication. Defaults to ORCHAGENT_SERVICE_KEY
                         env var.
        """
        self.base_url = base_url or os.environ.get(
            "ORCHAGENT_API_URL", "http://localhost:8000"
        )
        self.timeout = timeout
        self.service_key = service_key or os.environ.get("ORCHAGENT_SERVICE_KEY")
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AgentClient":
        """Enter async context."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def call_agent(
        self,
        agent_name: str,
        endpoint: str,
        payload: dict[str, Any],
        version: str = "v1",
    ) -> dict[str, Any]:
        """Call an OrchAgent agent endpoint.

        Args:
            agent_name: Name of the agent to call (e.g., "leak-finder").
            endpoint: Endpoint to call (e.g., "scan").
            payload: Request payload.
            version: Agent version (e.g., "v1").

        Returns:
            Response JSON from the agent.

        Raises:
            httpx.HTTPStatusError: If the request fails.
        """
        if not self._client:
            raise RuntimeError("AgentClient must be used as an async context manager")

        # OrchAgent API URL pattern: /{agent-name}/{version}/{endpoint}/
        # Trailing slash required to avoid 307 redirects that httpx won't follow for POST
        url = f"/{agent_name}/{version}/{endpoint}/"

        logger.info(f"Calling agent: {agent_name}/{version}/{endpoint}")

        # Build headers with authentication
        headers: dict[str, str] = {}
        if self.service_key:
            headers["Authorization"] = f"Bearer {self.service_key}"

        response = await self._client.post(url, json=payload, headers=headers)
        response.raise_for_status()

        return response.json()

    async def call_leak_finder(
        self,
        repo_url: str | None = None,
        path: str | None = None,
    ) -> dict[str, Any]:
        """Call the leak-finder agent to scan for secrets.

        Args:
            repo_url: URL of the git repository to scan (use this OR path).
            path: Local directory path to scan (use this OR repo_url).

        Returns:
            Scan results from leak-finder.
        """
        payload: dict[str, Any] = {}
        if repo_url:
            payload["repo_url"] = repo_url
        if path:
            payload["path"] = path

        return await self.call_agent(
            agent_name="leak-finder",
            endpoint="scan",
            payload=payload,
        )

    async def call_dep_scanner(
        self,
        repo_url: str | None = None,
        path: str | None = None,
        severity_threshold: str = "low",
    ) -> dict[str, Any]:
        """Call the dep-scanner agent to scan for vulnerabilities.

        Args:
            repo_url: URL of the git repository to scan (use this OR path).
            path: Local directory path to scan (use this OR repo_url).
            severity_threshold: Minimum severity to include.

        Returns:
            Scan results from dep-scanner.
        """
        payload: dict[str, Any] = {"severity_threshold": severity_threshold}
        if repo_url:
            payload["repo_url"] = repo_url
        if path:
            payload["path"] = path

        return await self.call_agent(
            agent_name="dep-scanner",
            endpoint="scan",
            payload=payload,
        )
