"""Authenticated HTTP client wrapper for GODRECON."""
from __future__ import annotations
from typing import Any, Dict, Optional
from godrecon.core.config import AuthConfig
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class AuthenticatedClient:
    """Wraps AsyncHTTPClient with authentication support."""

    def __init__(self, http: AsyncHTTPClient, auth_config: Optional[AuthConfig] = None) -> None:
        self.http = http
        self.auth = auth_config
        self._session_cookies: Dict[str, str] = {}
        if auth_config and auth_config.cookies:
            self._session_cookies.update(auth_config.cookies)

    def _build_headers(self, extra_headers: Optional[Dict] = None) -> Dict[str, str]:
        """Build auth headers."""
        headers: Dict[str, str] = {}
        if self.auth:
            if self.auth.bearer_token:
                headers["Authorization"] = f"Bearer {self.auth.bearer_token}"
            if self.auth.api_key:
                headers[self.auth.api_key_header] = self.auth.api_key
            headers.update(self.auth.headers)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def get(self, url: str, **kwargs: Any) -> Any:
        headers = self._build_headers(kwargs.pop("headers", None))
        cookies = {**self._session_cookies, **kwargs.pop("cookies", {})}
        return await self.http.get(url, headers=headers, cookies=cookies, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Any:
        headers = self._build_headers(kwargs.pop("headers", None))
        cookies = {**self._session_cookies, **kwargs.pop("cookies", {})}
        return await self.http.post(url, headers=headers, cookies=cookies, **kwargs)

    async def perform_login(self) -> bool:
        """Perform login and store session cookies."""
        if not self.auth or not self.auth.login_url or not self.auth.login_data:
            return False
        try:
            resp = await self.http.post(self.auth.login_url, data=self.auth.login_data)
            if resp and resp.get("cookies"):
                self._session_cookies.update(resp["cookies"])
                logger.info("Login successful, stored %d session cookies", len(resp["cookies"]))
                return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Login failed: %s", exc)
        return False
