"""Real-time collaboration module — WebSocket-based live sharing of scan results."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Set

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult


class CollaborationModule(BaseModule):
    """WebSocket-based real-time collaboration for scan results."""

    name = "collaboration"
    description = "Real-time collaboration via WebSocket — shared findings dashboard"
    version = "1.0.0"
    category = "collaboration"

    def __init__(self) -> None:
        super().__init__()
        self._clients: Set[Any] = set()
        self._findings: List[Dict[str, Any]] = []
        self._claimed: Dict[str, str] = {}  # finding_id -> user

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        cfg = config.collaboration_config
        if not cfg.enabled:
            return ModuleResult(
                module_name=self.name,
                target=target,
                findings=[Finding(
                    title="Collaboration: Disabled",
                    description="Set collaboration_config.enabled=true to start WebSocket server.",
                    severity="info",
                    tags=["collaboration"],
                )],
            )
        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=[Finding(
                title="Collaboration Server Ready",
                description=(
                    f"WebSocket server configured at ws://{cfg.host}:{cfg.port} — "
                    "call start_server() to begin broadcasting findings."
                ),
                severity="info",
                tags=["collaboration"],
                data={"host": cfg.host, "port": cfg.port},
            )],
        )

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast a message to all connected WebSocket clients."""
        if not self._clients:
            return
        data = json.dumps(message)
        await asyncio.gather(
            *[self._safe_send(client, data) for client in list(self._clients)],
            return_exceptions=True,
        )

    async def _safe_send(self, client: Any, data: str) -> None:
        try:
            await client.send(data)
        except Exception:  # noqa: BLE001
            self._clients.discard(client)

    def claim_finding(self, finding_id: str, user: str) -> bool:
        """Claim a finding for a specific user."""
        if finding_id in self._claimed:
            return False
        self._claimed[finding_id] = user
        return True

    async def add_finding(self, finding: Finding, user: str = "system") -> None:
        """Add a finding and broadcast it to all clients."""
        finding_dict = {
            "title": finding.title,
            "severity": finding.severity,
            "description": finding.description,
            "tags": finding.tags,
            "user": user,
        }
        self._findings.append(finding_dict)
        await self.broadcast({"type": "new_finding", "data": finding_dict})

    async def start_server(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        """Start the WebSocket server (requires websockets package)."""
        try:
            import websockets  # type: ignore

            async def handler(websocket: Any, path: str) -> None:
                self._clients.add(websocket)
                try:
                    # Send existing findings on connect
                    await websocket.send(json.dumps({
                        "type": "init",
                        "findings": self._findings,
                    }))
                    async for message in websocket:
                        data = json.loads(message)
                        if data.get("type") == "claim":
                            fid = data.get("finding_id", "")
                            usr = data.get("user", "anonymous")
                            success = self.claim_finding(fid, usr)
                            await websocket.send(json.dumps({
                                "type": "claim_response",
                                "success": success,
                                "finding_id": fid,
                            }))
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    self._clients.discard(websocket)

            self.logger.info("Starting collaboration server at ws://%s:%d", host, port)
            async with websockets.serve(handler, host, port):
                await asyncio.Future()  # run forever
        except ImportError:
            self.logger.warning("websockets package not installed; collaboration server unavailable")
