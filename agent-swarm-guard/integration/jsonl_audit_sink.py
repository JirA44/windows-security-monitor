"""Minimal application hook that emits privacy-minimized agent tool events.

Set AGENT_SWARM_HMAC_KEY to a high-entropy secret of at least 32 bytes.
Protect the output file with host ACLs and rotate it using your log policy.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


_LOCK = threading.Lock()


def _label(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if len(value) > 256 or any(ch in value for ch in "\r\n\0"):
        raise ValueError(f"{field} is too long or contains a control character")
    return value.strip()


class JsonlAuditSink:
    """Append tool authorization decisions in the detector's normalized schema."""

    def __init__(self, path: str | Path, hmac_key: str | None = None) -> None:
        raw_key = hmac_key or os.environ.get("AGENT_SWARM_HMAC_KEY", "")
        if len(raw_key.encode("utf-8")) < 32:
            raise ValueError("AGENT_SWARM_HMAC_KEY must contain at least 32 bytes")
        self.path = Path(path)
        self._key = raw_key.encode("utf-8")

    def _pseudonym(self, namespace: str, value: str) -> str:
        message = f"{namespace}\0{_label(value, namespace)}".encode("utf-8")
        digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest[:24]}"

    def tool_decision(
        self,
        *,
        actor_id: str,
        session_id: str,
        target: str,
        tool_name: str,
        allowed: bool,
        sensitive: bool = False,
    ) -> None:
        """Record one policy decision; never accepts or stores prompt contents."""
        if not isinstance(allowed, bool) or not isinstance(sensitive, bool):
            raise ValueError("allowed and sensitive must be booleans")
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "target": _label(target, "target"),
            "actor_id": self._pseudonym("actor", actor_id),
            "session_id": self._pseudonym("session", session_id),
            "action": "tool_call",
            "outcome": "allowed" if allowed else "denied",
            "tool_name": _label(tool_name, "tool_name"),
            "tool_allowed": allowed,
            "sensitive": sensitive,
            "bytes_read": 0,
        }
        line = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_APPEND avoids overwriting prior events. The lock serializes writers in this process.
        # On Windows, enforce the log ACL separately; the POSIX mode argument is not an ACL.
        with _LOCK:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)

