#!/usr/bin/env python3
"""Observation-only correlation of normalized AI-agent security events."""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED = ("timestamp", "target", "actor_id", "session_id", "action", "outcome")
FAILURES = {"denied", "failed", "not_found"}


class InputError(ValueError):
    pass


def parse_timestamp(value: Any, line_no: int) -> datetime:
    if not isinstance(value, str):
        raise InputError(f"line {line_no}: timestamp must be an ISO-8601 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(f"line {line_no}: invalid timestamp") from exc
    if dt.tzinfo is None:
        raise InputError(f"line {line_no}: timestamp must include a timezone")
    return dt.astimezone(timezone.utc)


def load_events(stream: Any) -> list[dict[str, Any]]:
    events = []
    for line_no, raw in enumerate(stream, 1):
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise InputError(f"line {line_no}: invalid JSON") from exc
        if not isinstance(event, dict):
            raise InputError(f"line {line_no}: event must be a JSON object")
        missing = [key for key in REQUIRED if key not in event]
        if missing:
            raise InputError(f"line {line_no}: missing required field(s): {', '.join(missing)}")
        for key in ("target", "actor_id", "session_id", "action", "outcome"):
            if not isinstance(event[key], str) or not event[key].strip():
                raise InputError(f"line {line_no}: {key} must be a non-empty string")
        event["_time"] = parse_timestamp(event["timestamp"], line_no)
        amount = event.get("bytes_read", 0)
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise InputError(f"line {line_no}: bytes_read must be a non-negative integer")
        if "sensitive" in event and not isinstance(event["sensitive"], bool):
            raise InputError(f"line {line_no}: sensitive must be boolean")
        if "tool_allowed" in event and not isinstance(event["tool_allowed"], bool):
            raise InputError(f"line {line_no}: tool_allowed must be boolean")
        events.append(event)
    return events


def validate_config(config: Any) -> dict[str, int]:
    if not isinstance(config, dict):
        raise InputError("configuration must be a JSON object")
    keys = ("window_seconds", "burst_min_events", "burst_min_actors", "failure_min_events",
            "failure_min_count", "failure_min_ratio_percent", "sensitive_min_events",
            "bulk_read_bytes")
    result = {}
    for key in keys:
        value = config.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise InputError(f"configuration field {key} must be a positive integer")
        result[key] = value
    if result["failure_min_ratio_percent"] > 100:
        raise InputError("failure_min_ratio_percent must be between 1 and 100")
    return result


def _alert(rule: str, severity: str, target: str, bucket: list[dict[str, Any]], evidence: dict[str, Any], recommendation: str) -> dict[str, Any]:
    # Actor/session identifiers are truncated to limit accidental disclosure in downstream alerting.
    actors = sorted({e["actor_id"] for e in bucket})
    sessions = sorted({e["session_id"] for e in bucket})
    start = min(e["_time"] for e in bucket)
    end = max(e["_time"] for e in bucket)
    return {
        "rule": rule,
        "severity": severity,
        "target": target,
        "window_start": start.isoformat().replace("+00:00", "Z"),
        "window_end": end.isoformat().replace("+00:00", "Z"),
        "evidence": evidence,
        "actor_count": len(actors),
        "session_count": len(sessions),
        "sample_actor_ids": actors[:5],
        "sample_session_ids": sessions[:5],
        "recommendation": recommendation,
        "automated_action": "none",
    }


def analyze(events: list[dict[str, Any]], config: dict[str, int]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    width = config["window_seconds"]
    for event in events:
        bucket = int(event["_time"].timestamp()) // width
        groups[(event["target"], bucket)].append(event)

    alerts = []
    for (target, _), group in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1])):
        actors = {e["actor_id"] for e in group}
        sessions = {e["session_id"] for e in group}
        failures = [e for e in group if e["outcome"].lower() in FAILURES]
        ratio = round(100 * len(failures) / len(group))
        if len(group) >= config["burst_min_events"] and len(actors) >= config["burst_min_actors"]:
            alerts.append(_alert("distributed_burst", "high", target, group,
                                  {"events": len(group), "distinct_actors": len(actors), "distinct_sessions": len(sessions)},
                                  "Review correlated identities and change windows; consider targeted throttling only after validation."))
        if len(group) >= config["failure_min_events"] and len(failures) >= config["failure_min_count"] and ratio >= config["failure_min_ratio_percent"]:
            alerts.append(_alert("denial_or_enumeration_spike", "medium", target, group,
                                  {"events": len(group), "denied_failed_not_found": len(failures), "failure_ratio_percent": ratio},
                                  "Review authorization and authentication logs; verify whether this is expected discovery or a test."))
        violations = [e for e in group if e.get("tool_allowed") is False]
        if violations:
            names = sorted({str(e.get("tool_name", "unspecified"))[:80] for e in violations})
            alerts.append(_alert("agent_tool_policy_violation", "high", target, violations,
                                  {"disallowed_calls": len(violations), "tool_names": names[:10]},
                                  "Validate the policy decision and agent context; preserve evidence and review tool permissions."))
        sensitive = [e for e in group if e.get("sensitive") is True]
        bytes_read = sum(e.get("bytes_read", 0) for e in group)
        if len(sensitive) >= config["sensitive_min_events"] or bytes_read >= config["bulk_read_bytes"]:
            alerts.append(_alert("sensitive_or_bulk_read", "high", target, group,
                                  {"sensitive_events": len(sensitive), "bytes_read": bytes_read},
                                  "Verify the access scope and expected export; follow the service incident procedure if unauthorized."))
    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="JSONL path or - for stdin")
    parser.add_argument("--config", default="config.json", help="JSON threshold file (default: config.json)")
    parser.add_argument("--output", help="write alert JSON to this path instead of stdout")
    args = parser.parse_args()
    try:
        config = validate_config(json.loads(Path(args.config).read_text(encoding="utf-8")))
        if args.input == "-":
            events = load_events(sys.stdin)
        else:
            with Path(args.input).open(encoding="utf-8") as stream:
                events = load_events(stream)
        alerts = analyze(events, config)
        report = {"schema_version": "1", "mode": "observation_only", "events_analyzed": len(events), "alerts": alerts}
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except (OSError, json.JSONDecodeError, InputError) as exc:
        print(f"agent-swarm-guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

