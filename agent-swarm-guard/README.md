# Agent Swarm Guard

**Defensive, local-first correlation for suspicious activity by coordinated AI agents.**

This alpha tool analyzes normalized JSON Lines security events and emits explainable alerts. It does not connect to a network, inspect third-party systems, block traffic, revoke credentials, or execute remediation. It is intended to help security teams correlate activity across accounts, sessions, tools, and protected resources.

> **Status:** early prototype. Run in shadow/observation mode and tune thresholds against your own baseline before operational use. It is not an IDS replacement or a guarantee of detection.

## What it detects

- Distributed bursts: many actors/sessions reaching one target in a short window.
- Denial and enumeration patterns: repeated denied, failed, or not-found actions.
- Tool-policy violations: agent tool calls that the event producer marked disallowed.
- Sensitive or bulk reads: repeated sensitive access or unusually large cumulative reads.

Rules are deterministic and return the evidence used for each alert, a severity, and a recommended next step. A single weak signal is not a conclusion of malicious intent. Shared NATs, load tests, scheduled jobs, and legitimate agent fan-out can look unusual.

## Quick start

Requires Python 3.10 or later. No third-party packages and no installation step.

```bash
python agent_swarm_guard.py examples/swarm-burst.jsonl --config config.json
```

Read JSON Lines from standard input:

```bash
cat examples/swarm-burst.jsonl | python agent_swarm_guard.py -
```

Write machine-readable alerts to a file:

```bash
python agent_swarm_guard.py examples/swarm-burst.jsonl --config config.json --output alerts.json
```

PowerShell:

```powershell
Get-Content .\examples\swarm-burst.jsonl | py .\agent_swarm_guard.py - --config .\config.json
```

Exit codes: `0` analysis completed (including when alerts exist), `2` invalid input/configuration or I/O error. The CLI never treats an alert as authorization to block or quarantine.

## Event format

One JSON object per line. Required fields:

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | ISO-8601 string with timezone | Event time, normalized to UTC |
| `target` | string | Protected service, resource, or logical route |
| `actor_id` | string | Pseudonymous account or agent identity |
| `session_id` | string | Pseudonymous session or API-key identity |
| `action` | string | Operation name, such as `read`, `tool_call`, `login` |
| `outcome` | string | Result, such as `allowed`, `denied`, `failed`, `not_found` |

Optional fields: `bytes_read` (non-negative integer), `sensitive` (boolean), `tool_name` (string), `tool_allowed` (boolean). Unknown fields are ignored. Do not place credentials, prompts, message bodies, personal data, or raw secrets in event records.

Example:

```json
{"timestamp":"2026-11-08T09:00:00Z","target":"docs-export","actor_id":"agent-17","session_id":"sess-8f2","action":"tool_call","outcome":"allowed","tool_name":"export_documents","tool_allowed":true,"bytes_read":2048,"sensitive":false}
```

## Configuration

`config.json` contains conservative demonstration thresholds: correlation window, burst size, failure ratio/count, sensitive-read threshold, and bulk-read volume. Configure to service-specific normal traffic. Record the reason for each change and review false-positive/false-negative findings.

The current implementation groups events into fixed UTC windows. Events near a window boundary may land in separate groups; production deployments should consider a streaming window store, late-event handling, retention controls, and a tested baseline per service.

## Integration pattern

1. Export authentication, API gateway, authorization, agent tool-call, and data-access events to a local pipeline.
2. Normalize them to the schema above, pseudonymizing identities consistently.
3. Run the analyzer on a bounded batch or scheduled export; retain the source-of-truth logs in your approved SIEM.
4. Route alerts to a human reviewer with surrounding context and known maintenance windows.
5. If you later add containment, put it in a separate policy service with least-privilege credentials, explicit allowlisted actions, expiry, audit logging, dry-run, rollback, and human approval for disruptive changes.

Agent-specific controls that complement detection: tool allowlists, per-agent identities, least privilege, server-side authorization on every tool call, rate and spend limits, and human confirmation for export, deletion, payment, publication, or permission changes. Treat instructions found in retrieved content as untrusted data.

## Privacy and operations

- Prefer pseudonymous IDs and data minimization. Keep identity resolution in a separate access-controlled system.
- This program reads only the specified file/stdin and writes alerts to stdout or the requested output path.
- Protect source logs and generated alerts with your normal access, retention, and incident-handling policies.
- Never upload real logs to public issues. Use sanitized, synthetic examples.
- Review alerts in context; automated correlation can produce both false positives and false negatives.

## Roadmap

- Add adapter examples for common gateway and agent-runtime audit formats.
- Add replay-based evaluation with precision, recall, event loss, and latency reporting.
- Add a streaming adapter only after bounded batch behavior and privacy controls are reviewed.
- Keep any response actions in a separate, explicitly approved module; detection remains observation-only by default.

## Fran�ais

Agent Swarm Guard est un prototype local qui corr�le des journaux de s�curit� normalis�s pour faire ressortir des comportements coordonn�s d'agents IA : rafales distribu�es, �checs r�p�t�s, appels d'outils interdits et acc�s sensibles ou volumineux. Il explique chaque alerte et propose une v�rification humaine. Il ne bloque rien et n'agit sur aucun r�seau.

Il faut d'abord l'utiliser en observation, adapter les seuils au trafic normal du service et mesurer les faux positifs. Ce prototype ne remplace pas un SIEM, un EDR ni une �quipe de r�ponse � incident.

## Contributions

Issues and pull requests are welcome. Include sanitized synthetic events, expected behavior, and the operational context. Do not submit live credentials, private logs, or exploit payloads.

