# Connect an application to Agent Swarm Guard

`jsonl_audit_sink.py` is a small Python example for instrumenting the **server-side authorization point** for an AI agent's tool call. It writes the exact normalized JSONL schema consumed by the detector.

## 1. Set a private pseudonymization key

Use a unique random secret with at least 32 bytes. Store it in your secret manager or environment, not in source control or the event file. On Windows, set an ACL on the log directory so only the service identity and security operators can read it. Rotating the key changes pseudonyms and breaks correlation across the rotation boundary.

PowerShell example for the current process:

```powershell
$env:AGENT_SWARM_HMAC_KEY = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

For a managed service, inject a persistent secret from the service's approved secret store rather than generating a new key at each restart.

## 2. Instrument the policy decision

Call the sink after the server has decided whether the tool is permitted, before returning the decision to the agent. The authorization system remains authoritative; this sample only records the result.

```python
from integration.jsonl_audit_sink import JsonlAuditSink

audit = JsonlAuditSink("reports/agent-events.jsonl")

def authorize_tool(actor_id, session_id, tool_name, target, policy_allows):
    allowed = policy_allows(actor_id, tool_name, target)
    audit.tool_decision(
        actor_id=actor_id,          # internal IDs are HMAC-pseudonymized on disk
        session_id=session_id,
        target=target,
        tool_name=tool_name,
        allowed=allowed,
        sensitive=tool_name in {"export_documents", "change_permissions"},
    )
    return allowed
```

Do not pass prompts, retrieved documents, API keys, email addresses, or request bodies. Use stable internal IDs so repeated activity can be correlated; the HMAC key prevents storing those IDs in clear text.

## 3. Analyze the resulting events

```powershell
py .\agent_swarm_guard.py .\reports\agent-events.jsonl --config .\config.json --output .\reports\agent-alerts.json
```

Schedule this command after log rotation or invoke it on a bounded batch. Keep raw events and generated alerts under the same retention and access controls as other security logs. The detector's current fixed-window grouping can split activity at window boundaries.

## Production considerations

- The example does not provide durable queueing, cross-process locking, log rotation, or SIEM delivery. Add these through the application's approved logging infrastructure before high-volume production use.
- A disk or permissions error raises an exception. Decide explicitly whether your application should fail closed or continue when audit logging is unavailable; do not silently discard the failure.
- Avoid logging events from untrusted client code. Instrument the trusted server-side policy decision.
- Validate what `sensitive` means for each service; it is an operator-supplied label, not automatic data classification.
- A tool call logged as `allowed` means the policy permitted it, not that execution completed successfully.

