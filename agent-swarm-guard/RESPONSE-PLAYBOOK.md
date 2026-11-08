# Human response playbook

This playbook applies to alerts produced by Agent Swarm Guard. Alerts are leads for review, not proof of an attack. The tool itself performs no containment.

## Triage sequence

1. **Validate the telemetry.** Confirm timestamps, target naming, pseudonymization consistency, event loss, and whether the alert window crosses a scheduled job, deployment, load test, or maintenance activity.
2. **Check independent evidence.** Review the identity provider, API gateway, application authorization records, agent tool policy, and data-access audit trail for the same time range.
3. **Assess impact.** Determine whether sensitive data was returned, permissions changed, credentials accessed, or external side effects completed. Preserve source logs and relevant request IDs.
4. **Contain narrowly if confirmed.** Follow the service's incident runbook. Prefer expiring a specific agent session or disabling one tool capability over broad IP or service blocks. Require an authorized human for disruptive changes.
5. **Recover and learn.** Rotate exposed credentials if evidence supports exposure, restore affected permissions/data, document false positives, and tune thresholds only after preserving the incident evidence.

## Alert-specific checks

| Alert | First checks | Possible narrow response after confirmation |
|---|---|---|
| `distributed_burst` | Shared source/NAT, expected fan-out, same target, synchronized sessions | Rate-limit the target or revoke only implicated sessions |
| `denial_or_enumeration_spike` | Auth failures, not-found route distribution, account lockouts, test activity | Add a targeted challenge or temporary limit; check account recovery paths |
| `agent_tool_policy_violation` | Exact policy version, agent identity, tool allowlist, prior policy changes | Disable the implicated tool for that identity and review agent credentials |
| `sensitive_or_bulk_read` | Data classification, authorized export job, result volume, destination | Pause the specific export/job and revoke the narrow session if unauthorized |

## Escalate immediately when

- Credentials, secrets, or regulated data may have been accessed or exported.
- An agent made an external change such as payment, deletion, publication, or permission modification.
- Multiple services show a coordinated pattern or containment is failing.

Use your organization's incident commander, privacy, legal, and regulatory escalation paths where applicable. Do not post raw logs or personal data to public GitHub issues.

