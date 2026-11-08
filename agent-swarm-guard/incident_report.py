#!/usr/bin/env python3
"""Build a local incident report from normalized events and detector alerts."""
from __future__ import annotations

import argparse
from email.message import EmailMessage
import hashlib
import ipaddress
import json
import sys
from collections import defaultdict
from datetime import datetime
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_swarm_guard import InputError, load_events


def md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def read_alerts(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"cannot read alert report: {exc}") from exc
    alerts = data.get("alerts") if isinstance(data, dict) else None
    if not isinstance(alerts, list) or any(not isinstance(a, dict) for a in alerts):
        raise InputError("alerts file must contain an object with an alerts array")
    return alerts


def read_routing(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"cannot read authority routing file: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("routes"), dict):
        raise InputError("routing file must contain a routes object")
    return data


def render(events: list[dict[str, Any]], alerts: list[dict[str, Any]], source_sha256: str,
           include_source_ips: bool, routing: dict[str, Any]) -> str:
    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    report_id = hashlib.sha256((source_sha256 + json.dumps(alerts, sort_keys=True)).encode()).hexdigest()[:20]
    alert_windows = []
    for alert in alerts:
        target = alert.get("target")
        try:
            start = datetime.fromisoformat(str(alert["window_start"]).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(alert["window_end"]).replace("Z", "+00:00"))
        except (KeyError, ValueError) as exc:
            raise InputError("each alert must contain valid window_start and window_end timestamps") from exc
        if start.tzinfo is None or end.tzinfo is None or end < start or not isinstance(target, str):
            raise InputError("alert target and time window are invalid")
        alert_windows.append((target, start, end))
    relevant = [e for e in events if any(target == e.get("target") and start <= e["_time"] <= end
                                         for target, start, end in alert_windows)]
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest = max((a.get("severity", "unknown") for a in alerts),
                  key=lambda s: severity_order.get(s, 0), default="none")

    source_rows: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "first": None, "last": None, "asns": set(), "countries": set()})
    for event in relevant:
        raw_ip = event.get("_source_ip")
        if not raw_ip:
            continue
        address = ipaddress.ip_address(raw_ip)
        if include_source_ips:
            display = raw_ip
        else:
            prefix = 24 if address.version == 4 else 48
            display = str(ipaddress.ip_network(f"{raw_ip}/{prefix}", strict=False))
        row = source_rows[display]
        row["count"] += 1
        stamp = event["_time"].isoformat().replace("+00:00", "Z")
        row["first"] = min(row["first"], stamp) if row["first"] else stamp
        row["last"] = max(row["last"], stamp) if row["last"] else stamp
        if event.get("source_asn"):
            row["asns"].add(event["source_asn"].upper())
        if event.get("source_country"):
            row["countries"].add(event["source_country"].upper())

    lines = [
        "# Rapport d'incident cyber - Agent Swarm Guard",
        "",
        f"- Identifiant du rapport : `{report_id}`",
        f"- G�n�r� le : `{generated}`",
        f"- S�v�rit� maximale d�tect�e : **{md(highest)}**",
        f"- �v�nements analys�s : **{len(events)}** ; �v�nements sur les cibles alert�es : **{len(relevant)}**",
        f"- Empreinte SHA-256 du fichier source : `{source_sha256}`",
        "",
        "> Ce document d�crit des observations techniques. Il ne prouve ni l'identit� ni la localisation de l'auteur. Une adresse source peut correspondre � un relais, VPN, NAT, serveur compromis ou proxy.",
        "",
        "## Alertes",
        "",
    ]
    if not alerts:
        lines.append("Aucune alerte n'a �t� fournie. Aucun signalement n'est recommand� sur la base de ce rapport seul.")
    for alert in alerts:
        lines.extend([
            f"### {md(alert.get('rule', 'rule inconnue'))} - {md(alert.get('severity', 'niveau inconnu'))}",
            f"- Cible : `{md(alert.get('target', 'inconnue'))}`",
            f"- Fen�tre observ�e : `{md(alert.get('window_start', ''))}`  `{md(alert.get('window_end', ''))}`",
            f"- Acteurs/sessions distincts : {md(alert.get('actor_count', 'n/d'))} / {md(alert.get('session_count', 'n/d'))}",
            f"- �l�ments d�tect�s : `{md(json.dumps(alert.get('evidence', {}), ensure_ascii=False, sort_keys=True))}`",
            f"- Suite propos�e : {md(alert.get('recommendation', 'revue humaine'))}",
            "",
        ])

    lines.extend(["## Indicateurs r�seau observ�s", ""])
    if source_rows:
        lines.append("Les adresses sont celles consign�es par la source de journaux. V�rifier qu'elles proviennent du pair observ� par une passerelle de confiance, et non d'un en-t�te client non v�rifi�.")
        lines.append("")
        lines.append("| Indicateur" + (" (restreint)" if include_source_ips else " (pr�fixe masqu�)") + " | ASN observ� | Pays fourni par la t�l�m�trie | �v�nements | Premi�re observation | Derni�re observation |")
        lines.append("|---|---|---|---:|---|---|")
        for source, row in sorted(source_rows.items()):
            asns = ", ".join(sorted(row["asns"])) or "n/d"
            countries = ", ".join(sorted(row["countries"])) or "n/d"
            lines.append(f"| `{md(source)}` | {md(asns)} | {md(countries)} | {row['count']} | `{row['first']}` | `{row['last']}` |")
    else:
        lines.append("Aucun champ `source_ip` valide n'�tait pr�sent dans les �v�nements correspondants.")
    lines.extend(["", "## Chronologie synth�tique", "", "| Horodatage UTC | Cible | Action | R�sultat | Outil |", "|---|---|---|---|---|"])
    for event in sorted(relevant, key=lambda e: e["_time"]):
        stamp = event["_time"].isoformat().replace("+00:00", "Z")
        lines.append(f"| `{stamp}` | `{md(event.get('target'))}` | `{md(event.get('action'))}` | `{md(event.get('outcome'))}` | `{md(event.get('tool_name', ''))}` |")

    lines.extend([
        "", "## Orientation vers les interlocuteurs fran�ais", "",
        "Le routage d�pend du statut, du secteur, du territoire et de la nature confirm�e de l'incident. Le lieu d'une adresse IP ne d�termine pas l'autorit� comp�tente. V�rifier le profil de l'organisation et les formulaires officiels avant toute transmission.",
        "",
    ])
    routes = routing["routes"]
    selected = ["cyber_assistance", "cert_fr"] if alerts else []
    if any(a.get("rule") == "sensitive_or_bulk_read" for a in alerts):
        selected.append("personal_data_breach")
    if alerts:
        selected.append("criminal_complaint")
    for key in selected:
        route = routes.get(key)
        if not isinstance(route, dict):
            continue
        name = md(route.get("name", key))
        url = md(route.get("url", ""))
        note = md(route.get("when", "V�rifier si cette d�marche s'applique."))
        contact = f" - courriel : `{md(route['email'])}`" if route.get("email") else ""
        lines.append(f"- **{name}**{contact} : [{md(route.get('link_label', 'acc�s officiel'))}]({url}). {note}")
    lines.extend([
        "", "## Pr�servation et validation humaine", "",
        "Conserver les journaux originaux en lecture seule avec leurs horodatages, la configuration de d�tection, les �l�ments de passerelle et les actions de r�ponse. V�rifier les faux positifs et compl�ter les informations manquantes avant transmission. Ne pas joindre les journaux bruts � un courriel non chiffr�.",
        "", "Ce rapport est une aide technique, pas une qualification juridique ni une attribution d'attaque. Les obligations de notification varient selon les faits et le statut de l'organisation.", "",
    ])
    if include_source_ips:
        lines.insert(1, "> **DIFFUSION RESTREINTE : contient des adresses IP exactes. Transmettre uniquement apr�s validation et par un canal adapt�.\n")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, help="normalized JSONL events")
    parser.add_argument("--alerts", required=True, help="JSON output from agent_swarm_guard.py")
    parser.add_argument("--output", required=True, help="local Markdown report path")
    parser.add_argument("--include-source-ips", action="store_true", help="include exact source IPs; creates a restricted report")
    parser.add_argument("--routing", default=str(Path(__file__).with_name("authority-routing.fr.json")), help="official contact routing profile")
    parser.add_argument("--draft-cert-email", action="store_true", help="create a local .eml draft to CERT-FR; never sends it")
    args = parser.parse_args()
    try:
        event_path = Path(args.events)
        source_bytes = event_path.read_bytes()
        source_sha256 = hashlib.sha256(source_bytes).hexdigest()
        with event_path.open(encoding="utf-8") as stream:
            events = load_events(stream)
        alerts = read_alerts(Path(args.alerts))
        routing = read_routing(Path(args.routing))
        report = render(events, alerts, source_sha256, args.include_source_ips, routing)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
        draft_path = None
        if args.draft_cert_email:
            if not alerts:
                raise InputError("cannot prepare an authority contact draft without detector alerts")
            cert = routing["routes"].get("cert_fr", {})
            recipient = cert.get("email") if isinstance(cert, dict) else None
            if not recipient:
                raise InputError("selected routing profile has no CERT-FR email recipient")
            report_id = hashlib.sha256((source_sha256 + json.dumps(alerts, sort_keys=True)).encode()).hexdigest()[:20]
            message = EmailMessage()
            message["To"] = recipient
            message["Subject"] = f"Signalement � qualifier - Agent Swarm Guard {report_id}"
            targets = sorted({str(a.get("target", "unknown"))[:120] for a in alerts})
            windows = sorted({f"{a.get('window_start', '?')} � {a.get('window_end', '?')}" for a in alerts})
            message.set_content(
                "Bonjour,\n\n"
                "Un outil de d�tection local a g�n�r� un rapport d'incident � qualifier. "
                "Aucun journal brut ni aucune adresse IP exacte n'est joint � ce brouillon.\n"
                f"Identifiant : {report_id}\n"
                f"R�gles d�tect�es : {', '.join(sorted({str(a.get('rule', 'unknown')) for a in alerts})) or 'aucune'}\n"
                f"Cibles observ�es : {', '.join(targets)}\n"
                f"Fen�tres observ�es : {'; '.join(windows)}\n"
                f"Empreinte SHA-256 des �v�nements sources : {source_sha256}\n\n"
                "Le rapport local n'est pas joint : le joindre uniquement apr�s revue humaine et v�rification du canal s�curis�.\n"
                "V�rifier l'�ligibilit� de l'organisation et le p�rim�tre du CERT-FR avant envoi.\n"
            )
            draft_path = output.with_suffix(".eml")
            draft_path.write_bytes(message.as_bytes())
        print(json.dumps({"report": str(output), "draft_email": str(draft_path) if draft_path else None, "report_id": hashlib.sha256((source_sha256 + json.dumps(alerts, sort_keys=True)).encode()).hexdigest()[:20], "source_sha256": source_sha256, "exact_source_ips_included": args.include_source_ips}, ensure_ascii=False))
        return 0
    except (OSError, InputError) as exc:
        print(f"incident-report: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

