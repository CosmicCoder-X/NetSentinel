from __future__ import annotations

from copy import copy

from .context import NetworkContext
from .models import Alert


def refine_alerts(alerts: list[Alert], context: NetworkContext, min_confidence: float) -> list[Alert]:
    refined: list[Alert] = []
    seen: set[tuple[object, ...]] = set()

    for alert in alerts:
        if _is_suppressed(alert, context):
            continue

        tuned = _tune_confidence(alert, context)
        if tuned.confidence < min_confidence and tuned.severity not in {"high", "critical"}:
            continue

        dedupe_key = (
            tuned.category,
            tuned.title,
            tuned.src_ip,
            tuned.dst_ip,
            tuned.timestamp,
            tuple(tuned.reasons),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        refined.append(tuned)

    return refined


def _is_suppressed(alert: Alert, context: NetworkContext) -> bool:
    if alert.src_ip not in context.approved_scanners:
        return False
    scan_like = any(
        token in f"{alert.title} {' '.join(alert.reasons)}".lower()
        for token in ("scan", "probe", "recon", "horizontal")
    )
    return scan_like


def _tune_confidence(alert: Alert, context: NetworkContext) -> Alert:
    tuned = copy(alert)
    evidence = dict(alert.evidence)
    confidence = alert.confidence

    if alert.dst_ip in context.critical_assets:
        confidence += 0.06
        evidence["critical_asset"] = True

    if context.is_internal(alert.dst_ip) and not context.is_internal(alert.src_ip):
        confidence += 0.05
        evidence["external_to_internal"] = True

    tuned.confidence = min(confidence, 0.99)
    tuned.evidence = evidence
    return tuned
