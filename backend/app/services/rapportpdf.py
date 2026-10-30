"""
Report PDF Service - Production SaaS Bug Bounty Platform

Generates a professional vulnerability assessment PDF report for a given
target, using WeasyPrint (HTML+CSS -> PDF) and Jinja2 for templating --
the same rendering approach used by tools like Pentest-Tools and several
Burp Suite Enterprise report exports.

Usage (from a route or Celery task):

    from app.services.report_pdf_service import generate_vulnerability_report

    pdf_path = generate_vulnerability_report(
        target_id=target.id,
        organization_id=user.organization_id,
    )
    # pdf_path is a path to a temp file -- send_file() it, or upload to
    # S3/Drive, then delete it. Do not leave scan report PDFs sitting in
    # /tmp indefinitely on a multi-tenant worker.

DESIGN NOTES:
  - Severity colors and CVSS/EPSS data come straight from the
    Vulnerability + CveCache tables already populated by scanner.py and
    nvd_service.py -- no new data collection needed, this is a pure
    presentation layer over data you already have.
  - Report generation is synchronous and can take a second or two for
    large vulnerability counts (WeasyPrint's HTML/CSS layout engine is
    not instant). For orgs with hundreds of vulnerabilities, consider
    wrapping this in a Celery task instead of calling it directly from
    a request handler.
  - Evidence (raw HTTP request/response) is truncated aggressively
    (400 chars) -- a PDF page is not the place for a full raw HTTP
    dump, and WeasyPrint's layout time grows with content volume.
"""

import os
import logging
import tempfile
from datetime import datetime

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from app.models.vulnerability import Vulnerability, SeverityLevel
from app.models.target import Target
from app.models.organization import Organization
from app.utils.exceptions import NotFoundError

logger = logging.getLogger("bug_bounty")

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")

# ==============================================================================
# SEVERITY -> COLOR MAPPING (matches the CSS classes in report_template.html)
# ==============================================================================
SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high":     "#b91c1c",
    "medium":   "#c2410c",
    "low":      "#a16207",
    "info":     "#475569",
}


def _severity_value(severity: SeverityLevel) -> str:
    """Normalizes a SeverityLevel enum (or None) to a lowercase string key."""
    if severity is None:
        return "info"
    return severity.value.lower() if hasattr(severity, "value") else str(severity).lower()


def _build_vuln_context(vuln: Vulnerability) -> dict:
    """
    Flattens a Vulnerability row (+ its evidence JSON) into the plain dict
    shape the Jinja2 template expects. Keeping this separate from the
    main generation function makes it easy to unit-test the data
    transformation without touching WeasyPrint at all.
    """
    import json

    try:
        evidence = json.loads(vuln.evidence) if vuln.evidence else {}
    except (json.JSONDecodeError, TypeError):
        evidence = {}

    nvd_data = evidence.get("nvd", {})
    sev_key = _severity_value(vuln.severity)

    return {
        "title":            vuln.title,
        "severity":         sev_key.upper(),
        "severity_color":   SEVERITY_COLORS.get(sev_key, "#475569"),
        "cvss_score":       vuln.cvss_score,
        "vuln_type":        vuln.vuln_type.value if vuln.vuln_type else "OTHER",
        "url":              vuln.url or "N/A",
        "description":      vuln.description,
        "remediation":      vuln.remediation,
        "cwe_id":           nvd_data.get("cwe_id") or evidence.get("cwe"),
        "epss_score":       nvd_data.get("epss_score"),
        "references":       nvd_data.get("references") or [],
        "evidence_request": evidence.get("request"),
    }


def _compute_overall_risk(severity_counts: dict) -> tuple:
    """
    Derives a single headline risk label + color for the cover page from
    the severity distribution. This is a simple, explainable heuristic
    (not a model) -- any critical finding makes the whole target "Risque
    Critique" regardless of how many lows exist alongside it, which
    matches how a security team actually triages: one critical hole
    outweighs a dozen info-level findings.
    """
    if severity_counts["critical"] > 0:
        return "RISQUE CRITIQUE", "#DC2626"
    if severity_counts["high"] > 0:
        return "RISQUE ÉLEVÉ", "#EA580C"
    if severity_counts["medium"] > 0:
        return "RISQUE MODÉRÉ", "#CA8A04"
    if severity_counts["low"] > 0:
        return "RISQUE FAIBLE", "#4B7BA8"
    return "RISQUE MINIMAL", "#64748B"


def _build_severity_bars(severity_counts: dict) -> list:
    """
    Builds the horizontal signal-bar rows for the executive summary.
    Bar width is relative to the highest count so the reader sees
    proportion at a glance, not just raw numbers.
    """
    order = [
        ("CRITICAL", "critical", "#7f1d1d"),
        ("HIGH",     "high",     "#b91c1c"),
        ("MEDIUM",   "medium",   "#c2410c"),
        ("LOW",      "low",      "#a16207"),
        ("INFO",     "info",     "#475569"),
    ]
    max_count = max(severity_counts.values()) or 1

    return [
        {
            "label": label,
            "count": severity_counts[key],
            "color": color,
            "pct": max(6, round((severity_counts[key] / max_count) * 100)) if severity_counts[key] else 2,
        }
        for label, key, color in order
    ]


def _build_priority_items(severity_counts: dict) -> list:
    """
    Builds the ordered, dynamic recommendation list for the conclusion
    page. Only includes a tier if it actually has findings -- an empty
    "0 critical vulnerabilities" bullet reads as filler, not insight.
    """
    items = []
    if severity_counts["critical"] > 0:
        items.append(
            f"<strong>Action immédiate :</strong> corriger sans délai "
            f"les {severity_counts['critical']} vulnérabilité(s) critique(s) -- "
            f"risque de compromission totale du système."
        )
    if severity_counts["high"] > 0:
        items.append(
            f"<strong>Haute priorité :</strong> planifier la correction des "
            f"{severity_counts['high']} vulnérabilité(s) de sévérité élevée "
            f"sous 7 jours."
        )
    if severity_counts["medium"] > 0:
        items.append(
            f"<strong>Priorité moyenne :</strong> traiter les "
            f"{severity_counts['medium']} vulnérabilité(s) moyennes lors du "
            f"prochain cycle de maintenance."
        )
    if severity_counts["low"] > 0:
        items.append(
            f"<strong>Suivi :</strong> consigner les "
            f"{severity_counts['low']} vulnérabilité(s) de faible sévérité "
            f"pour correction opportuniste."
        )
    items.append(
        "Mettre en place un processus de scan récurrent pour détecter "
        "toute régression après correction."
    )
    return items


def generate_vulnerability_report(target_id: str, organization_id: str,
                                   output_dir: str = None) -> str:
    """
    Generates a PDF vulnerability report for a target and returns the
    filesystem path to the generated file.

    Args:
        target_id       : Target whose vulnerabilities to report on
        organization_id : org scoping (multi-tenant safety -- never skip this)
        output_dir       : where to write the PDF. Defaults to a fresh
                           tempfile.mkdtemp() -- CALLER IS RESPONSIBLE for
                           cleaning this up after sending/uploading the file.

    Raises:
        NotFoundError -- target doesn't exist or doesn't belong to this org

    Returns:
        Absolute path to the generated PDF file.
    """
    target = Target.query.filter_by(
        id=target_id, organization_id=organization_id, is_deleted=False
    ).first()
    if target is None:
        raise NotFoundError(f"Target {target_id} not found")

    org = Organization.query.get(organization_id)
    org_name = org.name if org else "Organization"

    vulnerabilities = (
        Vulnerability.query
        .filter_by(target_id=target_id, organization_id=organization_id, is_deleted=False)
        .order_by(Vulnerability.cvss_score.desc().nullslast())
        .all()
    )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    vuln_contexts = []
    for vuln in vulnerabilities:
        ctx = _build_vuln_context(vuln)
        vuln_contexts.append(ctx)
        sev_key = ctx["severity"].lower()
        if sev_key in severity_counts:
            severity_counts[sev_key] += 1

    tools_used = sorted({
        # Best-effort: pull tool name out of the "[NUCLEI] Title" convention
        # scanner.py uses for vuln.title. Falls back to "Scanner" if the
        # title doesn't follow that pattern (e.g. manually-entered findings).
        vuln.title.split("]")[0].strip("[") if vuln.title and vuln.title.startswith("[") else "Scanner"
        for vuln in vulnerabilities
    })

    risk_label, risk_color = _compute_overall_risk(severity_counts)
    severity_bars = _build_severity_bars(severity_counts)
    priority_items = _build_priority_items(severity_counts)

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")

    html_content = template.render(
        organization_name=org_name,
        target_name=target.program_name or target.scan_url,
        target_url=target.scan_url,
        report_date=datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC"),
        total_vulns=len(vulnerabilities),
        severity_counts=severity_counts,
        severity_bars=severity_bars,
        vulnerabilities=vuln_contexts,
        tools_used=", ".join(tools_used) if tools_used else "Nuclei",
        risk_label=risk_label,
        risk_color=risk_color,
        priority_items=priority_items,
    )

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="vuln_report_")

    safe_target_name = "".join(
        c if c.isalnum() or c in "-_" else "_" for c in (target.program_name or "target")
    )
    filename = f"security_report_{safe_target_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(output_dir, filename)

    logger.info(
        f"Generating PDF report for target {target_id[:8]}: "
        f"{len(vulnerabilities)} vulnerabilities"
    )

    HTML(string=html_content, base_url=TEMPLATE_DIR).write_pdf(output_path)

    logger.info(f"PDF report written to {output_path}")
    return output_path