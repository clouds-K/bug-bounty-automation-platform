"""
NVD Service - National Vulnerability Database enrichment

Fetches CVE data from NVD API + EPSS data from FIRST.org, caches both
locally in CveCache. Called automatically by scanner.py after each Nuclei
finding that contains a CVE ID.

Usage in scanner.py:
    from app.services.nvd_service import enrich_vulnerability_with_nvd, extract_cve_id

    cve_id = extract_cve_id(finding)
    if cve_id:
        enrich_vulnerability_with_nvd(vuln, cve_id)

Rate limits:
    NVD  without API key : 5 requests / 30 seconds
    NVD  with API key    : 50 requests / 30 seconds  -> always set NVD_API_KEY
    EPSS (FIRST.org)     : no key required, generous limit, but throttled
                            anyway to be a good API citizen.
"""

import re
import time
import json
import logging
import requests
from datetime import datetime
from typing import Optional

from flask import current_app

from app import db
from app.models.cve_cache import CveCache
from app.models.vulnerability import Vulnerability

logger = logging.getLogger("bug_bounty")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# CVE ID pattern -- matches CVE-YYYY-NNNNN (4+ digit sequence, any year)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# ==============================================================================
# RATE LIMITING
# ==============================================================================
# Module-level throttle state. Fine for a single Celery worker process
# handling findings sequentially (--pool=solo, as used in dev). If this
# ever runs with multiple concurrent worker processes, replace this with
# a Redis-based token bucket shared across processes -- a local variable
# only throttles within one process, not across the whole fleet.
# ==============================================================================

_last_nvd_call = 0.0
_last_epss_call = 0.0

NVD_MIN_INTERVAL_SECONDS = 0.7   # ~50 req/30s with API key, safety margin
EPSS_MIN_INTERVAL_SECONDS = 0.3  # generous limit, but still be polite


def _throttle(kind: str, min_interval: float) -> float:
    """Sleeps just enough to respect min_interval since the last call of this type."""
    global _last_nvd_call, _last_epss_call
    now = time.monotonic()
    last_call = _last_nvd_call if kind == "nvd" else _last_epss_call
    elapsed = now - last_call
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    now = time.monotonic()
    if kind == "nvd":
        _last_nvd_call = now
    else:
        _last_epss_call = now
    return now


# ==============================================================================
# CVE ID EXTRACTION
# ==============================================================================

def extract_cve_id(finding: dict) -> Optional[str]:
    """
    Extract CVE ID from a Nuclei finding.

    Nuclei stores CVE IDs in multiple places depending on the template:
      - info.classification.cve-id : ["CVE-2012-1823"]  (most reliable)
      - template-id                : "CVE-2012-1823"
      - info.tags                  : ["cve", "CVE-2012-1823"]

    Returns the first CVE ID found, or None if not a CVE finding.
    """
    classification = finding.get("info", {}).get("classification", {})
    cve_ids = classification.get("cve-id", [])
    if cve_ids:
        return cve_ids[0].upper()

    template_id = finding.get("template-id", "")
    if CVE_PATTERN.match(template_id):
        return template_id.upper()

    tags = finding.get("info", {}).get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    for tag in tags:
        if CVE_PATTERN.match(tag):
            return tag.upper()

    return None


# ==============================================================================
# EPSS FETCH (separate API, separate rate limit)
# ==============================================================================

def _fetch_epss(cve_id: str):
    """
    Fetches EPSS score + percentile from FIRST.org for a single CVE.
    Returns (epss_score, epss_percentile) -- both None on any failure.
    EPSS is a nice-to-have enrichment; a failure here must never block
    or fail the main NVD enrichment.
    """
    _throttle("epss", EPSS_MIN_INTERVAL_SECONDS)
    try:
        resp = requests.get(EPSS_API_URL, params={"cve": cve_id}, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if not data:
            return None, None
        entry = data[0]
        score = float(entry["epss"]) if entry.get("epss") is not None else None
        percentile = float(entry["percentile"]) if entry.get("percentile") is not None else None
        return score, percentile
    except Exception as e:
        logger.debug(f"EPSS lookup failed for {cve_id}: {e}")
        return None, None


# ==============================================================================
# NVD API FETCH
# ==============================================================================

def fetch_from_nvd(cve_id: str, api_key: str = None) -> Optional[CveCache]:
    """
    Fetch CVE data from NVD API (+ EPSS from FIRST.org) and upsert the
    CveCache row. Returns the CveCache object (even if not_found=True),
    or whatever's already cached if a total network/parse failure occurs.

    Args:
        cve_id  : e.g. "CVE-2025-46817"
        api_key : NVD API key. If not provided, falls back to
                  current_app.config["NVD_API_KEY"] automatically -- most
                  callers don't need to pass this explicitly.
    """
    if api_key is None:
        api_key = current_app.config.get("NVD_API_KEY")

    headers = {"apiKey": api_key} if api_key else {}
    params = {"cveId": cve_id}

    _throttle("nvd", NVD_MIN_INTERVAL_SECONDS)

    try:
        logger.info(f"Fetching NVD data for {cve_id}")
        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=15)

        if resp.status_code == 429:
            logger.warning("NVD rate limit hit -- sleeping 35s before retry")
            time.sleep(35)
            _throttle("nvd", NVD_MIN_INTERVAL_SECONDS)
            resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=15)

        if resp.status_code == 404:
            logger.info(f"{cve_id} not found in NVD")
            return _save_not_found(cve_id)

        if resp.status_code == 403:
            # Usually an invalid/missing API key. Treat as a temporary
            # failure (not not_found) -- this needs a human to fix the
            # key, not a 7-day retry timer on an otherwise-valid CVE.
            logger.error(f"NVD returned 403 for {cve_id} -- check NVD_API_KEY")
            _increment_fetch_attempts(cve_id, "403 Forbidden -- check API key")
            return CveCache.query.get(cve_id)

        resp.raise_for_status()
        data = resp.json()

    except requests.RequestException as e:
        logger.warning(f"NVD API error for {cve_id}: {e}")
        _increment_fetch_attempts(cve_id, str(e))
        return CveCache.query.get(cve_id)
    except ValueError as e:
        logger.warning(f"NVD returned invalid JSON for {cve_id}: {e}")
        _increment_fetch_attempts(cve_id, f"Invalid JSON: {e}")
        return CveCache.query.get(cve_id)

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        logger.info(f"{cve_id} returned empty vulnerabilities list from NVD")
        return _save_not_found(cve_id)

    cve_data = vulns[0].get("cve", {})
    return _parse_and_save(cve_id, cve_data)


def _parse_and_save(cve_id: str, cve_data: dict) -> CveCache:
    """Parse NVD CVE response, fetch EPSS, and upsert the CveCache row."""

    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else None
    )

    cvss_score = cvss_vector = None
    cvss_v2_score = cvss_v2_vector = None

    metrics = cve_data.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [])
    cvss_v30 = metrics.get("cvssMetricV30", [])
    cvss_v2  = metrics.get("cvssMetricV2",  [])

    if cvss_v31:
        m = cvss_v31[0].get("cvssData", {})
        cvss_score, cvss_vector = m.get("baseScore"), m.get("vectorString")
    elif cvss_v30:
        m = cvss_v30[0].get("cvssData", {})
        cvss_score, cvss_vector = m.get("baseScore"), m.get("vectorString")

    if cvss_v2:
        m = cvss_v2[0].get("cvssData", {})
        cvss_v2_score, cvss_v2_vector = m.get("baseScore"), m.get("vectorString")

    best_score = cvss_score or cvss_v2_score
    severity = _score_to_severity(best_score)

    weaknesses = cve_data.get("weaknesses", [])
    cwe_id = None
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                cwe_id = desc["value"]
                break
        if cwe_id:
            break

    refs = [r.get("url") for r in cve_data.get("references", []) if r.get("url")]

    affected_products = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria")
                if cpe:
                    affected_products.append(cpe)

    published_date     = _parse_date(cve_data.get("published"))
    last_modified_date = _parse_date(cve_data.get("lastModified"))

    # EPSS -- separate API call, throttled independently, never blocks
    # the NVD data from being saved if it fails.
    epss_score, epss_percentile = _fetch_epss(cve_id)

    cache = CveCache.query.get(cve_id)
    if cache is None:
        cache = CveCache(cve_id=cve_id)
        db.session.add(cache)

    cache.description        = description
    cache.cvss_score         = cvss_score
    cache.cvss_vector        = cvss_vector
    cache.cvss_v2_score      = cvss_v2_score
    cache.cvss_v2_vector     = cvss_v2_vector
    cache.severity           = severity
    cache.cwe_id             = cwe_id
    cache.references         = refs
    cache.affected_products  = affected_products[:20]  # cap at 20
    cache.published_date     = published_date
    cache.last_modified_date = last_modified_date
    cache.epss_score         = epss_score
    cache.epss_percentile    = epss_percentile
    cache.fetched_at         = datetime.utcnow()
    cache.fetch_attempts     = 0
    cache.not_found          = False
    cache.last_error         = None

    db.session.commit()
    logger.info(
        f"Cached NVD data for {cve_id}: cvss={cvss_score} severity={severity} epss={epss_score}"
    )
    return cache


def _save_not_found(cve_id: str) -> CveCache:
    """Mark a CVE as confirmed not-in-NVD -- avoids retrying for 7 days."""
    cache = CveCache.query.get(cve_id)
    if cache is None:
        cache = CveCache(cve_id=cve_id)
        db.session.add(cache)

    cache.not_found      = True
    cache.last_error     = None
    cache.fetch_attempts = 0
    cache.fetched_at     = datetime.utcnow()
    db.session.commit()
    return cache


def _increment_fetch_attempts(cve_id: str, error: str):
    """
    Records a temporary failure (network error, 403, bad JSON...) WITHOUT
    marking not_found and WITHOUT overwriting any real data already
    cached. This is what stops a single NVD outage from permanently
    poisoning the cache with false not_found entries.
    """
    cache = CveCache.query.get(cve_id)
    if cache is None:
        cache = CveCache(cve_id=cve_id)
        db.session.add(cache)

    cache.fetch_attempts = (cache.fetch_attempts or 0) + 1
    cache.last_error     = error[:200]
    cache.fetched_at     = datetime.utcnow()
    db.session.commit()


def _score_to_severity(score) -> Optional[str]:
    """Convert CVSS score to severity string per NVD's official ranges."""
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _parse_date(date_str) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


# ==============================================================================
# MAIN ENRICHMENT FUNCTION -- called from scanner.py per finding
# ==============================================================================

def enrich_vulnerability_with_nvd(vuln: Vulnerability, cve_id: str,
                                   api_key: str = None) -> bool:
    """
    Enrich a Vulnerability row with NVD (+ EPSS) data.

    Cache-first: only calls NVD/EPSS if the CVE is not cached or stale.
    Updates vuln.cvss_score / cvss_vector / description (only if those
    fields are currently empty -- never overwrites Nuclei's own findings)
    and stores the full NVD payload under evidence["nvd"].

    vuln.cwe_id / vuln.cwe_source are handled differently from the other
    fields above: NVD's CWE is authoritative, so it OVERWRITES an existing
    ML estimate (cwe_source == "ml_estimate") instead of only filling an
    empty field. Without this, a vulnerability created before its CVE was
    known would keep the ML guess forever, even after the real CWE shows
    up moments later via NVD enrichment.

    Returns True if enrichment data was applied, False otherwise (no
    CVE id, NVD has no data, or a total fetch failure with nothing to
    fall back on).
    """
    if not cve_id:
        return False

    cache = CveCache.query.get(cve_id)
    if cache is None or cache.is_stale():
        cache = fetch_from_nvd(cve_id, api_key=api_key)

    if cache is None or cache.not_found:
        logger.info(f"No usable NVD data for {cve_id}")
        return False

    if cache.cvss_score is not None and vuln.cvss_score is None:
        vuln.cvss_score = cache.cvss_score

    if cache.cvss_vector and not vuln.cvss_vector:
        vuln.cvss_vector = cache.cvss_vector

    if cache.description and not vuln.description:
        vuln.description = cache.description

    if cache.cwe_id and vuln.cwe_id != cache.cwe_id:
        # NVD CWE is authoritative -- replaces any prior value, including
        # an ML estimate, so the frontend never shows a stale "IA" badge
        # once the real CWE is known.
        vuln.cwe_id = cache.cwe_id
        vuln.cwe_source = "nvd_official"

    try:
        evidence = json.loads(vuln.evidence) if vuln.evidence else {}
    except (json.JSONDecodeError, TypeError):
        evidence = {}

    evidence["nvd"] = {
        "cve_id":          cve_id,
        "cvss_score":      cache.cvss_score,
        "cvss_v2_score":   cache.cvss_v2_score,
        "severity":        cache.severity,
        "cwe_id":          cache.cwe_id,
        "epss_score":      cache.epss_score,
        "epss_percentile": cache.epss_percentile,
        "published_date":  cache.published_date.isoformat() if cache.published_date else None,
        "references":      (cache.references or [])[:5],
    }

    vuln.evidence = json.dumps(evidence)

    logger.info(
        f"Enriched vuln {vuln.id[:8]} with NVD data for {cve_id}: "
        f"cvss={cache.cvss_score} severity={cache.severity} epss={cache.epss_score}"
    )
    return True


# ==============================================================================
# BULK ENRICHMENT -- retroactively enrich existing vulnerabilities
# ==============================================================================

def enrich_all_cve_vulnerabilities(organization_id: str = None,
                                    api_key: str = None) -> dict:
    """
    Retroactively enrich all CVE vulnerabilities that haven't been
    enriched yet. Intended to be run as a one-off Celery task or
    management command, NOT inside the main scan flow (it iterates
    every matching vuln with a throttled NVD call per CVE, so it can
    take a while on a large dataset).

    Args:
        organization_id : if provided, only enrich vulns for this org
        api_key          : NVD API key override

    Returns:
        {"enriched": N, "skipped": N, "failed": N}
    """
    from app.models.vulnerability import VulnerabilityType

    query = Vulnerability.query.filter_by(
        vuln_type=VulnerabilityType.CVE,
        is_deleted=False
    )
    if organization_id:
        query = query.filter_by(organization_id=organization_id)

    vulns = query.all()
    enriched = skipped = failed = 0

    for vuln in vulns:
        cve_id = None

        match = CVE_PATTERN.search(vuln.title or "")
        if match:
            cve_id = match.group(0).upper()

        if not cve_id and vuln.evidence:
            try:
                evidence = json.loads(vuln.evidence)
                tid = evidence.get("template_id", "")
                if CVE_PATTERN.match(tid):
                    cve_id = tid.upper()
            except (json.JSONDecodeError, TypeError):
                pass

        if not cve_id:
            skipped += 1
            continue

        success = enrich_vulnerability_with_nvd(vuln, cve_id, api_key=api_key)
        if success:
            enriched += 1
        else:
            failed += 1
        # Note: fetch_from_nvd/_fetch_epss already throttle internally,
        # this loop doesn't need its own sleep on top of that.

    logger.info(
        f"Bulk NVD enrichment complete: enriched={enriched} skipped={skipped} failed={failed}"
    )
    return {"enriched": enriched, "skipped": skipped, "failed": failed}