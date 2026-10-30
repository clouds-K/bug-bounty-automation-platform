"""
Scanner Task - Celery async worker for real security scans using Nuclei.

Dispatched by scan_routes.py via:
    celery.send_task(
        "scanner.run_scan",
        args=[scan.id, target_id, user.organization_id, user.id, tools]
    )

Runs inside Flask app context (via init_celery's ContextTask), so
db.session and all models work normally.

Architecture:
    scan_routes.py  ->  Celery  ->  run_scan()  ->  nuclei (Docker container)
                                                 ->  parse JSON output
                                                 ->  enrich CVEs via NVD/EPSS
                                                 ->  create Vulnerability rows
                                                 ->  update Scan progress
                                                 ->  record Events

CHANGE LOG (most recent first):
  - NVD/EPSS enrichment: CVE-tagged findings are enriched with official
    NVD data (description, CVSS, CWE, references) and EPSS exploitation
    probability via app.services.nvd_service, cached in CveCache. This
    happens AFTER the duplicate check, not before -- enriching a finding
    that turns out to be a duplicate would waste a throttled NVD/EPSS
    call on data that gets thrown away (a real risk here: rescans of the
    same target are typically 80-95% duplicates).
  - Duplicate-safe inserts: each Vulnerability insert is wrapped in its
    own SAVEPOINT (db.session.begin_nested()). A duplicate fingerprint
    (same finding rediscovered on a rescan) only rolls back that single
    insert, not the entire batch -- previously a single duplicate near
    the end of a findings list could silently wipe out every earlier
    vulnerability in the same scan.
  - Thread-based streaming with a real timeout: run_nuclei() reads the
    Docker log stream in a background daemon thread that pushes chunks
    onto a Queue. The main loop blocks on the QUEUE (with a timeout),
    never directly on container.logs(stream=True) -- which has no
    timeout of its own and can hang forever if Nuclei stops producing
    output entirely (this caused a genuine 2h stuck scan before the fix).
  - Named, labeled scan containers: each Nuclei container is named
    nuclei-scan-{scan_id} and labeled component=nuclei-scan, so a
    crashed worker leaves identifiable orphans instead of anonymous
    zombie containers that are hard to trace back to a scan (this
    happened once: a container ran undetected for 9 hours).
  - Nuclei runs inside the official projectdiscovery/nuclei Docker
    container instead of via `wsl -d Kali-Linux nuclei ...`, removing
    the Windows<->WSL2 path-translation bug that was the root cause of
    vulnerabilities_found always being 0.
  - Each scan container is resource-limited (mem/cpu capped) and
    isolated (capabilities dropped) -- safer for a multi-tenant SaaS.
  - Docker image and per-container resource caps are read from Flask's
    app.config (NUCLEI_DOCKER_IMAGE, SCAN_CONTAINER_MEM_LIMIT,
    SCAN_CONTAINER_NANO_CPUS, SCAN_CONTAINER_TIMEOUT_BUFFER_SECONDS --
    see config.py), so ops can tune them via env vars without a deploy.
  - target_url is read directly from target.scan_url (never guessed
    from domain).
  - Respects target.scan_enabled: a paused target is skipped instead of
    silently scanned.
  - Plan-based rate limiting: free/starter/pro/enterprise orgs get
    different nuclei rate-limit / timeout / daily-scan-count defaults.
  - Optional tag filter (scan.config["tags"] / target.scan_config["tags"])
    for fast, targeted scans instead of always running the full template
    catalog.
"""

import json
import logging
from datetime import datetime
import time
import threading
import queue
from app.services import ml_service

import docker
from docker.errors import DockerException, ContainerError, ImageNotFound
from flask import current_app

from celery_app import celery
from app import db
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import (
    Vulnerability, VulnerabilityType, SeverityLevel, VulnerabilityStatus
)
from app.models.target import Target
from app.models.organization import Organization
from app.models.event import Event, EntityType, EventType, EventSource
from app.services.nvd_service import extract_cve_id, enrich_vulnerability_with_nvd
from sqlalchemy.exc import IntegrityError
from app.config.plan_limits import PLAN_LIMITS

logger = logging.getLogger("bug_bounty")



# ==============================================================================
# SEVERITY MAPPING -- Nuclei severity -> SeverityLevel enum
# ==============================================================================

SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high":     SeverityLevel.HIGH,
    "medium":   SeverityLevel.MEDIUM,
    "low":      SeverityLevel.LOW,
    "info":     SeverityLevel.INFO,
    "unknown":  SeverityLevel.INFO,
}


# ==============================================================================
# VULN TYPE MAPPING -- Nuclei tags -> VulnerabilityType enum
# ==============================================================================

TAG_TO_VULN_TYPE = {
    "xss":              VulnerabilityType.XSS,
    "sqli":             VulnerabilityType.SQL_INJECTION,
    "sql":              VulnerabilityType.SQL_INJECTION,
    "lfi":              VulnerabilityType.LFI,
    "rfi":              VulnerabilityType.RFI,
    "rce":              VulnerabilityType.RCE,
    "ssrf":             VulnerabilityType.SSRF,
    "xxe":              VulnerabilityType.XXE,
    "csrf":             VulnerabilityType.CSRF,
    "idor":             VulnerabilityType.IDOR,
    "redirect":         VulnerabilityType.OPEN_REDIRECT,
    "open-redirect":    VulnerabilityType.OPEN_REDIRECT,
    "broken-auth":      VulnerabilityType.BROKEN_AUTH,
    "auth":             VulnerabilityType.BROKEN_AUTH,
    "misconfig":        VulnerabilityType.MISCONFIGURATION,
    "config":           VulnerabilityType.MISCONFIGURATION,
    "exposure":         VulnerabilityType.SENSITIVE_DATA,
    "exposure-file":    VulnerabilityType.SENSITIVE_DATA,
    "sensitive":        VulnerabilityType.SENSITIVE_DATA,
    "cve":              VulnerabilityType.CVE,
}

# Severity levels we actually store -- skip pure INFO findings unless
# they're security-relevant (not just tech-detect / fingerprint)
SKIP_TEMPLATE_IDS = {
    "tech-detect",
    "fingerprinthub-web-fingerprints",
    "waf-detect",
    "caa-fingerprint",
    "robots-txt-endpoint",
}


def _map_vuln_type(finding: dict) -> VulnerabilityType:
    """
    Map a Nuclei finding to our VulnerabilityType enum.
    Priority: tags (most specific) -> template-id -> fallback OTHER.
    """
    tags = finding.get("info", {}).get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower in TAG_TO_VULN_TYPE:
            return TAG_TO_VULN_TYPE[tag_lower]

    template_id = finding.get("template-id", "").lower()
    for key, vtype in TAG_TO_VULN_TYPE.items():
        if key in template_id:
            return vtype

    return VulnerabilityType.OTHER


def _map_severity(finding: dict) -> SeverityLevel:
    """Map Nuclei severity string to SeverityLevel enum."""
    raw = finding.get("info", {}).get("severity", "info").lower()
    return SEVERITY_MAP.get(raw, SeverityLevel.INFO)


def _extract_cvss(finding: dict):
    """Extract CVSS score and vector from Nuclei finding if present."""
    classification = finding.get("info", {}).get("classification", {})
    cvss_score  = classification.get("cvss-score")
    cvss_vector = classification.get("cvss-metrics")

    if cvss_score is not None:
        try:
            cvss_score = float(cvss_score)
            if not (0.0 <= cvss_score <= 10.0):
                cvss_score = None
        except (TypeError, ValueError):
            cvss_score = None

    return cvss_score, cvss_vector


def _should_skip(finding: dict) -> bool:
    """
    Returns True if this finding should NOT be stored as a Vulnerability.
    We skip pure discovery/tech-detection findings that have no security value.
    """
    template_id = finding.get("template-id", "")
    if template_id in SKIP_TEMPLATE_IDS:
        return True

    severity = finding.get("info", {}).get("severity", "info").lower()
    tags = finding.get("info", {}).get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    if severity == "info" and any(t in ("tech", "discovery") for t in tags):
        return True

    return False


# ==============================================================================
# DOCKER CLIENT -- lazy singleton, one per worker process
# ==============================================================================

_docker_client = None


def get_docker_client():
    """Lazy singleton -- one Docker client per worker process."""
    global _docker_client
    if _docker_client is None:
        _docker_client = docker.from_env()
    return _docker_client


# ==============================================================================
# NUCLEI RUNNER (Docker-based, thread-safe timeout)
# ==============================================================================

def run_nuclei(target_url: str, rate_limit: int = 10, timeout_minutes: int = 60,
               tags: list = None, enable_oob: bool = True, scan_id: str = None) -> list:
    """
    Run Nuclei inside an isolated Docker container and return parsed findings.

    Uses a background thread to read the Docker log stream, so the main
    loop waits on a Queue with a real timeout instead of blocking directly
    on container.logs(stream=True) -- which has no timeout of its own and
    can hang forever if the container stops producing output entirely.
    """
    client = get_docker_client()

    image = current_app.config.get("NUCLEI_DOCKER_IMAGE", "projectdiscovery/nuclei:latest")
    mem_limit = current_app.config.get("SCAN_CONTAINER_MEM_LIMIT", "1536m")
    nano_cpus = current_app.config.get("SCAN_CONTAINER_NANO_CPUS", 1_000_000_000)
    timeout_buffer = current_app.config.get("SCAN_CONTAINER_TIMEOUT_BUFFER_SECONDS", 120)
    templates_volume = current_app.config.get("NUCLEI_TEMPLATES_VOLUME", "nuclei-templates")

    http_timeout = current_app.config.get("NUCLEI_HTTP_TIMEOUT_SECONDS", 10)

    cmd = [
        "-u", target_url,
        "-jsonl",
        "-silent",
        "-rate-limit", str(rate_limit),
        "-timeout", str(http_timeout),
        "-duc",
    ]
    if not enable_oob:
        cmd.append("-no-interactsh")
    if tags:
        cmd += ["-tags", ",".join(tags)]

    logger.info(
        f"Running Nuclei (Docker, streamed JSONL) against {target_url}: {cmd} "
        f"(overall budget: {timeout_minutes} min, per-request timeout: {http_timeout}s)"
    )

    # Predictable container name + label, so a crashed worker can find and
    # clean up orphaned containers on next start instead of them running
    # forever invisibly.
    container_name = f"nuclei-scan-{scan_id}" if scan_id else None

    findings = []
    container = None
    try:
        container = client.containers.run(
            image=image,
            command=cmd,
            volumes={templates_volume: {"bind": "/root/nuclei-templates", "mode": "ro"}},
            detach=True,
            mem_limit=mem_limit,
            nano_cpus=nano_cpus,
            cap_drop=["ALL"],
            cap_add=["NET_RAW", "NET_BIND_SERVICE"],
            network_mode="bridge",
            name=container_name,
            labels={"app": "bug-bounty-platform", "component": "nuclei-scan"},
        )

        # -- Background thread reads Docker's log stream --------------------
        # This thread can itself block on container.logs(stream=True), but
        # that's fine: it's a daemon thread, so it never prevents worker
        # shutdown, and the main loop below never waits on IT directly --
        # only on the Queue, which always respects a real timeout.
        log_queue = queue.Queue()
        stop_signal = threading.Event()

        def _read_logs():
            try:
                for chunk in container.logs(stream=True, stdout=True, stderr=False):
                    if stop_signal.is_set():
                        return
                    log_queue.put(chunk)
            except Exception as e:
                log_queue.put(e)
            finally:
                log_queue.put(None)  # sentinel: no more logs

        reader_thread = threading.Thread(target=_read_logs, daemon=True)
        reader_thread.start()

        hard_deadline = (timeout_minutes * 60) + timeout_buffer
        deadline_time = time.monotonic() + hard_deadline

        buffer = ""
        total_bytes = 0
        timed_out = False

        while True:
            remaining = deadline_time - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break

            try:
                # Blocks on the QUEUE, not on Docker's log stream -- so it
                # respects a real timeout even if the container produces
                # absolutely no output at all.
                item = log_queue.get(timeout=min(remaining, 5))
            except queue.Empty:
                continue  # loop back, re-check the deadline

            if item is None:
                break  # reader thread finished normally (container exited)
            if isinstance(item, Exception):
                logger.error(f"Error reading nuclei logs: {item}")
                break

            text = item.decode(errors="replace")
            total_bytes += len(text)
            buffer += text

            *complete_lines, buffer = buffer.split("\n")
            for line in complete_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.debug(f"Skipping non-JSON line from nuclei output: {line[:200]}")

        stop_signal.set()

        leftover = buffer.strip()
        if leftover:
            try:
                findings.append(json.loads(leftover))
            except json.JSONDecodeError:
                logger.debug(f"Skipping trailing non-JSON line: {leftover[:200]}")

        logger.info(f"Raw output size: {total_bytes} bytes")

        if timed_out:
            logger.warning(
                f"Nuclei exceeded hard deadline of {hard_deadline}s with no response -- "
                f"force-killing container."
            )
            try:
                container.kill()
            except Exception:
                pass
            exit_code = -1
            # Let the reader thread finish cleanly now that kill() has
            # closed the Docker log stream, instead of leaving it as an
            # orphaned daemon thread on this long-running worker.
            reader_thread.join(timeout=10)
            if reader_thread.is_alive():
                logger.warning("Reader thread did not exit cleanly after container kill")
        else:
            exit_status = container.wait(timeout=30)  # container already exited, just fetching code
            exit_code = exit_status.get("StatusCode", -1)

        if exit_code not in (0, 1):
            stderr_output = container.logs(stdout=False, stderr=True, tail=200).decode(errors="replace")
            logger.warning(f"Nuclei container exited with code {exit_code}: {stderr_output[:500]}")

    except ContainerError as e:
        logger.error(f"Nuclei container error: {e}")
    except ImageNotFound:
        logger.error(f"Image {image} not found locally. Run: docker pull {image}")
    except DockerException as e:
        logger.error(f"Docker error while running Nuclei: {e}")
    except Exception as e:
        logger.error(f"Unexpected error running Nuclei container: {e}")
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass

    return findings


# ==============================================================================
# MAIN CELERY TASK
# ==============================================================================

@celery.task(name="scanner.run_scan", bind=True, max_retries=2)
def run_scan(self, scan_id: str, target_id: str, organization_id: str,
             actor_id: str, tools: list, scan_type="full"):
    """
    Execute a real security scan using Nuclei and store findings as Vulnerabilities.

    Parameters:
        scan_id         : UUID of the Scan row to update
        target_id       : UUID of the Target being scanned
        organization_id : UUID of the org (multi-tenant safety)
        actor_id        : UUID of the user who triggered the scan
        tools           : list of tool names (currently only "nuclei" is implemented)
        scan_type       : "full" | "custom" (enables OOB/interactsh) or
                           anything else, e.g. "quick" (disables it)
    """
    logger.info(f"Scan {scan_id[:8]} started — target={target_id[:8]} tools={tools}")

    scan = Scan.query.filter_by(
        id=scan_id, organization_id=organization_id
    ).first()

    if not scan:
        logger.error(f"Scan {scan_id} not found — aborting")
        return

    target = Target.query.filter_by(
        id=target_id, organization_id=organization_id, is_deleted=False
    ).first()

    if not target:
        logger.error(f"Target {target_id} not found — aborting scan {scan_id}")
        scan.mark_failed(error_message="Target not found")
        db.session.commit()
        return

    # -- Respect scan_enabled (paused targets) -------------------------------
    if not target.scan_enabled:
        logger.warning(f"Target {target_id[:8]} has scan_enabled=False — aborting scan {scan_id}")
        scan.mark_failed(error_message="Scanning is paused for this target")
        db.session.commit()
        return

    target_url = target.scan_url

    if not target_url:
        logger.error(f"Target {target_id[:8]} has no scan_url — aborting scan {scan_id}")
        scan.mark_failed(error_message="Target has no scan_url configured")
        db.session.commit()
        return

    # -- Plan-based defaults --------------------------------------------------
    org = Organization.query.get(organization_id)
    plan_defaults = PLAN_LIMITS.get(org.plan if org else "free", PLAN_LIMITS["free"])

    # Resolution order: target.scan_config > scan.config > plan defaults
    target_config = target.scan_config or {}
    scan_config = scan.config or {}

    rate_limit = (
        target_config.get("rate_limit")
        or scan_config.get("rate_limit")
        or plan_defaults["rate_limit"]
    )
    timeout_minutes = (
        target_config.get("timeout_minutes")
        or scan_config.get("timeout_minutes")
        or plan_defaults["timeout_minutes"]
    )
    # Optional tag filter for faster/targeted scans, e.g. ["cve","exposure"]
    scan_tags = (
        target_config.get("tags")
        or scan_config.get("tags")
        or None
    )

    try:
        # -- Mark as RUNNING ---------------------------------------------
        scan.mark_started()
        target.mark_scan_started()
        db.session.commit()

        found_count = 0
        total_tools = len(tools)

        # -- Run each tool -------------------------------------------------
        for idx, tool in enumerate(tools):

            if tool == "nuclei":
                findings = run_nuclei(
                    target_url=target_url,
                    rate_limit=rate_limit,
                    timeout_minutes=timeout_minutes,
                    tags=scan_tags,
                    enable_oob=scan_type in ("full", "custom"),
                    scan_id=scan_id,
                )

                logger.info(f"Nuclei returned {len(findings)} raw findings for {target_url}")

                duplicate_count = 0

                # -- Process each finding ---------------------------------
                for finding in findings:
                    if _should_skip(finding):
                        continue

                    vuln_type  = _map_vuln_type(finding)
                    severity   = _map_severity(finding)
                    cvss_score, cvss_vector = _extract_cvss(finding)

                    name        = finding.get("info", {}).get("name", "Unknown Finding")
                    description = finding.get("info", {}).get("description", "")
                    matched_at  = finding.get("matched-at", target_url)
                    template_id = finding.get("template-id", "")
                    template_url = finding.get("template-url", "")

                    cwe_ids = finding.get("info", {}).get(
                        "classification", {}
                    ).get("cwe-id", [])
                    cwe_str = ", ".join(cwe_ids) if cwe_ids else None

                    remediation = finding.get("info", {}).get("remediation")

                    request_raw  = finding.get("request", "")
                    response_raw = finding.get("response", "")
                    if len(request_raw) > 2000:
                        request_raw = request_raw[:2000] + "... [truncated]"
                    if len(response_raw) > 2000:
                        response_raw = response_raw[:2000] + "... [truncated]"
                    cwe_id_value = cwe_ids[0] if cwe_ids else None
                    cwe_source_value = "nuclei" if cwe_id_value else None

                    if not cwe_id_value and description:
                        ml_result = ml_service.predict_cwe(description)
                        if ml_result:
                            cwe_id_value = ml_result["cwe_id"]
                            cwe_source_value = ml_result["source"]  # "ml_estimate"

                    vuln = Vulnerability(
                        organization_id=organization_id,
                        user_id=actor_id,
                        target_id=target_id,
                        title=f"[{tool.upper()}] {name}",
                        vuln_type=vuln_type,
                        severity=severity,
                        status=VulnerabilityStatus.DISCOVERED,
                        url=matched_at,
                        description=description,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        remediation=remediation,
                        cwe_id=cwe_id_value,
                        cwe_source=cwe_source_value,
                        evidence=json.dumps({
                            "template_id":  template_id,
                            "template_url": template_url,
                            "cwe":          cwe_str,
                            "request":      request_raw[:500],
                            "matched_at":   matched_at,
                        }),
                        http_method="GET",
                    )

                    # Each vulnerability gets its own SAVEPOINT. A duplicate
                    # fingerprint (same finding rediscovered on a rescan)
                    # only rolls back THIS insert -- every earlier
                    # vulnerability already added in this same loop stays
                    # intact and gets committed at the end.
                    try:
                        with db.session.begin_nested():
                            db.session.add(vuln)
                            db.session.flush()  # get vuln.id for Event

                            event = Event.record(
                                organization_id=organization_id,
                                entity_type=EntityType.VULNERABILITY,
                                entity_id=vuln.id,
                                event_type=EventType.VULN_CREATED,
                                actor_id=actor_id,
                                source=EventSource.SCANNER,
                                payload={
                                    "tool":         tool,
                                    "template_id":  template_id,
                                    "vuln_type":    vuln_type.value,
                                    "severity":     severity.value,
                                    "scan_id":      scan_id,
                                    "matched_at":   matched_at,
                                }
                            )
                            db.session.add(event)
                    except IntegrityError:
                        duplicate_count += 1
                        logger.info(
                            f"Doublon ignoré (déjà en base) : {template_id} sur {matched_at}"
                        )
                        continue

                    # NVD/EPSS enrichment happens AFTER the duplicate check,
                    # not before -- enriching a finding that turns out to be
                    # a duplicate would waste a throttled network call on
                    # data that's about to be thrown away. Rescans of the
                    # same target are typically 80-95% duplicates, so this
                    # ordering matters a lot in practice.
                    cve_id = extract_cve_id(finding)

                if cve_id:
                    enrich_vulnerability_with_nvd(vuln, cve_id)

                    found_count += 1

                db.session.commit()
                logger.info(
                    f"Scan {scan_id[:8]}: {found_count} nouvelles vulnérabilités, "
                    f"{duplicate_count} doublons ignorés"
                )

            else:
                logger.warning(f"Tool '{tool}' not yet implemented — skipping")

            # Update progress after each tool
            progress = int(100 * (idx + 1) / total_tools)
            scan.update_progress(progress)
            db.session.commit()

        # -- Mark COMPLETED ----------------------------------------------
        scan.mark_completed(vulnerabilities_found=found_count)

        if target:
            target.mark_scan_completed()
            target.update_vuln_stats()

        # Record scan completion event
        completion_event = Event.record(
            organization_id=organization_id,
            entity_type=EntityType.TARGET,
            entity_id=target_id,
            event_type=EventType.OTHER,
            actor_id=actor_id,
            source=EventSource.SCANNER,
            payload={
                "action":                "scan_completed",
                "scan_id":               scan_id,
                "vulnerabilities_found": found_count,
                "tools":                 tools,
                "target_url":            target_url,
            }
        )
        db.session.add(completion_event)
        db.session.commit()

        logger.info(f"Scan {scan_id[:8]} completed — {found_count} vulnerabilities found on {target_url}")
        return {"scan_id": scan_id, "vulnerabilities_found": found_count}

    except Exception as exc:
        logger.exception(f"Scan {scan_id[:8]} failed")
        try:
            scan.mark_failed(error_message=str(exc))
            if target:
                target.mark_scan_failed()
            db.session.commit()
        except Exception:
            db.session.rollback()

        raise self.retry(exc=exc, countdown=120 * (self.request.retries + 1))