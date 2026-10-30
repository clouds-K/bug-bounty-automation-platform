"""
Report Tasks - Celery tasks for PDF report generation.

WHY THIS IS A CELERY TASK, NOT A DIRECT FLASK ROUTE CALL:
    WeasyPrint depends on native GTK/Pango libraries that are readily
    available on Linux (confirmed working here: Ubuntu, WeasyPrint 69.0)
    but require a separate, heavy GTK3 runtime install on Windows that
    frequently fails (see: 'cannot load library libgobject-2.0-0').

    This project's Flask API runs on Windows, while Celery workers run
    on the Ubuntu VM -- exactly the same split already used for Nuclei
    (scanner.py): Flask/Windows only ever DISPATCHES work, Celery/Ubuntu
    is where the Linux-dependent library actually executes.

    Importing weasyprint at module level anywhere reachable from Flask's
    own import chain (e.g. app/services/__init__.py) will crash the
    ENTIRE API on Windows at startup, not just PDF generation -- this
    already happened once. The import must stay confined to code paths
    that only ever run on the Ubuntu worker process.

WHY THE PDF IS BASE64-ENCODED IN THE RESULT (not just a file path):
    The generated PDF lives on the Ubuntu worker's local disk (/tmp/...).
    Flask runs on a separate Windows machine and has no direct filesystem
    access to that path -- it's not on the /mnt/shared mount, and even
    if it were, cross-host file timing would be fragile. Instead, the
    task base64-encodes the PDF bytes directly into the Celery result,
    which is stored in Redis (already used as the result backend) and
    is trivially readable from Flask via AsyncResult, regardless of
    which machine either process runs on. This works well for report
    sizes seen so far (~60KB) -- if reports grow to several MB, switch
    to uploading the file to shared/object storage instead and return
    a URL, since large base64 blobs bloat the Redis result backend.

Usage from a Flask route (Windows):
    from celery_app import celery
    result = celery.send_task(
        "reports.generate_pdf",
        args=[target_id, organization_id]
    )
    # result.id is the Celery task id; poll it via AsyncResult or a
    # follow-up endpoint, same pattern as scan status polling.
"""

import base64
import logging

from celery_app import celery
from app import db
from app.models.target import Target
from app.utils.exceptions import NotFoundError

logger = logging.getLogger("bug_bounty")


@celery.task(name="reports.generate_pdf", bind=True, max_retries=1)
def generate_pdf_task(self, target_id: str, organization_id: str) -> dict:
    """
    Generates a vulnerability PDF report for target_id and returns a dict
    containing the base64-encoded PDF bytes plus basic metadata. See
    module docstring for why base64-in-result instead of a file path.
    """
    from app.services.rapportpdf import generate_vulnerability_report

    logger.info(f"Generating PDF report for target {target_id[:8]}")

    target = Target.query.filter_by(
        id=target_id, organization_id=organization_id, is_deleted=False
    ).first()
    if target is None:
        logger.error(f"Target {target_id} not found — aborting PDF generation")
        raise NotFoundError(f"Target {target_id} not found")

    try:
        pdf_path = generate_vulnerability_report(target_id, organization_id)

        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        pdf_base64 = base64.b64encode(pdf_bytes).decode("ascii")
        filename = pdf_path.split("/")[-1]

        logger.info(f"PDF report generated for target {target_id[:8]}: {len(pdf_bytes)} bytes")

        return {
            "target_id": target_id,
            "filename": filename,
            "size_bytes": len(pdf_bytes),
            "pdf_base64": pdf_base64,
        }

    except Exception as exc:
        logger.exception(f"PDF generation failed for target {target_id[:8]}")
        raise self.retry(exc=exc, countdown=10)