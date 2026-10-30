"""
Smoke test v2 — covers all models + exploit_service + report_service.

Run from the backend/ directory:
    python smoketest.py

Uses SQLite (no PostgreSQL/Redis required). Safe to re-run: deletes
smoketest.db at the start each time.
"""

import os

DB_FILE = "smoketest.db"
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

os.environ["DATABASE_URL"] = f"sqlite:///{DB_FILE}"

from app import create_app, db


def main():
    app = create_app("development")

    with app.app_context():
        from app.models.organization import Organization
        from app.models.user import User
        from app.models.target import Target
        from app.models.vulnerability import (
            Vulnerability, VulnerabilityType, VulnerabilityStatus
        )
        from app.models.exploit import ExploitType, ExploitStatus
        from app.models.report import ReportPlatform, ReportStatus
        from app.models.bounty import BountyStatus, PaymentMethod
        from app.services import (
            vulnerability_service,
            target_service,
            exploit_service,
            report_service,
            bounty_service,
        )

        print("=" * 60)
        print("SMOKE TEST v2 — Bug Bounty SaaS Platform")
        print("=" * 60)

        # ── Tables ────────────────────────────────────────────────
        print("\n[1] Tables:", sorted(db.metadata.tables.keys()))
        assert len(db.metadata.tables) == 10, "Expected 10 tables"
        print("    ✓ All 10 tables present")

        # ── Organization + User ───────────────────────────────────
        org = Organization(name="Test Corp", slug="test-corp", plan="free",
                           max_members=10, max_targets=20, max_scans_per_day=5)
        db.session.add(org)
        db.session.commit()

        user = User(
            organization_id=org.id,
            username="Khouloud",
            email="khouloud@test.com",
            role="admin",
        )
        user.set_password("Kholoud123")
        raw_key = user.generate_api_key()
        db.session.add(user)
        db.session.commit()

        print(f"\n[2] Org: {org.name} ({org.id[:8]}...)")
        print(f"    User: {user.username} | role={user.role}")
        print(f"    API key prefix: {user.api_key_prefix}")
        assert user.verify_api_key(raw_key), "API key verification failed"
        print("    ✓ API key verify OK")

        # ── Target ───────────────────────────────────────────────
        target = target_service.create_target({
            "organization_id": org.id,
            "user_id": user.id,
            "domain": "example.com",
            "program_name": "Test Program",
            "platform": "hackerone",
        }, actor_id=user.id)

        print(f"\n[3] Target: {target.domain} ({target.id[:8]}...)")
        assert target.organization_id == org.id
        print("    ✓ Target created via service")

        # ── Vulnerability ─────────────────────────────────────────
        vuln = vulnerability_service.create_vulnerability({
            "organization_id": org.id,
            "user_id": user.id,
            "target_id": target.id,
            "title": "Reflected XSS on /search",
            "vuln_type": VulnerabilityType.XSS,
            "url": "https://example.com/search",
            "parameter": "q",
        }, actor_id=user.id)

        print(f"\n[4] Vulnerability: {vuln.title}")
        print(f"    fingerprint: {vuln.fingerprint[:16]}...")
        print(f"    status: {vuln.status.value}")
        assert vuln.status == VulnerabilityStatus.DISCOVERED
        print("    ✓ Vulnerability created via service")

        # Status transition
        vuln = vulnerability_service.transition_status(
            vuln.id, org.id, VulnerabilityStatus.VERIFIED, actor_id=user.id
        )
        assert vuln.status == VulnerabilityStatus.VERIFIED
        assert len(vuln.status_history) == 1
        print(f"    ✓ Status transition: DISCOVERED → VERIFIED")
        print(f"    ✓ status_history: {vuln.status_history[0]['from']} → {vuln.status_history[0]['to']}")

        # ── Exploit ───────────────────────────────────────────────
        exploit = exploit_service.create_exploit({
            "organization_id": org.id,
            "user_id": user.id,
            "vulnerability_id": vuln.id,
            "target_id": target.id,
            "title": "XSS PoC via search parameter",
            "exploit_type": ExploitType.MANUAL,
            "payload_used": "<img src=x onerror=alert(1)>",
            "impact_score": 7.5,
            "status": ExploitStatus.PENDING,
        }, actor_id=user.id)

        print(f"\n[5] Exploit: {exploit.title}")
        print(f"    type: {exploit.exploit_type.value}")
        print(f"    fingerprint copied: {exploit.fingerprint == vuln.fingerprint}")
        assert exploit.fingerprint == vuln.fingerprint, "fingerprint should be copied from vuln"
        assert exploit.organization_id == org.id
        print("    ✓ Exploit created via service")

        # Status update
        exploit = exploit_service.update_exploit_status(
            exploit.id, org.id, ExploitStatus.SUCCESSFUL, actor_id=user.id
        )
        assert exploit.status == ExploitStatus.SUCCESSFUL
        assert exploit.is_confirmed == True
        print("    ✓ Exploit status: PENDING → SUCCESSFUL (is_confirmed=True)")

        # Field update
        exploit = exploit_service.update_exploit(
            exploit.id, org.id,
            {"notes": "Confirmed in Chrome and Firefox", "impact_score": 8.5},
            actor_id=user.id
        )
        assert exploit.notes == "Confirmed in Chrome and Firefox"
        print("    ✓ Exploit fields updated via service")

        # ── Report ────────────────────────────────────────────────
        report = report_service.create_report({
            "organization_id": org.id,
            "user_id": user.id,
            "vulnerability_id": vuln.id,
            "target_id": target.id,
            "platform": ReportPlatform.HACKERONE,
            "title": "Reflected XSS in /search parameter",
            "description": "User input is not sanitized in the search endpoint, allowing injection of arbitrary HTML.",
            "steps_to_reproduce": "1. Go to /search\n2. Enter <img src=x onerror=alert(1)>\n3. Observe alert.",
            "impact": "Attacker can execute arbitrary JavaScript in victim's browser.",
            "remediation": "Use htmlspecialchars() to sanitize all user input.",
        }, actor_id=user.id)

        print(f"\n[6] Report: {report.title[:40]}...")
        print(f"    platform: {report.platform.value}")
        print(f"    status: {report.status.value}")
        assert report.status == ReportStatus.DRAFT
        print("    ✓ Report created via service")

        # Submit
        report = report_service.submit_report(
            report.id, org.id, actor_id=user.id,
            submission_url="https://hackerone.com/reports/999999"
        )
        assert report.status == ReportStatus.SUBMITTED
        assert report.submitted_at is not None
        print("    ✓ Report submitted (DRAFT → SUBMITTED)")

        # Acknowledge
        report = report_service.acknowledge_report(
            report.id, org.id, actor_id=user.id,
            vendor_response="Thank you for the report, we are investigating."
        )
        assert report.is_acknowledged == True
        print("    ✓ Report acknowledged")

        # Resolve with bounty
        report = report_service.resolve_report(
            report.id, org.id, actor_id=user.id,
            bounty_amount=500.0, bounty_currency="USD",
            vendor_response="Fixed in v2.1. Bounty awarded."
        )
        assert report.status == ReportStatus.RESOLVED
        assert report.bounty_amount == 500.0

        # Verify Vulnerability.bounty_awarded was synced
        db.session.refresh(vuln)
        assert vuln.bounty_awarded == 500.0
        assert vuln.bounty_currency == "USD"
        print("    ✓ Report resolved with $500 bounty")
        print(f"    ✓ Vulnerability.bounty_awarded synced: ${vuln.bounty_awarded} {vuln.bounty_currency}")

        # ── Bounty ────────────────────────────────────────────────
        bounty = bounty_service.propose_bounty(
            organization_id=org.id,
            vulnerability_id=vuln.id,
            amount=500.0,
            currency="USD",
            actor_id=user.id,
        )

        print(f"\n[7] Bounty: ${bounty.amount} {bounty.currency}")
        print(f"    status: {bounty.status.value}")
        assert bounty.status == BountyStatus.PROPOSED
        print("    ✓ Bounty proposed via service")

        bounty = bounty_service.approve_bounty(
            bounty.id, org.id, actor_id=user.id,
            notes="Verified XSS, approved standard rate"
        )
        assert bounty.status == BountyStatus.APPROVED
        print("    ✓ Bounty approved")

        bounty = bounty_service.mark_bounty_paid(
            bounty.id, org.id, actor_id=user.id,
            payment_method=PaymentMethod.MANUAL,
        )
        assert bounty.status == BountyStatus.PAID
        assert bounty.paid_at is not None
        print("    ✓ Bounty paid")

        # ── Events audit trail ────────────────────────────────────
        from app.models.event import Event
        event_count = Event.query.filter_by(organization_id=org.id).count()
        print(f"\n[8] Events recorded: {event_count}")
        assert event_count >= 8, f"Expected at least 8 events, got {event_count}"
        print("    ✓ Full audit trail recorded")

        # ── Multi-tenant isolation check ──────────────────────────
        org2 = Organization(name="Other Corp", slug="other-corp",
                            max_members=5, max_targets=10, max_scans_per_day=3)
        db.session.add(org2)
        db.session.commit()

        # org2 should not see org's vulnerability
        result = vulnerability_service.get_vulnerability(vuln.id, org2.id)
        assert result is None, "Cross-org data leak detected!"
        print("\n[9] Multi-tenant isolation: ✓ org2 cannot see org1 data")

        print("\n" + "=" * 60)
        print("ALL CHECKS PASSED ✓")
        print("=" * 60)
        print(f"""
Summary:
  Organizations : 2 (isolation tested)
  Users         : 1
  Targets       : 1
  Vulnerabilities: 1 (status transitions verified)
  Exploits      : 1 (status + field update verified)
  Reports       : 1 (full workflow: draft→submit→ack→resolve)
  Bounties      : 1 (propose→approve→pay)
  Events        : {event_count} (audit trail)
""")


if __name__ == "__main__":
    main()