from __future__ import annotations

import json
from pathlib import Path

from proofsmith.bundle import create_bundle, write_bundle
from proofsmith.hashchain import verify_chain
from proofsmith.impact import plan_for
from proofsmith.models import ChangedFile, CheckResult, CheckStatus, VerificationRequest
from proofsmith.policy import Policy
from proofsmith.redaction import redact_text


def test_impact_plan_is_deterministic_and_explains_reasons() -> None:
    files = (
        ChangedFile("src/app.py", 4, 1),
        ChangedFile("package.json", 2, 0),
        ChangedFile("docs/guide.md", 3, 0),
    )
    plan = plan_for(files)
    assert plan.checks == tuple(sorted(plan.checks))
    assert "unit" in plan.checks
    assert "frontend-check" in plan.checks
    assert "docs-links" in plan.checks
    assert plan.reasons["unit"] == ("python:src/app.py",)


def test_policy_blocks_security_failure() -> None:
    checks = (
        CheckResult(
            "secret-scan", "Secret scan", CheckStatus.BLOCKED, "found", evidence=("line 1",)
        ),
    )
    status, reason = Policy().evaluate((ChangedFile("src/app.py", 1, 0),), checks)
    assert status is CheckStatus.BLOCKED
    assert reason == "security gate failed"


def test_redaction_removes_secret_values() -> None:
    token = "sk_" + "live_" + "example123456"
    value = "api_key=" + token + " password=" + "hunter2"
    redacted = redact_text(value)
    assert token not in redacted
    assert "hunter2" not in redacted
    assert "[REDACTED]" in redacted


def test_bundle_persists_and_hash_chain_verifies(tmp_path: Path) -> None:
    request = VerificationRequest(
        revision="abc123",
        changed_files=(ChangedFile("src/app.py", 2, 0),),
        checks=("unit",),
    )
    checks = (
        CheckResult("unit", "Unit tests", CheckStatus.PASS, "passed", evidence=("2 passed",)),
    )
    bundle = create_bundle(request, checks)
    path = write_bundle(bundle, tmp_path)
    stored = json.loads(path.read_text())
    valid, message = verify_chain([stored])
    assert valid, message
    assert stored["final_status"] == "pass"


def test_bundle_requires_evidence_for_pass() -> None:
    request = VerificationRequest(
        revision="abc123",
        changed_files=(ChangedFile("src/app.py", 2, 0),),
        checks=("unit",),
    )
    checks = (CheckResult("unit", "Unit tests", CheckStatus.PASS, "passed"),)
    bundle = create_bundle(request, checks)
    assert bundle.final_status is CheckStatus.REVIEW


def test_redacted_bundle_remains_hash_verifiable(tmp_path: Path) -> None:
    request = VerificationRequest(
        revision="abc123",
        changed_files=(ChangedFile("src/app.py", 2, 0),),
        checks=("secret-scan",),
    )
    checks = (
        CheckResult(
            "secret-scan",
            "Secret scan",
            CheckStatus.PASS,
            "clean",
            evidence=("api_key=sk_live_example123456",),
        ),
    )

    path = write_bundle(create_bundle(request, checks), tmp_path)
    stored = json.loads(path.read_text())
    valid, message = verify_chain([stored])

    assert valid, message
    assert "sk_live_example123456" not in path.read_text()
