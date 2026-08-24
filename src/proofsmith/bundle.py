"""Evidence bundle creation and persistence."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, cast

from .hashchain import bundle_hash
from .models import CheckResult, EvidenceBundle, VerificationRequest
from .policy import Policy
from .redaction import redact


def create_bundle(
    request: VerificationRequest,
    checks: tuple[CheckResult, ...],
    policy: Policy | None = None,
    previous_hash: str | None = None,
) -> EvidenceBundle:
    selected_policy = policy or Policy(name=request.policy_name)
    status, reason = selected_policy.evaluate(request.changed_files, checks)
    enriched = (
        CheckResult(
            check_id="policy",
            title=f"Policy: {selected_policy.name}",
            status=status,
            summary=reason,
            evidence=(reason,),
        ),
    )
    all_checks = checks + enriched
    provisional = EvidenceBundle.now(
        bundle_id=f"ps_{uuid.uuid4().hex[:12]}",
        request=request,
        checks=all_checks,
        content_hash="",
        previous_hash=previous_hash,
    ).to_dict()
    unsigned = {key: value for key, value in provisional.items() if key != "content_hash"}
    provisional["content_hash"] = bundle_hash(unsigned)
    return EvidenceBundle(
        schema_version=provisional["schema_version"],
        bundle_id=provisional["bundle_id"],
        created_at=provisional["created_at"],
        request=request,
        checks=all_checks,
        final_status=provisional["final_status"],
        content_hash=provisional["content_hash"],
        previous_hash=previous_hash,
    )


def write_bundle(bundle: EvidenceBundle, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{bundle.bundle_id}.json"

    # Redaction changes the canonical payload, so it must happen before hashing.
    # Otherwise verify_chain would reject every persisted bundle containing a
    # secret-shaped value even though the redacted file is intentionally safe.
    payload = redact(bundle.to_dict())
    unsigned = {key: value for key, value in payload.items() if key != "content_hash"}
    payload["content_hash"] = bundle_hash(unsigned)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    return target


def read_bundle(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text()))
