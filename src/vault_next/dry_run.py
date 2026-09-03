"""Pure synthetic dry-run contract used to prove stable candidate identity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from vault_next.canonical import canonical_sha256


@dataclass(frozen=True)
class SyntheticSnapshotItem:
    relative_path: str
    content_sha256: str
    byte_count: int
    item_class: str = "synthetic_text"


def plan_synthetic_dry_run(items: Iterable[SyntheticSnapshotItem]) -> list[dict[str, Any]]:
    """Map invented snapshot metadata to stable candidate records without filesystem writes."""

    result: list[dict[str, Any]] = []
    for item in sorted(items, key=lambda candidate: candidate.relative_path):
        material = {
            "byte_count": item.byte_count,
            "content_sha256": item.content_sha256,
            "item_class": item.item_class,
            "relative_path": item.relative_path,
        }
        result.append(
            {
                "candidate_id": f"candidate_sha256_{canonical_sha256(material)}",
                "disposition": "synthetic_candidate",
                "source": material,
            }
        )
    return result

