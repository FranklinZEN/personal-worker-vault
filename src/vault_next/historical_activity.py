"""S6-H2-C candidate-only historical activity and artifact reconstruction.

The module accepts caller-supplied immutable bytes or validated analytical output. It has no legacy
source discovery, network, model, connector, skill-activation, promotion, current-work, or U2 ability.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT = "vault-next-historical-activity-reconstruction/1.0.0"
PURPOSE = "historical_activity_reconstruction"
FAMILY = "meeting_workstream_history"
CUTOFF = "2026-08-01T00:00:00Z"
DISCLOSURE = "hybrid_visible_hosted_exact_packs_local_private_storage"
PARSER_VERSION = "safe_logical_parser/1.1.0"
CODEX_MARKDOWN_PROFILE = "codex_markdown_conversation/0.1"
CODEX_MANIFEST_PROFILE = "codex_export_manifest_json/0.1"
ITEM_METHOD = "historical_item_observer/1.1.0"
CONVERSATION_METHOD = "historical_conversation_observer/1.1.0"
RELATIONSHIP_METHOD = "historical_relationship_reconstructor/1.0.0"

MEETING_TYPES = frozenset(
    {
        "one_to_one", "staff_meeting", "project_alignment", "technical_deep_dive", "planning",
        "status_review", "decision_review", "working_session", "retrospective",
        "external_or_interview", "company_all_hands", "mixed", "non_meeting", "unknown",
    }
)
TIME_FIELDS = frozenset(
    {
        "source_created_at", "source_modified_at", "event_started_at", "event_ended_at",
        "conversation_started_at", "conversation_ended_at", "artifact_generated_at", "effective_at",
    }
)
TIME_PRECISIONS = frozenset({"instant", "minute", "day", "month", "interval", "unknown"})
TIME_BASES = frozenset(
    {
        "export_structured", "source_metadata", "frontmatter", "explicit_content", "filename",
        "relationship_inference", "unknown",
    }
)
CONFIDENCES = frozenset({"high", "medium", "low", "unavailable"})
PERSON_ROLES = frozenset({"participant", "speaker_or_author", "mentioned_person", "intended_audience"})
SKILL_BASES = frozenset(
    {"explicitly_invoked", "source_reported", "strongly_inferred", "weakly_inferred", "unknown"}
)
SKILL_EVIDENCE_TYPES = frozenset(
    {
        "owner_explicit_request", "exact_tool_invocation", "source_declared_invocation",
        "artifact_declared_method",
    }
)
RELATION_STATUSES = frozenset({"candidate", "source_reported", "structurally_verified"})
RELATION_BASES = frozenset(
    {
        "exact_bytes", "export_declared", "explicit_reference", "timestamp_adjacency",
        "content_evidence", "bounded_analysis",
    }
)
ITEM_CLASSES = frozenset(
    {
        "meeting_transcript", "meeting_notes", "meeting_debrief", "meeting_preparation",
        "meeting_self_review", "conversation_evidence", "artifact_revision", "deep_dive",
        "decision_brief", "status_or_continuity", "outbound_draft", "project_or_workstream_note",
        "follow_up", "retrospective", "supporting_evidence", "skill_or_method_source",
        "reference_or_administrative", "multi_meeting_bundle", "unknown", "unsupported",
    }
)
VIEW_NAMES = (
    "daily_timeline", "strands", "people", "meeting_types", "artifact_lineage", "missing_evidence"
)


class HistoricalActivityError(RuntimeError):
    """An H2-C parser, observation, batch, publication, or recovery failed closed."""


class ExistingV2HistoricalActivityAuthority(Protocol):
    """Purpose-only seam over one existing v2 identity."""

    def authorize_historical_activity_reconstruction(self, manifest: dict[str, Any]) -> dict[str, Any]: ...

    def verify_historical_activity_reconstruction(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def read_historical_activity_reconstruction_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...

    def verify_archived_historical_activity_reconstruction(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class HistoricalActivityCaps:
    max_members: int = 2_000
    max_logical_records: int = 5_000
    max_decoded_chars: int = 512 * 1024 * 1024
    max_member_bytes: int = 128 * 1024 * 1024
    max_pack_records: int = 20
    max_pack_chars: int = 250_000

    def validate(self) -> None:
        if any(value <= 0 for value in vars(self).values()):
            raise HistoricalActivityError("historical activity caps must be positive")
        if self.max_pack_records > self.max_logical_records:
            raise HistoricalActivityError("historical activity pack cap exceeds record cap")


@dataclass(frozen=True)
class LogicalRecord:
    member_ref: str
    logical_record_id: str
    source_class: str
    profile: str
    object_digest: str
    content: str
    anchors: tuple[dict[str, Any], ...]
    logical_record_digest: str

    def descriptor(self) -> dict[str, Any]:
        return {
            "member_ref": self.member_ref,
            "logical_record_id": self.logical_record_id,
            "source_class": self.source_class,
            "profile": self.profile,
            "object_digest": self.object_digest,
            "content_sha256": sha256_hex(self.content.encode("utf-8")),
            "anchors": list(self.anchors),
            "logical_record_digest": self.logical_record_digest,
        }


@dataclass(frozen=True)
class AnalysisPack:
    pack_index: int
    record_digests: tuple[str, ...]
    member_refs: tuple[str, ...]
    character_count: int
    records: tuple[dict[str, Any], ...]
    pack_digest: str


@dataclass(frozen=True)
class PreparedHistoricalActivity:
    manifest: dict[str, Any]
    package: dict[str, Any]


@dataclass(frozen=True)
class HistoricalActivityResult:
    status: str
    event_id: str
    receipt_id: str


class SafeLogicalParser:
    """Parse exact supplied bytes only; never discovers a path or follows a reference."""

    def __init__(self, caps: HistoricalActivityCaps) -> None:
        caps.validate()
        self.caps = caps

    def parse(self, member: dict[str, Any], material: bytes) -> tuple[LogicalRecord, ...]:
        self._member(member, material)
        if member["source_class"] == "codex_export":
            if member["profile"] == "markdown_text":
                return (self._codex_markdown(member, material),)
            if member["profile"] == "json" and member["member_ref"].endswith("manifest.json"):
                return (self._codex_manifest(member, material),)
            raise HistoricalActivityError("historical activity Codex profile is unsupported")
        if member["profile"] in {"markdown_text", "plain_text"}:
            return (self._text(member, material),)
        if member["profile"] == "json" and member["source_class"] == "claude_export":
            return self._claude(member, material)
        if (
            member["profile"] == "opaque_binary"
            and member["source_class"] == "claude_export"
            and member["member_ref"].endswith(".jsonl")
        ):
            return (self._claude_jsonl(member, material),)
        raise HistoricalActivityError("historical activity member profile is unsupported")

    def _member(self, member: dict[str, Any], material: bytes) -> None:
        required = {
            "member_ref", "source_class", "profile", "content_sha256", "byte_count",
        }
        if set(member) != required or member["source_class"] not in {
            "legacy_vault", "claude_export", "codex_export",
        }:
            raise HistoricalActivityError("historical activity member descriptor is invalid")
        if not isinstance(material, bytes) or len(material) != member["byte_count"]:
            raise HistoricalActivityError("historical activity member byte count changed")
        if len(material) > self.caps.max_member_bytes or sha256_hex(material) != member["content_sha256"]:
            raise HistoricalActivityError("historical activity member digest or cap failed")

    def _text(self, member: dict[str, Any], material: bytes) -> LogicalRecord:
        try:
            content = material.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HistoricalActivityError("historical activity text is not UTF-8") from exc
        anchors = []
        for index, line in enumerate(content.splitlines(), start=1):
            if line.strip():
                anchors.append(
                    {
                        "anchor_id": f"{member['member_ref']}#line-{index:06d}",
                        "kind": "line", "locator": f"line:{index}",
                        "text_sha256": sha256_hex(line.encode("utf-8")),
                    }
                )
        if not anchors:
            anchors.append(
                {
                    "anchor_id": f"{member['member_ref']}#empty",
                    "kind": "empty", "locator": "empty", "text_sha256": sha256_hex(b""),
                }
            )
        return self._record(member, member["member_ref"], content, tuple(anchors))

    def _codex_markdown(self, member: dict[str, Any], material: bytes) -> LogicalRecord:
        try:
            content = material.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HistoricalActivityError("historical activity Codex Markdown is not UTF-8") from exc
        if len(content) > self.caps.max_decoded_chars:
            raise HistoricalActivityError("historical activity decoded-text cap exceeded")
        lines = content.splitlines()
        metadata = self._codex_frontmatter(lines)
        kind = metadata.get("kind")
        anchors = tuple(
            {
                "anchor_id": f"{member['member_ref']}#line-{index:06d}",
                "kind": "codex_line", "locator": f"line:{index}",
                "text_sha256": sha256_hex(line.encode("utf-8")),
            }
            for index, line in enumerate(lines, start=1)
        )
        if kind == "archive-manifest":
            if metadata.get("source") != "Codex desktop task inventory and task reader":
                raise HistoricalActivityError("historical activity Codex source marker is invalid")
            return self._record(member, member["member_ref"], content, anchors)
        if metadata.get("source") != "codex-app task reader":
            raise HistoricalActivityError("historical activity Codex source marker is invalid")
        if kind != "conversation-export":
            raise HistoricalActivityError("historical activity Codex Markdown kind is invalid")
        required = {
            "project", "project_id", "thread_id", "title", "status_at_export", "completeness",
            "created_at", "updated_at", "exported_at", "turns", "messages",
            "truncated_message_items",
        }
        if not required.issubset(metadata) or metadata["project"] != "vault":
            raise HistoricalActivityError("historical activity Codex conversation metadata is invalid")
        try:
            turns = int(metadata["turns"])
            messages = int(metadata["messages"])
        except ValueError as exc:
            raise HistoricalActivityError("historical activity Codex counts are invalid") from exc
        turn_numbers = [
            int(match.group(1)) for line in lines
            if (match := re.fullmatch(r"## Turn ([1-9][0-9]*) — .+", line))
        ]
        message_count = sum(
            line == "### User"
            or re.fullmatch(r"### Assistant — (commentary|final answer)", line) is not None
            for line in lines
        )
        if (
            turns <= 0 or messages <= 0 or turn_numbers != list(range(1, turns + 1))
            or message_count != messages
            or not any(line.startswith("# Codex conversation — ") for line in lines)
        ):
            raise HistoricalActivityError("historical activity Codex transcript structure changed")
        thread_id = metadata["thread_id"]
        if not thread_id or not re.fullmatch(r"[0-9a-f-]+", thread_id):
            raise HistoricalActivityError("historical activity Codex thread identity is invalid")
        return self._record(
            member, thread_id, content, anchors, profile=CODEX_MARKDOWN_PROFILE,
        )

    @staticmethod
    def _codex_frontmatter(lines: list[str]) -> dict[str, str]:
        if not lines or lines[0] != "---":
            raise HistoricalActivityError("historical activity Codex frontmatter is unavailable")
        try:
            end = lines.index("---", 1)
        except ValueError as exc:
            raise HistoricalActivityError("historical activity Codex frontmatter is unterminated") from exc
        metadata: dict[str, str] = {}
        for line in lines[1:end]:
            if not line.strip():
                continue
            key, separator, value = line.partition(":")
            if not separator or not key or key in metadata:
                raise HistoricalActivityError("historical activity Codex frontmatter is invalid")
            normalized = value.strip()
            if len(normalized) >= 2 and normalized[0] == normalized[-1] == '"':
                normalized = normalized[1:-1]
            metadata[key] = normalized
        return metadata

    def _codex_manifest(self, member: dict[str, Any], material: bytes) -> LogicalRecord:
        try:
            content = material.decode("utf-8")
            parsed = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HistoricalActivityError("historical activity Codex manifest is invalid") from exc
        required = {
            "schema_version", "export_name", "exported_at", "project", "inclusion_policy",
            "coverage", "totals", "threads",
        }
        if not isinstance(parsed, dict) or set(parsed) != required:
            raise HistoricalActivityError("historical activity Codex manifest structure changed")
        threads = parsed["threads"]
        if not isinstance(threads, list) or not threads or len(threads) > self.caps.max_logical_records:
            raise HistoricalActivityError("historical activity Codex manifest thread count is invalid")
        identities: set[str] = set()
        files: set[str] = set()
        anchors: list[dict[str, Any]] = []
        for key in sorted(required - {"threads"}):
            encoded = canonical_bytes(parsed[key])
            anchors.append(
                {
                    "anchor_id": f"{member['member_ref']}#/{key}", "kind": "json_pointer",
                    "locator": f"/{key}", "text_sha256": sha256_hex(encoded),
                }
            )
        thread_fields = {
            "id", "title", "status", "created_at", "updated_at", "turn_count", "message_count",
            "file", "completeness", "truncated_message_items", "non_text_references",
        }
        for index, thread in enumerate(threads):
            if not isinstance(thread, dict) or not thread_fields.issubset(thread):
                raise HistoricalActivityError("historical activity Codex manifest thread is invalid")
            identity, filename = thread["id"], thread["file"]
            if (
                not isinstance(identity, str) or not identity or identity in identities
                or not isinstance(filename, str) or not filename or filename in files
            ):
                raise HistoricalActivityError("historical activity Codex manifest linkage is invalid")
            identities.add(identity)
            files.add(filename)
            anchors.append(
                {
                    "anchor_id": f"{member['member_ref']}#/threads/{identity}",
                    "kind": "json_pointer", "locator": f"/threads/{index}",
                    "text_sha256": sha256_hex(canonical_bytes(thread)),
                }
            )
        logical_id = str(parsed["export_name"])
        if not logical_id:
            raise HistoricalActivityError("historical activity Codex manifest identity is invalid")
        return self._record(
            member, logical_id, content, tuple(anchors), profile=CODEX_MANIFEST_PROFILE,
        )

    def _claude(self, member: dict[str, Any], material: bytes) -> tuple[LogicalRecord, ...]:
        try:
            parsed = json.loads(material)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HistoricalActivityError("historical activity Claude JSON is invalid") from exc
        conversations = parsed.get("conversations") if isinstance(parsed, dict) else parsed
        if not isinstance(conversations, list) or not conversations:
            raise HistoricalActivityError("historical activity Claude conversation list is unavailable")
        if len(conversations) > self.caps.max_logical_records:
            raise HistoricalActivityError("historical activity logical-record cap exceeded")
        records = []
        for index, conversation in enumerate(conversations):
            if not isinstance(conversation, dict):
                raise HistoricalActivityError("historical activity Claude conversation is invalid")
            conversation_id = conversation.get("uuid") or conversation.get("id")
            messages = conversation.get("chat_messages") or conversation.get("messages")
            if not isinstance(conversation_id, str) or not conversation_id or not isinstance(messages, list):
                raise HistoricalActivityError("historical activity Claude identity/messages are invalid")
            lines: list[str] = []
            anchors: list[dict[str, Any]] = []
            for message_index, message in enumerate(messages):
                if not isinstance(message, dict):
                    raise HistoricalActivityError("historical activity Claude message is invalid")
                message_id = message.get("uuid") or message.get("id") or f"message-{message_index}"
                sender = message.get("sender") or message.get("role")
                text = message.get("text") or message.get("content")
                if not isinstance(message_id, str) or not isinstance(sender, str) or not isinstance(text, str):
                    raise HistoricalActivityError("historical activity Claude message fields are invalid")
                lines.append(f"{sender}: {text}")
                anchors.append(
                    {
                        "anchor_id": f"{member['member_ref']}#{conversation_id}/{message_id}",
                        "kind": "json_message", "locator": f"/{index}/messages/{message_index}",
                        "text_sha256": sha256_hex(text.encode("utf-8")),
                    }
                )
            content = "\n".join(lines)
            records.append(self._record(member, conversation_id, content, tuple(anchors)))
        if sum(len(record.content) for record in records) > self.caps.max_decoded_chars:
            raise HistoricalActivityError("historical activity decoded-text cap exceeded")
        return tuple(records)

    def _claude_jsonl(self, member: dict[str, Any], material: bytes) -> LogicalRecord:
        """Parse one explicitly selected Claude Code session without opening tool-result siblings."""

        try:
            text = material.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HistoricalActivityError("historical activity Claude JSONL is not UTF-8") from exc
        entries = self._claude_jsonl_entries(text)
        if not entries or len(entries) > self.caps.max_logical_records:
            raise HistoricalActivityError("historical activity Claude JSONL record count is invalid")
        canonical_lines: list[str] = []
        anchors: list[dict[str, Any]] = []
        for index, (line, first_line, last_line) in enumerate(entries, start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HistoricalActivityError("historical activity Claude JSONL line is invalid") from exc
            if not isinstance(value, dict):
                raise HistoricalActivityError("historical activity Claude JSONL entry is invalid")
            # Claude Code session entries can contain finite JSON numbers (for example,
            # a tool-result duration).  Canonical records deliberately reject floats,
            # so retain their exact IEEE-754 representation in a tagged derived value
            # before stable anchoring.  The immutable original bytes remain bound by
            # ``object_digest``; this conversion only makes the parser deterministic.
            entry = canonical_bytes(self._normalise_jsonl_value(value)).decode("utf-8")
            canonical_lines.append(entry)
            entry_id = value.get("uuid") or value.get("id") or f"line-{index:06d}"
            if not isinstance(entry_id, str) or not entry_id:
                raise HistoricalActivityError("historical activity Claude JSONL identity is invalid")
            anchors.append(
                {
                    "anchor_id": f"{member['member_ref']}#{entry_id}",
                    "kind": "jsonl_record",
                    "locator": (
                        f"line:{first_line}" if first_line == last_line
                        else f"lines:{first_line}-{last_line}"
                    ),
                    "text_sha256": sha256_hex(entry.encode("utf-8")),
                }
            )
        content = "\n".join(canonical_lines)
        if len(content) > self.caps.max_decoded_chars:
            raise HistoricalActivityError("historical activity decoded-text cap exceeded")
        logical_id = member["member_ref"].rsplit(":", 1)[-1].rsplit("/", 1)[-1].removesuffix(".jsonl")
        return self._record(member, logical_id, content, tuple(anchors))

    @staticmethod
    def _claude_jsonl_entries(text: str) -> tuple[tuple[str, int, int], ...]:
        """Split a Claude session into top-level JSON entries without losing citations.

        Some real Claude Code exports contain literal control characters inside JSON
        strings.  They are malformed JSONL but have an otherwise recoverable,
        unambiguous top-level-object structure.  Canonically escape only those controls
        while inside a string, retain the original physical line span in the anchor, and
        reject any unbalanced or non-object stream.
        """

        entries: list[tuple[str, int, int]] = []
        buffer: list[str] = []
        depth = 0
        in_string = False
        escaped = False
        line = 1
        start_line = 1
        for character in text:
            if in_string:
                if escaped:
                    buffer.append(character)
                    escaped = False
                elif character == "\\":
                    buffer.append(character)
                    escaped = True
                elif character == '"':
                    buffer.append(character)
                    in_string = False
                elif ord(character) < 0x20:
                    buffer.append(json.dumps(character)[1:-1])
                    if character == "\n":
                        line += 1
                else:
                    buffer.append(character)
                continue

            if character == '"':
                in_string = True
                buffer.append(character)
                continue
            if character in "{[":
                depth += 1
                buffer.append(character)
                continue
            if character in "}]":
                depth -= 1
                if depth < 0:
                    raise HistoricalActivityError("historical activity Claude JSONL nesting is invalid")
                buffer.append(character)
                continue
            if character == "\n":
                if depth == 0 and "".join(buffer).strip():
                    entries.append(("".join(buffer), start_line, line))
                    buffer = []
                    start_line = line + 1
                else:
                    buffer.append(character)
                line += 1
                continue
            buffer.append(character)
        if in_string or escaped or depth != 0:
            raise HistoricalActivityError("historical activity Claude JSONL stream is incomplete")
        if "".join(buffer).strip():
            entries.append(("".join(buffer), start_line, line))
        if any(not item[0].lstrip().startswith("{") for item in entries):
            raise HistoricalActivityError("historical activity Claude JSONL entry is not an object")
        return tuple(entries)

    @classmethod
    def _normalise_jsonl_value(cls, value: Any) -> Any:
        """Return a canonical-safe representation of an explicitly selected JSONL entry.

        Python's JSON decoder accepts ``NaN`` and infinities even though they are not
        portable JSON values.  Reject them.  Finite floats are preserved losslessly as
        tagged hexadecimal strings because they are only parser-level evidence fields,
        never a source for semantic numeric inference.
        """

        if isinstance(value, float):
            if not math.isfinite(value):
                raise HistoricalActivityError("historical activity JSONL float is non-finite")
            return {"$vault_next_json_float_hex": value.hex()}
        if isinstance(value, list):
            return [cls._normalise_jsonl_value(item) for item in value]
        if isinstance(value, dict):
            return {key: cls._normalise_jsonl_value(item) for key, item in value.items()}
        return value

    @staticmethod
    def _record(
        member: dict[str, Any], logical_record_id: str, content: str,
        anchors: tuple[dict[str, Any], ...], *, profile: str | None = None,
    ) -> LogicalRecord:
        record_profile = profile or member["profile"]
        descriptor = {
            "member_ref": member["member_ref"], "logical_record_id": logical_record_id,
            "source_class": member["source_class"], "profile": record_profile,
            "object_digest": member["content_sha256"], "content_sha256": sha256_hex(content.encode("utf-8")),
            "anchors": list(anchors),
        }
        return LogicalRecord(
            member["member_ref"], logical_record_id, member["source_class"], record_profile,
            member["content_sha256"], content, anchors, canonical_sha256(descriptor),
        )


class HistoricalActivityCoordinator:
    """Validate analytical outputs and append one candidate-only historical package."""

    def __init__(
        self, bundle_root: Path, schemas: SchemaRegistry,
        authority: ExistingV2HistoricalActivityAuthority, *,
        caps: HistoricalActivityCaps = HistoricalActivityCaps(),
        id_factory: ULIDFactory = DEFAULT_FACTORY, fail_before_event: bool = False,
    ) -> None:
        caps.validate()
        self.root = bundle_root
        self.schemas = schemas
        self.authority = authority
        self.caps = caps
        self.ids = id_factory
        self.fail_before_event = fail_before_event

    def build_packs(self, records: tuple[LogicalRecord, ...]) -> tuple[AnalysisPack, ...]:
        self._records(records)
        packs: list[AnalysisPack] = []
        current: list[dict[str, Any]] = []
        characters = 0
        for record in records:
            for entry in self._pack_entries(record):
                size = len(entry["content"])
                if current and (
                    len(current) == self.caps.max_pack_records
                    or characters + size > self.caps.max_pack_chars
                ):
                    packs.append(self._pack(len(packs), current))
                    current, characters = [], 0
                current.append(entry)
                characters += size
        if current:
            packs.append(self._pack(len(packs), current))
        return tuple(packs)

    def build_item_observation(
        self, record: LogicalRecord, parent: dict[str, str], payload: dict[str, Any]
    ) -> dict[str, Any]:
        expected = {
            "item_class", "temporal_assertions", "people", "meeting_types", "strands", "inputs",
            "generated_artifacts", "skill_triggers", "statements", "owner_dispositions", "conflicts",
            "omissions", "child_event_occurrences",
        }
        if set(payload) != expected or payload["item_class"] not in ITEM_CLASSES:
            raise HistoricalActivityError("historical item payload is invalid")
        citations = self._semantic_payload(record, payload)
        self._times(payload["temporal_assertions"], citations)
        self._people(payload["people"])
        self._meeting_types(payload["meeting_types"])
        self._strands(payload["strands"])
        self._skill_triggers(payload["skill_triggers"])
        self._child_events(record, payload["item_class"], payload["child_event_occurrences"])
        observation = {
            "schema_version": "1.0", "observation_id": self.ids.new("artifact"),
            "observation_version": 1, "observation_type": "historical_item",
            **parent, "member_ref": record.member_ref, "logical_record_id": record.logical_record_id,
            "object_digest": record.object_digest, "source_class": record.source_class,
            "item_class": payload["item_class"], "parser_version": PARSER_VERSION,
            "method_version": ITEM_METHOD, "prompt_version": ITEM_METHOD,
            **{key: payload[key] for key in expected if key != "item_class"},
            "citation_refs": sorted(citations), "recorded_at": timestamp(aware_utc_now()),
            **self._fences(),
        }
        observation["observation_digest"] = canonical_sha256(observation)
        self._item(observation, record)
        return observation

    def revise_item_observation(
        self, prior: dict[str, Any], record: LogicalRecord,
        parent: dict[str, str], payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Create an immutable revision while retaining the prior observation identity."""

        self._prior_observation(prior, record, parent, "historical_item")
        self._item(prior, record)
        revised = self.build_item_observation(record, parent, payload)
        revised["observation_id"] = prior["observation_id"]
        revised["observation_version"] = prior["observation_version"] + 1
        revised["observation_digest"] = canonical_sha256(
            {key: value for key, value in revised.items() if key != "observation_digest"}
        )
        self._item(revised, record)
        return revised

    def build_conversation_observation(
        self, record: LogicalRecord, parent: dict[str, str], payload: dict[str, Any]
    ) -> dict[str, Any]:
        expected = {
            "temporal_assertions", "owner_intents", "inputs", "skill_triggers", "outputs", "revisions",
            "owner_dispositions", "effects", "conflicts", "omissions",
        }
        if set(payload) != expected or record.source_class != "claude_export":
            raise HistoricalActivityError("historical conversation payload is invalid")
        citations = self._semantic_payload(record, payload)
        self._times(payload["temporal_assertions"], citations)
        self._skill_triggers(payload["skill_triggers"])
        observation = {
            "schema_version": "1.0", "observation_id": self.ids.new("artifact"),
            "observation_version": 1, "observation_type": "historical_conversation_execution",
            **parent, "member_ref": record.member_ref, "logical_record_id": record.logical_record_id,
            "conversation_id": record.logical_record_id, "object_digest": record.object_digest,
            "parser_version": PARSER_VERSION, "method_version": CONVERSATION_METHOD,
            "prompt_version": CONVERSATION_METHOD, **payload,
            "citation_refs": sorted(citations), "recorded_at": timestamp(aware_utc_now()),
            **self._fences(),
        }
        observation["observation_digest"] = canonical_sha256(observation)
        self._conversation(observation, record)
        return observation

    def revise_conversation_observation(
        self, prior: dict[str, Any], record: LogicalRecord,
        parent: dict[str, str], payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Create an immutable revision while retaining the prior observation identity."""

        self._prior_observation(prior, record, parent, "historical_conversation_execution")
        self._conversation(prior, record)
        revised = self.build_conversation_observation(record, parent, payload)
        revised["observation_id"] = prior["observation_id"]
        revised["observation_version"] = prior["observation_version"] + 1
        revised["observation_digest"] = canonical_sha256(
            {key: value for key, value in revised.items() if key != "observation_digest"}
        )
        self._conversation(revised, record)
        return revised

    def build_reconstruction(
        self, observations: tuple[dict[str, Any], ...], payload: dict[str, Any]
    ) -> dict[str, Any]:
        expected = {"relationships", "clusters", "exceptions", "primary", "views"}
        if set(payload) != expected or set(payload["views"]) != set(VIEW_NAMES):
            raise HistoricalActivityError("historical reconstruction payload is invalid")
        if not observations:
            raise HistoricalActivityError("historical reconstruction requires observations")
        identifiers = {item["observation_id"] for item in observations}
        citations = {ref for item in observations for ref in item["citation_refs"]}
        for relation in payload["relationships"]:
            self._relationship(relation, identifiers, citations)
        for cluster in payload["clusters"]:
            if (
                not isinstance(cluster, dict)
                or not set(cluster.get("member_observation_ids", [])) <= identifiers
                or not cluster.get("candidate_only") is True
            ):
                raise HistoricalActivityError("historical reconstruction cluster is invalid")
        self._semantic_collection(payload["exceptions"], citations)
        self._semantic_collection((payload["primary"],), citations)
        for view in payload["views"].values():
            self._semantic_collection(view if isinstance(view, list) else (view,), citations)
        reconstruction = {
            "schema_version": "1.0", "reconstruction_id": self.ids.new("artifact"),
            "reconstruction_version": 1, "family": FAMILY,
            "method_version": RELATIONSHIP_METHOD, "prompt_version": RELATIONSHIP_METHOD,
            "observation_digests": [item["observation_digest"] for item in observations],
            **payload, **self._fences(),
        }
        reconstruction["reconstruction_digest"] = canonical_sha256(reconstruction)
        self._reconstruction(reconstruction, observations)
        return reconstruction

    def prepare(
        self, *, bundle_id: str, parent: dict[str, str], selected_member_refs: tuple[str, ...],
        records: tuple[LogicalRecord, ...], item_observations: tuple[dict[str, Any], ...],
        conversation_observations: tuple[dict[str, Any], ...], reconstruction: dict[str, Any],
        expires_at: datetime, cross_wave_reconciliation: dict[str, Any] | None = None,
    ) -> PreparedHistoricalActivity:
        self._parent(parent)
        self._records(records)
        if expires_at.tzinfo is None or expires_at <= aware_utc_now():
            raise HistoricalActivityError("historical activity expiry is invalid")
        member_order = tuple(dict.fromkeys(record.member_ref for record in records))
        if not selected_member_refs or selected_member_refs != member_order:
            raise HistoricalActivityError("historical activity exact source order changed")
        by_record = {(record.member_ref, record.logical_record_id): record for record in records}
        observations = (*item_observations, *conversation_observations)
        if len(observations) != len(records):
            raise HistoricalActivityError("historical activity record/observation accounting changed")
        for observation in item_observations:
            self._item(observation, by_record[(observation["member_ref"], observation["logical_record_id"])])
        for observation in conversation_observations:
            self._conversation(
                observation, by_record[(observation["member_ref"], observation["logical_record_id"])]
            )
        self._reconstruction(reconstruction, observations)
        package = {
            "schema_version": "1.0", "component": COMPONENT, "family": FAMILY,
            "logical_records": [record.descriptor() for record in records],
            "item_observations": list(item_observations),
            "conversation_observations": list(conversation_observations),
            "reconstruction": reconstruction, **self._fences(),
        }
        if cross_wave_reconciliation is not None:
            self.schemas.require(
                "historical-cross-wave-reconciliation", cross_wave_reconciliation
            )
            if (
                cross_wave_reconciliation["catalogue_digest"] != parent["catalogue_digest"]
                or cross_wave_reconciliation["candidate_only"] is not True
                or cross_wave_reconciliation["no_current_work"] is not True
            ):
                raise HistoricalActivityError("cross-wave reconciliation binding changed")
            package["cross_wave_reconciliation"] = cross_wave_reconciliation
        package["package_digest"] = canonical_sha256(package)
        manifest = {
            "schema_version": "1.0", "component": COMPONENT, "purpose": PURPOSE,
            "authority_id": AUTHORITY_ID, "admission_id": self.ids.new("private_admission"),
            "bundle_id": bundle_id, "family": FAMILY, **parent, "cutoff": CUTOFF,
            "selected_member_refs": list(selected_member_refs),
            "logical_record_digests": [record.logical_record_digest for record in records],
            "item_observation_digests": [item["observation_digest"] for item in item_observations],
            "conversation_observation_digests": [
                item["observation_digest"] for item in conversation_observations
            ],
            "reconstruction_digest": reconstruction["reconstruction_digest"],
            "disclosure": DISCLOSURE, "candidate_only": True,
            "operations": [
                "append_candidate_historical_activity", "build_candidate_fts5",
                "build_historical_activity_views",
            ],
            "expires_at": timestamp(expires_at),
        }
        if cross_wave_reconciliation is not None:
            manifest["cross_wave_reconciliation_digest"] = cross_wave_reconciliation[
                "reconciliation_digest"
            ]
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self._manifest(manifest)
        return PreparedHistoricalActivity(manifest, package)

    def authorize(self, prepared: PreparedHistoricalActivity) -> dict[str, Any]:
        self._prepared(prepared)
        receipt = self.authority.authorize_historical_activity_reconstruction(prepared.manifest)
        self._receipt(receipt, prepared.manifest)
        return receipt

    def publish(
        self, prepared: PreparedHistoricalActivity, *, receipt_id: str
    ) -> HistoricalActivityResult:
        self._prepared(prepared)
        root = self._root()
        existing = self._matching(root, prepared.manifest["manifest_digest"])
        if existing is not None:
            if existing["receipt_id"] != receipt_id:
                raise HistoricalActivityError("historical activity receipt replay changed")
            self._archived(receipt_id, prepared.manifest, root)
            self._verify_package(root, prepared)
            self._rebuild(root, existing, prepared)
            return HistoricalActivityResult("already_complete", existing["event_id"], receipt_id)
        receipt = self.authority.verify_historical_activity_reconstruction(
            receipt_id, prepared.manifest
        )
        self._receipt(receipt, prepared.manifest)
        display, signed = self.authority.read_historical_activity_reconstruction_evidence(
            receipt_id, prepared.manifest
        )
        self._initialize(root)
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".historical-activity-{prepared.manifest['admission_id']}-",
                dir=root / "staging" / "historical-activity",
            )
        )
        try:
            event = self._event(prepared, receipt_id)
            self.schemas.require("historical-activity-reconstruction-event", event)
            materials = {
                "manifest.json": canonical_bytes(prepared.manifest),
                "package.json": canonical_bytes(prepared.package),
                "display.json": display, "receipt.json": signed, "event.json": canonical_bytes(event),
            }
            for name, material in materials.items():
                self._immutable(stage / name, material)
            if self.fail_before_event:
                raise HistoricalActivityError("injected interruption before historical activity event")
            targets = {
                "manifest.json": root / "canonical" / "historical-activity-manifests"
                / prepared.manifest["manifest_digest"],
                "package.json": root / "canonical" / "historical-activity-packages"
                / prepared.package["package_digest"],
                "display.json": root / "evidence" / "historical-activity" / f"{receipt_id}.json",
                "receipt.json": root / "receipts" / "historical-activity" / f"{receipt_id}.json",
                "event.json": root / "canonical" / "historical-activity-events" / f"{event['event_id']}.json",
            }
            for name, target in targets.items():
                self._publish(stage / name, target, sha256_hex(materials[name]))
            self._rebuild(root, event, prepared)
            return HistoricalActivityResult("complete", event["event_id"], receipt_id)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def verify_restart(
        self, prepared: PreparedHistoricalActivity, *, receipt_id: str
    ) -> HistoricalActivityResult:
        self._prepared(prepared)
        root = self._root()
        event = self._matching(root, prepared.manifest["manifest_digest"])
        if event is None or event["receipt_id"] != receipt_id:
            raise HistoricalActivityError("historical activity event is unavailable")
        self._archived(receipt_id, prepared.manifest, root)
        self._verify_package(root, prepared)
        self._rebuild(root, event, prepared)
        return HistoricalActivityResult("complete", event["event_id"], receipt_id)

    def append_disposable_mirror_rollback(self, event_id: str) -> dict[str, Any]:
        root = self._root()
        if not root.is_relative_to(Path("/private/tmp")):
            raise HistoricalActivityError("historical activity rollback is mirror-only")
        record = {
            "schema_version": "1.0", "rollback_type": "logical_historical_activity_views",
            "target_event_id": event_id, "parent_events_unchanged": True,
        }
        record["rollback_sha256"] = canonical_sha256(record)
        self._immutable(
            root / "canonical" / "historical-activity-rollbacks" / f"{self.ids.new('event')}.json",
            canonical_bytes(record),
        )
        return record

    def _pack_entries(self, record: LogicalRecord) -> list[dict[str, Any]]:
        if len(record.content) <= self.caps.max_pack_chars:
            return [{"descriptor": record.descriptor(), "content": record.content}]
        anchor_kinds = {anchor.get("kind") for anchor in record.anchors}
        if not record.anchors or anchor_kinds not in ({"jsonl_record"}, {"codex_line"}):
            raise HistoricalActivityError("historical activity record requires supported stable chunking")
        lines = record.content.splitlines()
        if len(lines) != len(record.anchors):
            raise HistoricalActivityError("historical activity chunk anchors changed")
        raw: list[tuple[int, int, tuple[str, ...], str]] = []
        start = 0
        while start < len(lines):
            end = start
            characters = 0
            while end < len(lines):
                added = len(lines[end]) + (1 if end > start else 0)
                if characters + added > self.caps.max_pack_chars:
                    break
                characters += added
                end += 1
            if end == start:
                raise HistoricalActivityError("historical activity JSONL entry exceeds pack cap")
            anchor_ids = tuple(anchor["anchor_id"] for anchor in record.anchors[start:end])
            raw.append((start, end, anchor_ids, "\n".join(lines[start:end])))
            if end == len(lines):
                break
            if end - start < 2:
                raise HistoricalActivityError("historical activity chunk cannot retain stable overlap")
            start = end - 1
        count = len(raw)
        entries: list[dict[str, Any]] = []
        for chunk_index, (start, end, anchor_ids, content) in enumerate(raw):
            overlap = () if chunk_index == 0 else (anchor_ids[0],)
            entries.append(
                {
                    "descriptor": record.descriptor(),
                    "content": content,
                    "chunk": {
                        "chunk_index": chunk_index,
                        "chunk_count": count,
                        "start_record_index": start,
                        "end_record_index_exclusive": end,
                        "anchor_ids": list(anchor_ids),
                        "overlap_anchor_ids": list(overlap),
                        "content_sha256": sha256_hex(content.encode("utf-8")),
                    },
                }
            )
        return entries

    def _pack(self, index: int, payload: list[dict[str, Any]]) -> AnalysisPack:
        body = {
            "schema_version": "1.0", "pack_index": index,
            "record_digests": [entry["descriptor"]["logical_record_digest"] for entry in payload],
            "member_refs": list(
                dict.fromkeys(entry["descriptor"]["member_ref"] for entry in payload)
            ),
            "character_count": sum(len(entry["content"]) for entry in payload), "records": payload,
        }
        return AnalysisPack(
            index, tuple(body["record_digests"]), tuple(body["member_refs"]),
            body["character_count"], tuple(payload), canonical_sha256(body),
        )

    def _records(self, records: tuple[LogicalRecord, ...]) -> None:
        if not records or len(records) > self.caps.max_logical_records:
            raise HistoricalActivityError("historical activity logical-record count is invalid")
        if len({record.logical_record_digest for record in records}) != len(records):
            raise HistoricalActivityError("historical activity logical record is duplicated")
        if len(set(record.member_ref for record in records)) > self.caps.max_members:
            raise HistoricalActivityError("historical activity member cap exceeded")
        if sum(len(record.content) for record in records) > self.caps.max_decoded_chars:
            raise HistoricalActivityError("historical activity decoded-text cap exceeded")
        for record in records:
            descriptor = record.descriptor()
            digest_material = {key: value for key, value in descriptor.items() if key != "logical_record_digest"}
            if record.logical_record_digest != canonical_sha256(digest_material):
                raise HistoricalActivityError("historical activity logical record changed")

    def _semantic_payload(self, record: LogicalRecord, payload: dict[str, Any]) -> set[str]:
        allowed = {anchor["anchor_id"] for anchor in record.anchors}
        for key, value in payload.items():
            # A fully unknown time is permitted without a citation; _times applies
            # the stricter temporal contract below.
            if key == "temporal_assertions":
                continue
            if isinstance(value, list):
                self._semantic_collection(value, allowed)
        return self._citation_refs(payload)

    @classmethod
    def _citation_refs(cls, value: Any) -> set[str]:
        if isinstance(value, dict):
            refs = set(value.get("citation_refs", []))
            for key, child in value.items():
                if key != "citation_refs":
                    refs.update(cls._citation_refs(child))
            return refs
        if isinstance(value, (list, tuple)):
            refs: set[str] = set()
            for child in value:
                refs.update(cls._citation_refs(child))
            return refs
        return set()

    @staticmethod
    def _semantic_collection(values: Any, allowed: set[str]) -> None:
        if not isinstance(values, (list, tuple)):
            raise HistoricalActivityError("historical activity semantic collection is invalid")
        for item in values:
            if not isinstance(item, dict):
                raise HistoricalActivityError("historical activity semantic item is invalid")
            refs = item.get("citation_refs")
            unavailable = item.get("citation_unavailable") is True
            if not isinstance(refs, list) or set(refs) - allowed or (not refs and not unavailable):
                raise HistoricalActivityError("historical activity semantic citation is invalid")

    def _times(self, values: list[dict[str, Any]], allowed: set[str]) -> None:
        for value in values:
            required = {
                "field", "value", "earliest", "latest", "precision", "basis", "confidence",
                "citation_refs", "conflicts", "timezone_assumption",
            }
            if (
                set(value) != required or value["field"] not in TIME_FIELDS
                or value["precision"] not in TIME_PRECISIONS or value["basis"] not in TIME_BASES
                or value["confidence"] not in CONFIDENCES or set(value["citation_refs"]) - allowed
            ):
                raise HistoricalActivityError("historical activity temporal assertion is invalid")
            candidates = [item for item in (value["value"], value["earliest"], value["latest"]) if item]
            if value["basis"] == "unknown":
                if candidates or value["confidence"] != "unavailable":
                    raise HistoricalActivityError("historical activity unknown time overclaims")
            elif not candidates or not value["citation_refs"]:
                raise HistoricalActivityError("historical activity supported time lacks evidence")
            for candidate in candidates:
                try:
                    parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                except (AttributeError, ValueError) as exc:
                    raise HistoricalActivityError("historical activity time is invalid") from exc
                if parsed.tzinfo is None:
                    raise HistoricalActivityError("historical activity time lacks timezone")

    @staticmethod
    def cutoff_disposition(values: list[dict[str, Any]]) -> str:
        cutoff = datetime.fromisoformat(CUTOFF.replace("Z", "+00:00"))
        supported = []
        for value in values:
            if value.get("field") not in {
                "event_started_at", "conversation_started_at", "artifact_generated_at",
                "source_created_at",
            }:
                continue
            candidates = [item for item in (value.get("value"), value.get("earliest"), value.get("latest")) if item]
            supported.extend(datetime.fromisoformat(item.replace("Z", "+00:00")) for item in candidates)
        if not supported:
            return "date_unavailable"
        if min(supported) < cutoff <= max(supported):
            return "cutoff_ambiguous"
        return "eligible" if max(supported) >= cutoff else "excluded_before_cutoff"

    @staticmethod
    def _people(values: list[dict[str, Any]]) -> None:
        for value in values:
            if value.get("role") not in PERSON_ROLES:
                raise HistoricalActivityError("historical activity person role is invalid")

    @staticmethod
    def _meeting_types(values: list[dict[str, Any]]) -> None:
        if any(value.get("label") not in MEETING_TYPES for value in values):
            raise HistoricalActivityError("historical activity meeting type is invalid")

    @staticmethod
    def _strands(values: list[dict[str, Any]]) -> None:
        for value in values:
            if not isinstance(value.get("label"), str) or not value["label"].strip():
                raise HistoricalActivityError("historical activity strand is invalid")
            if value.get("merge_authorized") is not False:
                raise HistoricalActivityError("historical activity strand cannot silently merge")

    @staticmethod
    def _skill_triggers(values: list[dict[str, Any]]) -> None:
        for value in values:
            if (
                value.get("basis") not in SKILL_BASES
                or value.get("evidence_type") not in SKILL_EVIDENCE_TYPES
            ):
                raise HistoricalActivityError("historical activity skill evidence is invalid")

    def _child_events(
        self, record: LogicalRecord, item_class: str, values: list[dict[str, Any]]
    ) -> None:
        if not isinstance(values, list):
            raise HistoricalActivityError("historical activity child events are invalid")
        if (item_class == "multi_meeting_bundle") != bool(values):
            raise HistoricalActivityError("historical activity multi-meeting container changed")
        if values and len(values) < 2:
            raise HistoricalActivityError("historical activity multi-meeting bundle needs child events")
        allowed = {anchor["anchor_id"] for anchor in record.anchors}
        identifiers: set[str] = set()
        required = {
            "occurrence_id", "label", "temporal_assertions", "people", "meeting_types", "strands",
            "citation_refs", "confidence", "conflicts", "omissions",
        }
        for value in values:
            if (
                not isinstance(value, dict) or set(value) != required
                or not isinstance(value["occurrence_id"], str) or not value["occurrence_id"]
                or value["occurrence_id"] in identifiers
                or not isinstance(value["label"], str) or not value["label"].strip()
                or not value["citation_refs"] or set(value["citation_refs"]) - allowed
                or value["confidence"] not in CONFIDENCES
            ):
                raise HistoricalActivityError("historical activity child event is invalid")
            identifiers.add(value["occurrence_id"])
            self._times(value["temporal_assertions"], allowed)
            self._semantic_collection(value["people"], allowed)
            self._people(value["people"])
            self._semantic_collection(value["meeting_types"], allowed)
            self._meeting_types(value["meeting_types"])
            self._semantic_collection(value["strands"], allowed)
            self._strands(value["strands"])
            self._semantic_collection(value["conflicts"], allowed)
            self._semantic_collection(value["omissions"], allowed)

    @staticmethod
    def _prior_observation(
        prior: dict[str, Any], record: LogicalRecord, parent: dict[str, str], observation_type: str
    ) -> None:
        if (
            not isinstance(prior, dict)
            or prior.get("observation_type") != observation_type
            or not isinstance(prior.get("observation_id"), str)
            or not isinstance(prior.get("observation_version"), int)
            or prior["observation_version"] < 1
            or prior.get("member_ref") != record.member_ref
            or prior.get("logical_record_id") != record.logical_record_id
            or prior.get("object_digest") != record.object_digest
            or any(prior.get(key) != value for key, value in parent.items())
        ):
            raise HistoricalActivityError("historical activity prior observation binding changed")

    def _item(self, observation: dict[str, Any], record: LogicalRecord) -> None:
        self.schemas.require("historical-item-observation", observation)
        self._observation(observation, record)

    def _conversation(self, observation: dict[str, Any], record: LogicalRecord) -> None:
        self.schemas.require("historical-conversation-execution-observation", observation)
        self._observation(observation, record)

    @staticmethod
    def _observation(observation: dict[str, Any], record: LogicalRecord) -> None:
        material = {key: value for key, value in observation.items() if key != "observation_digest"}
        anchors = {anchor["anchor_id"] for anchor in record.anchors}
        if (
            observation["observation_digest"] != canonical_sha256(material)
            or observation["member_ref"] != record.member_ref
            or observation["logical_record_id"] != record.logical_record_id
            or observation["object_digest"] != record.object_digest
            or set(observation["citation_refs"]) - anchors
            or not all(
                observation[key]
                for key in ("candidate_only", "no_current_work", "no_promotion", "no_activation", "no_u2")
            )
        ):
            raise HistoricalActivityError("historical activity observation binding changed")

    def _reconstruction(
        self, reconstruction: dict[str, Any], observations: tuple[dict[str, Any], ...] | list[dict[str, Any]]
    ) -> None:
        self.schemas.require("historical-cross-source-reconstruction", reconstruction)
        material = {key: value for key, value in reconstruction.items() if key != "reconstruction_digest"}
        expected = [item["observation_digest"] for item in observations]
        if (
            reconstruction["reconstruction_digest"] != canonical_sha256(material)
            or reconstruction["observation_digests"] != expected
            or not all(
                reconstruction[key]
                for key in ("candidate_only", "no_current_work", "no_promotion", "no_activation", "no_u2")
            )
        ):
            raise HistoricalActivityError("historical activity reconstruction binding changed")

    @staticmethod
    def _relationship(value: dict[str, Any], identifiers: set[str], citations: set[str]) -> None:
        required = {
            "relationship_id", "subject_ref", "object_ref", "predicate", "status", "basis_type",
            "evidence_refs", "method_version", "confidence", "effective_at", "conflicts", "omissions",
        }
        if (
            set(value) != required or value["subject_ref"] not in identifiers
            or value["object_ref"] not in identifiers or value["subject_ref"] == value["object_ref"]
            or value["status"] not in RELATION_STATUSES or value["basis_type"] not in RELATION_BASES
            or not value["evidence_refs"] or set(value["evidence_refs"]) - citations
            or value["confidence"] not in CONFIDENCES or value["method_version"] != RELATIONSHIP_METHOD
        ):
            raise HistoricalActivityError("historical activity relationship is invalid")
        if value["status"] == "structurally_verified" and value["basis_type"] not in {
            "exact_bytes", "export_declared",
        }:
            raise HistoricalActivityError("historical activity semantic link cannot be structural")

    @staticmethod
    def _parent(parent: dict[str, str]) -> None:
        if set(parent) != {"parent_event_id", "parent_manifest_digest", "catalogue_digest"}:
            raise HistoricalActivityError("historical activity parent binding is invalid")
        if any(not isinstance(value, str) or not value for value in parent.values()):
            raise HistoricalActivityError("historical activity parent binding is incomplete")
        if any(
            len(parent[key]) != 64
            or any(character not in "0123456789abcdef" for character in parent[key])
            for key in ("parent_manifest_digest", "catalogue_digest")
        ):
            raise HistoricalActivityError("historical activity parent digest is invalid")

    def _manifest(self, manifest: dict[str, Any]) -> None:
        self.schemas.require("historical-activity-reconstruction-manifest", manifest)
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest["manifest_digest"] != canonical_sha256(material):
            raise HistoricalActivityError("historical activity manifest changed")

    def _prepared(self, prepared: PreparedHistoricalActivity) -> None:
        self._manifest(prepared.manifest)
        material = {key: value for key, value in prepared.package.items() if key != "package_digest"}
        if prepared.package["package_digest"] != canonical_sha256(material):
            raise HistoricalActivityError("historical activity package changed")
        records = prepared.package.get("logical_records", [])
        item_observations = prepared.package.get("item_observations", [])
        conversation_observations = prepared.package.get("conversation_observations", [])
        if (
            prepared.manifest["logical_record_digests"]
            != [record.get("logical_record_digest") for record in records]
            or prepared.manifest["item_observation_digests"]
            != [item.get("observation_digest") for item in item_observations]
            or prepared.manifest["conversation_observation_digests"]
            != [item.get("observation_digest") for item in conversation_observations]
        ):
            raise HistoricalActivityError("historical activity manifest/package accounting changed")
        reconstruction = prepared.package["reconstruction"]
        observation_digests = [
            item.get("observation_digest")
            for item in (*item_observations, *conversation_observations)
        ]
        if (
            prepared.manifest["reconstruction_digest"] != reconstruction["reconstruction_digest"]
            or reconstruction.get("observation_digests") != observation_digests
            or not all(
                prepared.package.get(key) is True
                for key in ("candidate_only", "no_current_work", "no_promotion", "no_activation", "no_u2")
            )
        ):
            raise HistoricalActivityError("historical activity manifest/package binding changed")
        cross_wave = prepared.package.get("cross_wave_reconciliation")
        manifest_cross_wave = prepared.manifest.get("cross_wave_reconciliation_digest")
        if (cross_wave is None) != (manifest_cross_wave is None):
            raise HistoricalActivityError("historical activity cross-wave accounting changed")
        if cross_wave is not None:
            self.schemas.require("historical-cross-wave-reconciliation", cross_wave)
            if (
                cross_wave["reconciliation_digest"] != manifest_cross_wave
                or cross_wave["catalogue_digest"] != prepared.manifest["catalogue_digest"]
                or cross_wave["candidate_only"] is not True
                or cross_wave["no_current_work"] is not True
            ):
                raise HistoricalActivityError("historical activity cross-wave binding changed")

    @staticmethod
    def _fences() -> dict[str, bool]:
        return {
            "candidate_only": True, "no_current_work": True, "no_promotion": True,
            "no_activation": True, "no_u2": True,
        }

    @staticmethod
    def _receipt(receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        expected = {
            "authority_id": AUTHORITY_ID, "purpose": PURPOSE,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
        }
        if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in expected.items()):
            raise HistoricalActivityError("historical activity receipt binding is invalid")

    def _root(self) -> Path:
        PrivateBundleLayout.validate(self.root)
        return self.root.resolve(strict=True)

    @staticmethod
    def _initialize(root: Path) -> None:
        for relative in (
            "canonical/historical-activity-manifests", "canonical/historical-activity-packages",
            "canonical/historical-activity-events", "canonical/historical-activity-rollbacks",
            "staging/historical-activity", "receipts/historical-activity",
            "evidence/historical-activity", "derived/historical-activity", "workspace/History",
        ):
            path = root / relative
            if path.exists():
                if path.is_symlink() or not path.is_dir():
                    raise HistoricalActivityError("historical activity layout is unsafe")
            else:
                path.mkdir(mode=0o700)
            if path.stat().st_mode & 0o077:
                raise HistoricalActivityError("historical activity layout is not owner-only")

    def _event(self, prepared: PreparedHistoricalActivity, receipt_id: str) -> dict[str, Any]:
        manifest = prepared.manifest
        return {
            "schema_version": "1.0", "event_id": self.ids.new("event"), "publication_type": PURPOSE,
            "parent_event_id": manifest["parent_event_id"],
            "parent_manifest_digest": manifest["parent_manifest_digest"],
            "catalogue_digest": manifest["catalogue_digest"], "manifest_digest": manifest["manifest_digest"],
            "package_digest": prepared.package["package_digest"], "receipt_id": receipt_id,
            "candidate_only": True, "recorded_at": timestamp(aware_utc_now()),
        }

    def _matching(self, root: Path, digest: str) -> dict[str, Any] | None:
        directory = root / "canonical" / "historical-activity-events"
        if not directory.exists():
            return None
        matches = []
        for path in directory.iterdir():
            if path.is_file() and not path.is_symlink():
                record = self._json(path)
                if record.get("manifest_digest") == digest:
                    matches.append(record)
        if len(matches) > 1:
            raise HistoricalActivityError("historical activity event is duplicated")
        return matches[0] if matches else None

    def _archived(self, receipt_id: str, manifest: dict[str, Any], root: Path) -> None:
        self.authority.verify_archived_historical_activity_reconstruction(
            receipt_id, manifest, display_root=root / "evidence" / "historical-activity",
            receipt_root=root / "receipts" / "historical-activity",
        )

    @staticmethod
    def _verify_package(root: Path, prepared: PreparedHistoricalActivity) -> None:
        path = root / "canonical" / "historical-activity-packages" / prepared.package["package_digest"]
        if path.is_symlink() or not path.is_file() or path.read_bytes() != canonical_bytes(prepared.package):
            raise HistoricalActivityError("historical activity package object is invalid")

    def _rebuild(
        self, root: Path, event: dict[str, Any], prepared: PreparedHistoricalActivity
    ) -> None:
        self._initialize(root)
        reconstruction = prepared.package["reconstruction"]
        record = {
            "schema_version": "1.0", "event_id": event["event_id"],
            "manifest_digest": event["manifest_digest"], "package_digest": event["package_digest"],
            "primary": reconstruction["primary"], "views": reconstruction["views"],
            "candidate_only": True,
        }
        record["view_digest"] = canonical_sha256(record)
        derived = root / "derived" / "historical-activity" / f"{event['event_id']}.json"
        derived.write_bytes(canonical_bytes(record))
        os.chmod(derived, 0o600)
        cross_wave = prepared.package.get("cross_wave_reconciliation")
        if cross_wave is not None:
            reconciliation = (
                root / "derived" / "historical-activity"
                / f"{event['event_id']}.cross-wave.json"
            )
            reconciliation.write_bytes(canonical_bytes(cross_wave))
            os.chmod(reconciliation, 0o600)
        self._fts(root, event["event_id"], reconstruction)
        self._workspace(root, reconstruction)

    @staticmethod
    def _fts(root: Path, event_id: str, reconstruction: dict[str, Any]) -> None:
        target = root / "derived" / "historical-activity" / "views.sqlite3"
        staged = target.with_suffix(".stage")
        if staged.exists():
            staged.unlink()
        database = sqlite3.connect(staged)
        try:
            database.execute("CREATE TABLE views(event_id TEXT, view_name TEXT, body TEXT)")
            database.execute("CREATE VIRTUAL TABLE views_fts USING fts5(view_name, body)")
            for name in VIEW_NAMES:
                body = json.dumps(reconstruction["views"][name], sort_keys=True)
                database.execute("INSERT INTO views VALUES (?, ?, ?)", (event_id, name, body))
                database.execute("INSERT INTO views_fts VALUES (?, ?)", (name, body))
            primary = reconstruction["primary"]
            database.execute("INSERT INTO views VALUES (?, ?, ?)", (event_id, "primary", primary["markdown"]))
            database.execute("INSERT INTO views_fts VALUES (?, ?)", ("primary", primary["markdown"]))
            database.commit()
        finally:
            database.close()
        os.replace(staged, target)
        os.chmod(target, 0o600)

    @staticmethod
    def _workspace(root: Path, reconstruction: dict[str, Any]) -> None:
        workspace = root / "workspace" / "History"
        primary = reconstruction["primary"]
        pages = {"Historical Activity and Artifact Map.md": primary["markdown"]}
        for name in VIEW_NAMES:
            title = name.replace("_", " ").title()
            body = json.dumps(reconstruction["views"][name], indent=2, sort_keys=True)
            pages[f"{title}.md"] = f"# {title}\n\n```json\n{body}\n```\n"
        for name, body in pages.items():
            target = workspace / name
            target.write_text(body, encoding="utf-8")
            os.chmod(target, 0o600)

    @staticmethod
    def _immutable(path: Path, material: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise HistoricalActivityError("historical activity immutable target already exists")
        path.write_bytes(material)
        os.chmod(path, 0o600)

    @staticmethod
    def _publish(staged: Path, target: Path, digest: str) -> None:
        if staged.is_symlink() or sha256_hex(staged.read_bytes()) != digest:
            raise HistoricalActivityError("historical activity staged object changed")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or sha256_hex(target.read_bytes()) != digest:
                raise HistoricalActivityError("historical activity immutable target conflicts")
            staged.unlink()
        else:
            os.replace(staged, target)

    @staticmethod
    def _json(path: Path) -> dict[str, Any]:
        try:
            material = path.read_bytes()
            record = json.loads(material)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HistoricalActivityError("historical activity record is invalid") from exc
        if not isinstance(record, dict) or canonical_bytes(record) != material:
            raise HistoricalActivityError("historical activity record is not canonical")
        return record
