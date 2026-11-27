"""Pure-Python SHA-256 hash-chain verifier for raksa-siem audit ledger segments."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
_PAYLOAD_MARKER = ',"payload":'


@dataclass(slots=True)
class LedgerVerifyReport:
    """Integrity verification summary matching Go ledger.VerifyReport."""

    valid: bool
    dir: str
    segments_checked: int
    entries_checked: int
    tip_hash: str
    broken_segment: str = ""
    broken_at_seq: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "valid": self.valid,
            "dir": self.dir,
            "segments_checked": self.segments_checked,
            "entries_checked": self.entries_checked,
            "tip_hash": self.tip_hash,
        }
        if self.broken_segment:
            out["broken_segment"] = self.broken_segment
        if self.broken_at_seq:
            out["broken_at_seq"] = self.broken_at_seq
        if self.error:
            out["error"] = self.error
        return out


def verify_ledger_dir(dir_path: str | Path) -> LedgerVerifyReport:
    """Verify SHA-256 hash chaining across all siem-YYYY-MM-DD.ndjson files in dir_path."""
    base = Path(dir_path)
    if not base.exists() or not base.is_dir():
        return LedgerVerifyReport(
            valid=False,
            dir=str(base),
            segments_checked=0,
            entries_checked=0,
            tip_hash=GENESIS_HASH,
            error=f"ledger directory not found: {base}",
        )

    segments = sorted(
        (p for p in base.iterdir() if p.is_file() and p.name.startswith("siem-") and p.name.endswith(".ndjson")),
        key=lambda p: p.name,
    )

    expected_seq = 1
    expected_prev = GENESIS_HASH
    checked = 0
    tip = GENESIS_HASH

    for seg in segments:
        try:
            text = seg.read_text(encoding="utf-8")
        except OSError as exc:
            return LedgerVerifyReport(
                valid=False,
                dir=str(base),
                segments_checked=len(segments),
                entries_checked=checked,
                tip_hash=tip,
                broken_segment=seg.name,
                broken_at_seq=expected_seq,
                error=f"read segment error: {exc}",
            )

        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue

            try:
                ent = json.loads(line)
            except json.JSONDecodeError as exc:
                return LedgerVerifyReport(
                    valid=False,
                    dir=str(base),
                    segments_checked=len(segments),
                    entries_checked=checked,
                    tip_hash=tip,
                    broken_segment=seg.name,
                    broken_at_seq=expected_seq,
                    error=f"corrupt JSON at seq {expected_seq}: {exc}",
                )

            if not isinstance(ent, dict):
                return LedgerVerifyReport(
                    valid=False,
                    dir=str(base),
                    segments_checked=len(segments),
                    entries_checked=checked,
                    tip_hash=tip,
                    broken_segment=seg.name,
                    broken_at_seq=expected_seq,
                    error=f"unexpected entry type at seq {expected_seq}",
                )

            idx = line.find(_PAYLOAD_MARKER)
            if idx == -1 or not line.endswith("}"):
                return LedgerVerifyReport(
                    valid=False,
                    dir=str(base),
                    segments_checked=len(segments),
                    entries_checked=checked,
                    tip_hash=tip,
                    broken_segment=seg.name,
                    broken_at_seq=expected_seq,
                    error=f"missing trailing payload field at seq {expected_seq}",
                )
            raw_payload = line[idx + len(_PAYLOAD_MARKER) : -1].strip()

            seq = int(ent.get("seq", -1))
            ts_str = str(ent.get("timestamp", ""))
            kind = str(ent.get("kind", ""))
            prev_hash = str(ent.get("prev_hash", ""))
            stored_hash = str(ent.get("hash", ""))

            if seq != expected_seq or prev_hash != expected_prev:
                return LedgerVerifyReport(
                    valid=False,
                    dir=str(base),
                    segments_checked=len(segments),
                    entries_checked=checked,
                    tip_hash=tip,
                    broken_segment=seg.name,
                    broken_at_seq=expected_seq,
                    error=(
                        f"chain discontinuity: expected seq={expected_seq} prev={expected_prev}, "
                        f"got seq={seq} prev={prev_hash}"
                    ),
                )

            calc = hashlib.sha256(
                f"{seq}|{ts_str}|{kind}|{prev_hash}|{raw_payload}".encode("utf-8")
            ).hexdigest()
            if calc.lower() != stored_hash.lower():
                return LedgerVerifyReport(
                    valid=False,
                    dir=str(base),
                    segments_checked=len(segments),
                    entries_checked=checked,
                    tip_hash=tip,
                    broken_segment=seg.name,
                    broken_at_seq=seq,
                    error=f"hash mismatch: expected {calc}, stored {stored_hash}",
                )

            expected_seq += 1
            expected_prev = stored_hash
            checked += 1
            tip = stored_hash

    return LedgerVerifyReport(
        valid=True,
        dir=str(base),
        segments_checked=len(segments),
        entries_checked=checked,
        tip_hash=tip,
    )
