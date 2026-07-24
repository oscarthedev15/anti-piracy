"""
Evidence service — append-only, tamper-evident audit ledger.

Selling to governments means the output has to survive legal challenge and
oversight. Every detection and every enforcement recommendation is recorded as
a hash-chained record (each record commits to the hash of the previous one), so
any later tampering with the history is detectable.

This is a lightweight, in-memory reference implementation. Production would
persist to an append-only store (e.g. WORM storage / QLDB / a Merkle log) and
sign each record with the operating agency's key.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LedgerRecord:
    seq: int
    kind: str            # "detection" | "blocklist" | "review" | ...
    subject: str
    payload: dict
    timestamp: str
    prev_hash: str
    hash: str = ""


class EvidenceLedger:
    def __init__(self, genesis: str = "AEGIS-GENESIS"):
        self._records: list[LedgerRecord] = []
        self._genesis = hashlib.sha256(genesis.encode()).hexdigest()

    def _hash(self, rec: LedgerRecord) -> str:
        body = json.dumps({
            "seq": rec.seq, "kind": rec.kind, "subject": rec.subject,
            "payload": rec.payload, "timestamp": rec.timestamp,
            "prev_hash": rec.prev_hash,
        }, sort_keys=True)
        return hashlib.sha256(body.encode()).hexdigest()

    def record(self, kind: str, subject: str, payload: dict) -> str:
        prev = self._records[-1].hash if self._records else self._genesis
        rec = LedgerRecord(
            seq=len(self._records),
            kind=kind,
            subject=subject,
            payload=payload,
            timestamp=_utcnow(),
            prev_hash=prev,
        )
        rec.hash = self._hash(rec)
        self._records.append(rec)
        return f"ev:{rec.seq}:{rec.hash[:12]}"

    def verify(self) -> bool:
        """Re-walk the chain; return False if any link was tampered with."""
        prev = self._genesis
        for rec in self._records:
            if rec.prev_hash != prev:
                return False
            if self._hash(rec) != rec.hash:
                return False
            prev = rec.hash
        return True

    def __len__(self) -> int:
        return len(self._records)

    def export(self) -> list[dict]:
        return [rec.__dict__ for rec in self._records]
