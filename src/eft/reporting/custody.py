"""Evidence Chain of Custody & Cryptographic Ledger Management Engine."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from eft.core.exceptions import EvidenceTamperedException
from eft.core.integrity import compute_bytes_hashes, compute_file_hashes
from eft.models.custody import (
    CustodyAction,
    CustodyEvent,
    EvidenceLedger,
    EvidenceManifest,
)


class ChainOfCustodyManager:
    """Manages forensic evidence manifests, custody ledgers, and cryptographic verification."""

    @classmethod
    def create_manifest(
        cls,
        file_path: Union[str, Path],
        case_id: str,
        evidence_id: str,
        examiner_name: str,
        examiner_agency: Optional[str] = None,
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        pre_hashes: Optional[Dict[str, str]] = None,
        file_format: Optional[str] = None,
    ) -> EvidenceManifest:
        """Create an initial cryptographic evidence manifest from an acquired evidence file.

        Args:
            file_path: Path to the acquired physical evidence file.
            case_id: DFIR Case or Incident ID.
            evidence_id: Unique evidence identifier.
            examiner_name: Full name or badge number of the acquiring examiner.
            examiner_agency: Agency or organization name.
            notes: Investigative context or notes.
            metadata: Supplemental metadata dictionary.
            pre_hashes: Optional pre-calculated hashes; if omitted, computed automatically.
            file_format: Optional declared format ('eml', 'msg', 'mbox').

        Returns:
            Populated EvidenceManifest instance.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        file_size = path.stat().st_size
        file_name = path.name

        if not pre_hashes:
            pre_hashes = compute_file_hashes(path)

        if not file_format:
            suffix = path.suffix.lower().lstrip(".")
            file_format = suffix if suffix in ["eml", "msg", "mbox"] else "eml"

        manifest = EvidenceManifest(
            manifest_id=f"MAN-{uuid.uuid4().hex[:12].upper()}",
            case_id=case_id,
            evidence_id=evidence_id,
            examiner_name=examiner_name,
            examiner_agency=examiner_agency,
            source_file_path=str(path),
            source_file_name=file_name,
            source_file_size_bytes=file_size,
            file_format=file_format,
            acquisition_timestamp_utc=datetime.now(timezone.utc),
            pre_analysis_hashes=pre_hashes,
            post_analysis_hashes=None,
            integrity_verified=True,
            notes=notes,
            metadata=metadata or {},
        )
        return manifest

    @classmethod
    def create_manifest_from_bytes(
        cls,
        data: bytes,
        source_file_name: str,
        case_id: str,
        evidence_id: str,
        examiner_name: str,
        examiner_agency: Optional[str] = None,
        file_format: str = "eml",
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvidenceManifest:
        """Create a cryptographic evidence manifest directly from in-memory byte payload.

        Args:
            data: Raw evidence byte stream.
            source_file_name: Virtual or original filename.
            case_id: DFIR Case identifier.
            evidence_id: Evidence identifier.
            examiner_name: Name of the acquiring examiner.
            examiner_agency: Agency or organization.
            file_format: Declared format ('eml', 'msg', 'mbox').
            notes: Investigative context.
            metadata: Supplemental metadata.

        Returns:
            Populated EvidenceManifest instance.
        """
        hashes = compute_bytes_hashes(data)

        return EvidenceManifest(
            manifest_id=f"MAN-{uuid.uuid4().hex[:12].upper()}",
            case_id=case_id,
            evidence_id=evidence_id,
            examiner_name=examiner_name,
            examiner_agency=examiner_agency,
            source_file_path=f"memory://{source_file_name}",
            source_file_name=source_file_name,
            source_file_size_bytes=len(data),
            file_format=file_format,
            acquisition_timestamp_utc=datetime.now(timezone.utc),
            pre_analysis_hashes=hashes,
            post_analysis_hashes=None,
            integrity_verified=True,
            notes=notes,
            metadata=metadata or {},
        )

    @classmethod
    def create_ledger(
        cls,
        manifest: EvidenceManifest,
        initial_event_description: Optional[str] = None,
        initial_agency: Optional[str] = None,
    ) -> EvidenceLedger:
        """Initialize an immutable chain of custody ledger with the first ACQUISITION event.

        Args:
            manifest: The evidence acquisition manifest.
            initial_event_description: Optional custom initial event description.
            initial_agency: Optional agency override for the initial event.

        Returns:
            Initialized EvidenceLedger instance.
        """
        now = datetime.now(timezone.utc)
        desc = (
            initial_event_description
            or f"Evidence acquired and registered into chain of custody ledger with SHA-256: {manifest.pre_analysis_hashes.get('sha256', '')}"
        )
        agency = initial_agency or manifest.examiner_agency

        initial_event = CustodyEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:10].upper()}",
            timestamp_utc=manifest.acquisition_timestamp_utc,
            action=CustodyAction.ACQUISITION.value,
            performed_by=manifest.examiner_name,
            agency=agency,
            description=desc,
            evidence_hash=manifest.pre_analysis_hashes.get("sha256"),
            details={
                "source_file_path": manifest.source_file_path,
                "file_size_bytes": manifest.source_file_size_bytes,
                "hashes": manifest.pre_analysis_hashes,
                "manifest_id": manifest.manifest_id,
            },
        )

        ledger = EvidenceLedger(
            ledger_id=f"LEDGER-{uuid.uuid4().hex[:12].upper()}",
            case_id=manifest.case_id,
            evidence_id=manifest.evidence_id,
            manifest=manifest,
            events=[initial_event],
            created_at_utc=now,
            updated_at_utc=now,
            is_tampered=False,
            tamper_details=None,
        )
        return ledger

    @classmethod
    def record_event(
        cls,
        ledger: EvidenceLedger,
        action: Union[str, CustodyAction],
        performed_by: str,
        description: str,
        agency: Optional[str] = None,
        evidence_hash: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> CustodyEvent:
        """Append an immutable custody event to an existing evidence ledger.

        Args:
            ledger: The target EvidenceLedger.
            action: Custody action type or custom string.
            performed_by: Examiner or automated service name.
            description: Narrative explanation of the action taken.
            agency: Agency or organization of actor.
            evidence_hash: Optional SHA-256 evidence hash at event time.
            details: Contextual structured metadata.

        Returns:
            The newly recorded CustodyEvent.
        """
        action_str = action.value if isinstance(action, CustodyAction) else action
        hash_val = evidence_hash or ledger.manifest.pre_analysis_hashes.get("sha256")

        now = datetime.now(timezone.utc)

        event = CustodyEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:10].upper()}",
            timestamp_utc=now,
            action=action_str,
            performed_by=performed_by,
            agency=agency or ledger.manifest.examiner_agency,
            description=description,
            evidence_hash=hash_val,
            details=details or {},
        )
        ledger.events.append(event)
        ledger.updated_at_utc = now
        return event

    @classmethod
    def verify_integrity(
        cls,
        ledger: EvidenceLedger,
        current_file_path: Optional[Union[str, Path]] = None,
        current_bytes: Optional[bytes] = None,
        performed_by: Optional[str] = None,
        raise_on_tamper: bool = False,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Cryptographically verify the integrity of the evidence against pre-analysis acquisition hashes.

        Args:
            ledger: Target EvidenceLedger.
            current_file_path: Optional path to verify; defaults to manifest.source_file_path.
            current_bytes: Optional in-memory byte buffer to verify.
            performed_by: Name of examiner or engine verifying integrity.
            raise_on_tamper: If True, raises EvidenceTamperedException on mismatch.

        Returns:
            Tuple of (is_valid, report_dictionary).
        """
        examiner = performed_by or ledger.manifest.examiner_name
        now = datetime.now(timezone.utc)

        if current_bytes is not None:
            current_hashes = compute_bytes_hashes(current_bytes)
        else:
            target_path = Path(current_file_path or ledger.manifest.source_file_path)
            if not target_path.is_file():
                error_msg = f"Evidence file not found for verification: {target_path}"
                cls.record_event(
                    ledger=ledger,
                    action=CustodyAction.INTEGRITY_CHECK,
                    performed_by=examiner,
                    description=f"Integrity check failed: {error_msg}",
                    details={"error": error_msg},
                )
                ledger.is_tampered = True
                ledger.tamper_details = error_msg
                ledger.manifest.integrity_verified = False
                ledger.manifest.verification_timestamp_utc = now
                if raise_on_tamper:
                    raise FileNotFoundError(error_msg)
                return False, {"status": "FILE_NOT_FOUND", "error": error_msg}

            current_hashes = compute_file_hashes(target_path)

        pre_hashes = ledger.manifest.pre_analysis_hashes
        mismatched_keys = []
        for algo, original_hash in pre_hashes.items():
            current_val = current_hashes.get(algo)
            if current_val and current_val.lower() != original_hash.lower():
                mismatched_keys.append(algo)

        ledger.manifest.post_analysis_hashes = current_hashes
        ledger.manifest.verification_timestamp_utc = now

        if not mismatched_keys:
            ledger.manifest.integrity_verified = True
            cls.record_event(
                ledger=ledger,
                action=CustodyAction.INTEGRITY_CHECK,
                performed_by=examiner,
                description=f"Cryptographic integrity successfully verified against acquisition hashes. All digests match (SHA-256: {current_hashes.get('sha256', '')}).",
                evidence_hash=current_hashes.get("sha256"),
                details={
                    "verified_algorithms": list(pre_hashes.keys()),
                    "hashes": current_hashes,
                    "result": "VERIFIED_MATCH",
                },
            )
            return True, {
                "status": "VERIFIED",
                "integrity_verified": True,
                "current_hashes": current_hashes,
                "pre_hashes": pre_hashes,
                "timestamp_utc": now.isoformat(),
            }
        else:
            ledger.manifest.integrity_verified = False
            ledger.is_tampered = True
            tamper_msg = (
                f"EVIDENCE TAMPER DETECTED: Hash mismatch on {', '.join(mismatched_keys)}. "
                f"Expected SHA-256: {pre_hashes.get('sha256')}, Got: {current_hashes.get('sha256')}"
            )
            ledger.tamper_details = tamper_msg

            cls.record_event(
                ledger=ledger,
                action=CustodyAction.TAMPER_DETECTED,
                performed_by=examiner,
                description=tamper_msg,
                evidence_hash=current_hashes.get("sha256"),
                details={
                    "mismatched_algorithms": mismatched_keys,
                    "expected_hashes": pre_hashes,
                    "observed_hashes": current_hashes,
                    "result": "TAMPER_DETECTED",
                },
            )

            if raise_on_tamper:
                raise EvidenceTamperedException(tamper_msg)

            return False, {
                "status": "TAMPER_DETECTED",
                "integrity_verified": False,
                "mismatched_algorithms": mismatched_keys,
                "expected_hashes": pre_hashes,
                "observed_hashes": current_hashes,
                "timestamp_utc": now.isoformat(),
            }

    @classmethod
    def export_manifest_json(
        cls,
        manifest: EvidenceManifest,
        output_path: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Export an EvidenceManifest to standardized JSON string and optional disk file.

        Args:
            manifest: EvidenceManifest to serialize.
            output_path: Optional file path destination.
            indent: JSON indentation formatting.

        Returns:
            JSON formatted string.
        """
        json_data = manifest.model_dump(mode="json")
        json_str = json.dumps(json_data, indent=indent, default=str)
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json_str, encoding="utf-8")
        return json_str

    @classmethod
    def export_ledger_json(
        cls,
        ledger: EvidenceLedger,
        output_path: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Export a complete EvidenceLedger to standardized JSON string and optional disk file.

        Args:
            ledger: EvidenceLedger to serialize.
            output_path: Optional file path destination.
            indent: JSON indentation formatting.

        Returns:
            JSON formatted string.
        """
        json_data = ledger.model_dump(mode="json")
        json_str = json.dumps(json_data, indent=indent, default=str)
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json_str, encoding="utf-8")
        return json_str

    @classmethod
    def load_manifest_json(cls, source: Union[str, Path]) -> EvidenceManifest:
        """Deserialize an EvidenceManifest from a file path or raw JSON string.

        Args:
            source: Path to JSON manifest or raw JSON content string.

        Returns:
            Reconstructed EvidenceManifest instance.
        """
        path = Path(source)
        if path.is_file():
            raw = path.read_text(encoding="utf-8")
        else:
            raw = str(source)
        data = json.loads(raw)
        return EvidenceManifest.model_validate(data)

    @classmethod
    def load_ledger_json(cls, source: Union[str, Path]) -> EvidenceLedger:
        """Deserialize an EvidenceLedger from a file path or raw JSON string.

        Args:
            source: Path to JSON ledger or raw JSON content string.

        Returns:
            Reconstructed EvidenceLedger instance.
        """
        path = Path(source)
        if path.is_file():
            raw = path.read_text(encoding="utf-8")
        else:
            raw = str(source)
        data = json.loads(raw)
        return EvidenceLedger.model_validate(data)

    @classmethod
    def generate_manifest_summary(cls, manifest: EvidenceManifest) -> str:
        """Generate a concise, court-admissible markdown summary card of the evidence manifest."""
        status_badge = "VERIFIED IMMUTABLE" if manifest.integrity_verified else "TAMPER DETECTED"
        lines = [
            f"# Evidence Manifest: {manifest.evidence_id}",
            f"- **Case ID:** {manifest.case_id}",
            f"- **Manifest ID:** `{manifest.manifest_id}`",
            f"- **Examiner:** {manifest.examiner_name}"
            + (f" ({manifest.examiner_agency})" if manifest.examiner_agency else ""),
            f"- **Acquisition Date (UTC):** {manifest.acquisition_timestamp_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Original Filename:** `{manifest.source_file_name}`",
            f"- **File Size:** {manifest.source_file_size_bytes:,} bytes",
            f"- **Integrity Status:** `{status_badge}`",
            "",
            "### Cryptographic Hashes (Acquisition / Pre-Analysis)",
            f"- **MD5:** `{manifest.pre_analysis_hashes.get('md5', 'N/A')}`",
            f"- **SHA-1:** `{manifest.pre_analysis_hashes.get('sha1', 'N/A')}`",
            f"- **SHA-256:** `{manifest.pre_analysis_hashes.get('sha256', 'N/A')}`",
            f"- **SHA-512:** `{manifest.pre_analysis_hashes.get('sha512', 'N/A')}`",
        ]

        if manifest.post_analysis_hashes:
            lines.extend(
                [
                    "",
                    "### Verification Hashes (Post-Analysis)",
                    f"- **MD5:** `{manifest.post_analysis_hashes.get('md5', 'N/A')}`",
                    f"- **SHA-1:** `{manifest.post_analysis_hashes.get('sha1', 'N/A')}`",
                    f"- **SHA-256:** `{manifest.post_analysis_hashes.get('sha256', 'N/A')}`",
                    f"- **SHA-512:** `{manifest.post_analysis_hashes.get('sha512', 'N/A')}`",
                    f"- **Verification Timestamp (UTC):** {manifest.verification_timestamp_utc.strftime('%Y-%m-%d %H:%M:%S UTC') if manifest.verification_timestamp_utc else 'N/A'}",
                ]
            )

        if manifest.notes:
            lines.extend(["", "### Notes", manifest.notes])

        return "\n".join(lines)

    @classmethod
    def generate_custody_timeline(cls, ledger: EvidenceLedger) -> str:
        """Generate a formatted chronological markdown timeline of all custody events."""
        lines = [
            f"# Chain of Custody Timeline: {ledger.evidence_id} (Case: {ledger.case_id})",
            f"- **Ledger ID:** `{ledger.ledger_id}`",
            f"- **Total Recorded Events:** {len(ledger.events)}",
            f"- **Tamper Detected:** `{'YES - COMPROMISED' if ledger.is_tampered else 'NO - DEFUSED / CLEAN'}`",
            "",
            "| # | Timestamp (UTC) | Action | Performed By | Agency | Description | SHA-256 Hash |",
            "|---|---|---|---|---|---|---|",
        ]
        for idx, event in enumerate(ledger.events, 1):
            ts = event.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S")
            short_hash = f"`{event.evidence_hash[:16]}...`" if event.evidence_hash else "N/A"
            agency = event.agency or "-"
            desc = event.description.replace("|", "\\|")
            lines.append(
                f"| {idx} | {ts} | `{event.action}` | {event.performed_by} | {agency} | {desc} | {short_hash} |"
            )

        return "\n".join(lines)
