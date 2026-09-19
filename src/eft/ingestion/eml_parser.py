"""RFC 822 / RFC 5322 EML parser for Email Forensic Tool."""

from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from eft.core.exceptions import CorruptFileError, ForensicIngestionError
from eft.ingestion.base import BaseEmailParser
from eft.ingestion.header_decomposer import HeaderDecomposer
from eft.ingestion.mime_decomposer import MIMETreeDecomposer
from eft.models.canonical import (
    CanonicalEmail,
    SourceFileInfo,
)


class EMLParser(BaseEmailParser):
    """Parser for standard RFC 822 / 5322 (.eml) email files."""

    def __init__(self) -> None:
        self._mime_decomposer = MIMETreeDecomposer()

    def parse(
        self,
        file_path_or_data: Union[str, Path, bytes],
        source_info: SourceFileInfo,
    ) -> List[CanonicalEmail]:
        """Parse an EML file or raw bytes into a CanonicalEmail model."""
        raw_bytes = self._read_bytes(file_path_or_data)
        if not raw_bytes.strip():
            raise CorruptFileError(f"Target email file is empty: {source_info.file_name}")

        try:
            msg: EmailMessage = email.message_from_bytes(
                raw_bytes, policy=policy.default
            )
        except Exception as e:
            raise CorruptFileError(
                f"Failed to parse MIME structure for {source_info.file_name}: {e}"
            ) from e

        diagnostics: List[str] = []
        if msg.defects:
            for defect in msg.defects:
                diagnostics.append(f"MIME defect: {defect.__class__.__name__} - {defect}")

        ordered_headers, headers_map = self._extract_headers(msg)
        header_decomp = HeaderDecomposer.decompose(ordered_headers)

        (
            mime_parts,
            body_artifacts,
            attachments,
            body_plain,
            body_html,
        ) = self._mime_decomposer.decompose(msg)

        canonical = CanonicalEmail(
            message_id=self._clean_header(msg.get("Message-ID")),
            date=self._clean_header(msg.get("Date")),
            subject=self._clean_header(msg.get("Subject")),
            from_address=self._clean_header(msg.get("From")),
            to_addresses=self._extract_address_list(msg, "To"),
            cc_addresses=self._extract_address_list(msg, "Cc"),
            bcc_addresses=self._extract_address_list(msg, "Bcc"),
            reply_to=self._clean_header(msg.get("Reply-To")),
            return_path=self._clean_header(msg.get("Return-Path")),
            headers=headers_map,
            ordered_headers=ordered_headers,
            header_decomposition=header_decomp,
            body_plain=body_plain,
            body_html=body_html,
            body_artifacts=body_artifacts,
            attachments=attachments,
            mime_parts=mime_parts,
            source_file=source_info,
            parsing_diagnostics=diagnostics,
        )

        return [canonical]

    def _read_bytes(self, target: Union[str, Path, bytes]) -> bytes:
        if isinstance(target, bytes):
            return target
        path = Path(target)
        try:
            with open(path, "rb") as f:
                return f.read()
        except Exception as e:
            raise ForensicIngestionError(f"Unable to read file in read-only mode: {e}") from e

    def _clean_header(self, val: Optional[str]) -> Optional[str]:
        if val is None:
            return None
        return str(val).strip()

    def _extract_headers(
        self, msg: EmailMessage
    ) -> Tuple[List[Tuple[str, str]], Dict[str, Union[str, List[str]]]]:
        ordered: List[Tuple[str, str]] = []
        mapping: Dict[str, List[str]] = {}

        for k, v in msg.raw_items():
            str_val = str(v)
            ordered.append((k, str_val))
            k_lower = k.lower()
            if k_lower not in mapping:
                mapping[k_lower] = []
            mapping[k_lower].append(str_val)

        final_mapping: Dict[str, Union[str, List[str]]] = {}
        for k, vals in mapping.items():
            if len(vals) == 1:
                final_mapping[k] = vals[0]
            else:
                final_mapping[k] = vals

        return ordered, final_mapping

    def _extract_address_list(self, msg: EmailMessage, header_name: str) -> List[str]:
        raw = msg.get(header_name)
        if not raw:
            return []
        values = msg.get_all(header_name, [])
        addresses: List[str] = []
        for val in values:
            for part in str(val).split(","):
                part_clean = part.strip()
                if part_clean:
                    addresses.append(part_clean)
        return addresses
