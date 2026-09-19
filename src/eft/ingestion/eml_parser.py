"""RFC 822 / RFC 5322 EML parser for Email Forensic Tool."""

from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from eft.core.exceptions import CorruptFileError, ForensicIngestionError
from eft.core.integrity import compute_bytes_hashes
from eft.ingestion.base import BaseEmailParser
from eft.models.canonical import (
    AttachmentMetadata,
    CanonicalEmail,
    MIMEPartNode,
    SourceFileInfo,
)


class EMLParser(BaseEmailParser):
    """Parser for standard RFC 822 / 5322 (.eml) email files."""

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
        body_plain, body_html, attachments, mime_parts = self._extract_content(msg)

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
            body_plain=body_plain,
            body_html=body_html,
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
        # Support multiple headers or comma-separated addresses
        values = msg.get_all(header_name, [])
        addresses: List[str] = []
        for val in values:
            for part in str(val).split(","):
                part_clean = part.strip()
                if part_clean:
                    addresses.append(part_clean)
        return addresses

    def _extract_content(
        self, msg: EmailMessage
    ) -> Tuple[Optional[str], Optional[str], List[AttachmentMetadata], List[MIMEPartNode]]:
        plain_parts: List[str] = []
        html_parts: List[str] = []
        attachments: List[AttachmentMetadata] = []
        mime_nodes: List[MIMEPartNode] = []

        part_idx = 0
        for part in msg.walk():
            part_idx += 1
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            is_multipart = part.is_multipart()
            charset = part.get_content_charset()
            encoding = part.get("Content-Transfer-Encoding")
            content_id = part.get("Content-ID")

            raw_payload = b""
            if not is_multipart:
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        raw_payload = payload
                    elif isinstance(payload, str):
                        raw_payload = payload.encode(charset or "utf-8", errors="replace")
                except Exception:
                    raw_payload = b""

            node = MIMEPartNode(
                part_index=part_idx,
                content_type=content_type,
                charset=charset,
                content_transfer_encoding=encoding,
                content_disposition=disposition,
                content_id=content_id,
                is_multipart=is_multipart,
                size_bytes=len(raw_payload) if not is_multipart else 0,
            )
            mime_nodes.append(node)

            if is_multipart:
                continue

            # Determine if attachment
            is_attachment = (
                disposition == "attachment"
                or bool(filename)
                or (
                    content_type not in ["text/plain", "text/html"]
                    and disposition != "inline"
                )
            )

            if is_attachment:
                safe_name = filename or f"attachment_{part_idx}.bin"
                att_hashes = compute_bytes_hashes(raw_payload)
                attachments.append(
                    AttachmentMetadata(
                        filename=safe_name,
                        content_type=content_type,
                        size_bytes=len(raw_payload),
                        content_id=content_id,
                        content_disposition=disposition,
                        is_inline=(disposition == "inline"),
                        hashes=att_hashes,
                        raw_data=raw_payload,
                    )
                )
            else:
                text_content = self._decode_text_payload(raw_payload, charset)
                if content_type == "text/plain":
                    plain_parts.append(text_content)
                elif content_type == "text/html":
                    html_parts.append(text_content)

        body_plain = "\n\n".join(plain_parts) if plain_parts else None
        body_html = "\n\n".join(html_parts) if html_parts else None

        return body_plain, body_html, attachments, mime_nodes

    def _decode_text_payload(self, data: bytes, charset: Optional[str]) -> str:
        if not data:
            return ""

        charsets_to_try = [charset] if charset else []
        charsets_to_try.extend(["utf-8", "latin-1", "windows-1252", "iso-8859-1"])

        for cs in charsets_to_try:
            if not cs:
                continue
            try:
                return data.decode(cs)
            except (UnicodeDecodeError, LookupError):
                continue

        return data.decode("utf-8", errors="replace")
