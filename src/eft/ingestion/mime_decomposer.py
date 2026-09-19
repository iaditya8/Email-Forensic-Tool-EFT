"""MIME Tree Decomposition and Body Isolation Engine for Email Forensic Tool."""

from __future__ import annotations

import hashlib
from email.message import EmailMessage
from typing import List, Optional, Tuple

from eft.core.integrity import compute_bytes_hashes
from eft.models.canonical import (
    AttachmentMetadata,
    IsolatedBody,
    IsolatedBodyArtifacts,
    MIMEPartNode,
)


class MIMETreeDecomposer:
    """Recursively walks and decomposes MIME message trees into structured nodes and isolated artifacts."""

    def __init__(self) -> None:
        self._part_counter = 0

    def decompose(
        self, msg: EmailMessage
    ) -> Tuple[List[MIMEPartNode], IsolatedBodyArtifacts, List[AttachmentMetadata], Optional[str], Optional[str]]:
        """Decompose an EmailMessage into hierarchical MIME nodes, isolated body artifacts, and attachments.

        Args:
            msg: The email.message.EmailMessage instance to decompose.

        Returns:
            Tuple of:
            - Flat/hierarchical list of MIMEPartNodes
            - IsolatedBodyArtifacts container
            - List of AttachmentMetadata
            - Combined plaintext body (if any)
            - Combined HTML body (if any)
        """
        self._part_counter = 0
        plain_bodies: List[IsolatedBody] = []
        html_bodies: List[IsolatedBody] = []
        attachments: List[AttachmentMetadata] = []

        root_nodes = self._process_part(
            part=msg,
            parent_path=None,
            depth=0,
            sibling_index=1,
            plain_bodies=plain_bodies,
            html_bodies=html_bodies,
            attachments=attachments,
        )

        # Collect flat list containing all nodes
        flat_nodes: List[MIMEPartNode] = []
        for node in root_nodes:
            self._flatten_tree(node, flat_nodes)

        combined_plain = (
            "\n\n".join([b.content for b in plain_bodies]) if plain_bodies else None
        )
        combined_html = (
            "\n\n".join([b.content for b in html_bodies]) if html_bodies else None
        )

        body_artifacts = IsolatedBodyArtifacts(
            plain_bodies=plain_bodies,
            html_bodies=html_bodies,
            rtf_bodies=[],
        )

        return flat_nodes, body_artifacts, attachments, combined_plain, combined_html

    def _process_part(
        self,
        part: EmailMessage,
        parent_path: Optional[str],
        depth: int,
        sibling_index: int,
        plain_bodies: List[IsolatedBody],
        html_bodies: List[IsolatedBody],
        attachments: List[AttachmentMetadata],
    ) -> List[MIMEPartNode]:
        self._part_counter += 1
        part_idx = self._part_counter

        part_path = f"{parent_path}.{sibling_index}" if parent_path else str(sibling_index)
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        is_multipart = part.is_multipart()
        charset = part.get_content_charset()
        encoding = part.get("Content-Transfer-Encoding")
        content_id = part.get("Content-ID")
        boundary = part.get_param("boundary") if hasattr(part, "get_param") else None

        # Extract part-level raw headers
        part_headers: List[Tuple[str, str]] = []
        if hasattr(part, "raw_items"):
            for k, v in part.raw_items():
                part_headers.append((str(k), str(v)))

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

        # Determine attachment classification
        is_attachment = (
            disposition == "attachment"
            or bool(filename)
            or (
                content_type not in ["text/plain", "text/html"]
                and not is_multipart
                and disposition != "inline"
            )
        )

        node = MIMEPartNode(
            part_index=part_idx,
            part_path=part_path,
            depth=depth,
            parent_path=parent_path,
            content_type=content_type,
            charset=charset,
            content_transfer_encoding=encoding,
            content_disposition=disposition,
            content_id=content_id,
            boundary=boundary,
            is_multipart=is_multipart,
            is_attachment=is_attachment,
            filename=filename,
            size_bytes=len(raw_payload) if not is_multipart else 0,
            raw_headers=part_headers,
            children=[],
        )

        if is_multipart:
            # Process subparts
            payload = part.get_payload()
            if isinstance(payload, list):
                for idx, subpart in enumerate(payload):
                    sub_nodes = self._process_part(
                        part=subpart,
                        parent_path=part_path,
                        depth=depth + 1,
                        sibling_index=idx + 1,
                        plain_bodies=plain_bodies,
                        html_bodies=html_bodies,
                        attachments=attachments,
                    )
                    node.children.extend(sub_nodes)
        else:
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
                payload_sha256 = hashlib.sha256(raw_payload).hexdigest()
                isolated = IsolatedBody(
                    content=text_content,
                    content_type=content_type,
                    charset=charset,
                    size_bytes=len(raw_payload),
                    sha256=payload_sha256,
                )
                if content_type == "text/plain":
                    plain_bodies.append(isolated)
                elif content_type == "text/html":
                    html_bodies.append(isolated)

        return [node]

    def _flatten_tree(self, node: MIMEPartNode, accumulator: List[MIMEPartNode]) -> None:
        accumulator.append(node)
        for child in node.children:
            self._flatten_tree(child, accumulator)

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
