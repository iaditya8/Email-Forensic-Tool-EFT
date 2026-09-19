"""Microsoft Outlook OLE MSG parser for Email Forensic Tool."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

try:
    import extract_msg
except ImportError:
    extract_msg = None  # type: ignore

from eft.core.exceptions import CorruptFileError, ForensicIngestionError
from eft.core.integrity import compute_bytes_hashes
from eft.ingestion.base import BaseEmailParser
from eft.ingestion.header_decomposer import HeaderDecomposer
from eft.models.canonical import (
    AttachmentMetadata,
    CanonicalEmail,
    IsolatedBody,
    IsolatedBodyArtifacts,
    MIMEPartNode,
    SourceFileInfo,
)


class MSGParser(BaseEmailParser):
    """Parser for Microsoft Outlook (.msg) binary OLE structured files."""

    def parse(
        self,
        file_path_or_data: Union[str, Path, bytes],
        source_info: SourceFileInfo,
    ) -> List[CanonicalEmail]:
        """Parse an Outlook MSG file or byte stream into a CanonicalEmail model."""
        if extract_msg is None:
            raise ForensicIngestionError(
                "extract-msg library is required to parse .msg files but is not installed."
            )

        msg_obj = None
        try:
            if isinstance(file_path_or_data, bytes):
                if not file_path_or_data:
                    raise CorruptFileError(f"Target MSG file is empty: {source_info.file_name}")
                msg_obj = extract_msg.openMsg(io.BytesIO(file_path_or_data))
            else:
                path = Path(file_path_or_data)
                if path.stat().st_size == 0:
                    raise CorruptFileError(f"Target MSG file is empty: {source_info.file_name}")
                # Read via byte stream into openMsg to enforce read-only access
                with open(path, "rb") as f:
                    content = f.read()
                msg_obj = extract_msg.openMsg(io.BytesIO(content))

            return [self._convert_to_canonical(msg_obj, source_info)]
        except CorruptFileError:
            raise
        except Exception as e:
            raise CorruptFileError(
                f"Failed to parse Outlook MSG file {source_info.file_name}: {e}"
            ) from e
        finally:
            if msg_obj is not None:
                try:
                    msg_obj.close()
                except Exception:
                    pass

    def _convert_to_canonical(
        self, msg: extract_msg.Message, source_info: SourceFileInfo
    ) -> CanonicalEmail:
        diagnostics: List[str] = []

        # Header parsing
        ordered_headers, headers_map = self._extract_headers(msg)
        header_decomp = HeaderDecomposer.decompose(ordered_headers)

        # Body parsing
        body_plain: Optional[str] = None
        body_html: Optional[str] = None
        body_rtf: Optional[str] = None

        plain_bodies: List[IsolatedBody] = []
        html_bodies: List[IsolatedBody] = []
        rtf_bodies: List[IsolatedBody] = []

        try:
            if msg.body:
                body_plain = str(msg.body)
                plain_bytes = body_plain.encode("utf-8")
                plain_bodies.append(
                    IsolatedBody(
                        content=body_plain,
                        content_type="text/plain",
                        charset="utf-8",
                        size_bytes=len(plain_bytes),
                        sha256=hashlib.sha256(plain_bytes).hexdigest(),
                    )
                )
        except Exception as e:
            diagnostics.append(f"Failed to extract plaintext body: {e}")

        try:
            if getattr(msg, "htmlBody", None):
                raw_html = msg.htmlBody
                if isinstance(raw_html, bytes):
                    body_html = raw_html.decode("utf-8", errors="replace")
                elif isinstance(raw_html, str):
                    body_html = raw_html

                if body_html:
                    html_bytes = body_html.encode("utf-8")
                    html_bodies.append(
                        IsolatedBody(
                            content=body_html,
                            content_type="text/html",
                            charset="utf-8",
                            size_bytes=len(html_bytes),
                            sha256=hashlib.sha256(html_bytes).hexdigest(),
                        )
                    )
        except Exception as e:
            diagnostics.append(f"Failed to extract HTML body: {e}")

        try:
            if getattr(msg, "rtfBody", None):
                raw_rtf = msg.rtfBody
                if isinstance(raw_rtf, bytes):
                    body_rtf = raw_rtf.decode("utf-8", errors="replace")
                elif isinstance(raw_rtf, str):
                    body_rtf = raw_rtf

                if body_rtf:
                    rtf_bytes = body_rtf.encode("utf-8")
                    rtf_bodies.append(
                        IsolatedBody(
                            content=body_rtf,
                            content_type="text/rtf",
                            charset="utf-8",
                            size_bytes=len(rtf_bytes),
                            sha256=hashlib.sha256(rtf_bytes).hexdigest(),
                        )
                    )
        except Exception:
            pass

        body_artifacts = IsolatedBodyArtifacts(
            plain_bodies=plain_bodies,
            html_bodies=html_bodies,
            rtf_bodies=rtf_bodies,
        )

        # Attachment parsing
        attachments: List[AttachmentMetadata] = []
        try:
            for idx, att in enumerate(getattr(msg, "attachments", [])):
                att_name = (
                    getattr(att, "longFilename", None)
                    or getattr(att, "shortFilename", None)
                    or getattr(att, "name", None)
                    or f"msg_attachment_{idx + 1}.bin"
                )
                att_data: bytes = b""
                try:
                    raw = getattr(att, "data", None)
                    if isinstance(raw, bytes):
                        att_data = raw
                    elif raw is not None:
                        att_data = bytes(raw)
                except Exception as e:
                    diagnostics.append(f"Could not read attachment {att_name} data: {e}")

                att_mimetype = (
                    getattr(att, "mimetype", "application/octet-stream")
                    or "application/octet-stream"
                )
                att_cid = getattr(att, "cid", None)
                att_hashes = compute_bytes_hashes(att_data)

                attachments.append(
                    AttachmentMetadata(
                        filename=str(att_name),
                        content_type=str(att_mimetype),
                        size_bytes=len(att_data),
                        content_id=str(att_cid) if att_cid else None,
                        is_inline=bool(att_cid),
                        hashes=att_hashes,
                        raw_data=att_data,
                    )
                )
        except Exception as e:
            diagnostics.append(f"Error iterating MSG attachments: {e}")

        # Recipients
        to_list: List[str] = []
        cc_list: List[str] = []
        bcc_list: List[str] = []

        if getattr(msg, "to", None):
            to_list = [t.strip() for t in str(msg.to).split(";") if t.strip()]
        if getattr(msg, "cc", None):
            cc_list = [c.strip() for c in str(msg.cc).split(";") if c.strip()]
        if getattr(msg, "bcc", None):
            bcc_list = [b.strip() for b in str(msg.bcc).split(";") if b.strip()]

        # MIME part placeholder tree
        mime_parts: List[MIMEPartNode] = []
        if body_plain:
            mime_parts.append(
                MIMEPartNode(
                    part_index=1,
                    part_path="1",
                    depth=0,
                    content_type="text/plain",
                    size_bytes=len(body_plain.encode("utf-8")),
                )
            )
        if body_html:
            mime_parts.append(
                MIMEPartNode(
                    part_index=2,
                    part_path="2",
                    depth=0,
                    content_type="text/html",
                    size_bytes=len(body_html.encode("utf-8")),
                )
            )

        return CanonicalEmail(
            message_id=getattr(msg, "messageId", None),
            date=str(msg.date) if getattr(msg, "date", None) else None,
            subject=getattr(msg, "subject", None),
            from_address=getattr(msg, "sender", None),
            to_addresses=to_list,
            cc_addresses=cc_list,
            bcc_addresses=bcc_list,
            reply_to=getattr(msg, "replyTo", None),
            return_path=None,
            headers=headers_map,
            ordered_headers=ordered_headers,
            header_decomposition=header_decomp,
            body_plain=body_plain,
            body_html=body_html,
            body_rtf=body_rtf,
            body_artifacts=body_artifacts,
            attachments=attachments,
            mime_parts=mime_parts,
            source_file=source_info,
            parsing_diagnostics=diagnostics,
        )

    def _extract_headers(
        self, msg: extract_msg.Message
    ) -> Tuple[List[Tuple[str, str]], Dict[str, Union[str, List[str]]]]:
        ordered: List[Tuple[str, str]] = []
        headers_dict: Dict[str, List[str]] = {}

        raw_header_str = getattr(msg, "header", None) or getattr(msg, "headers", None)
        if raw_header_str and hasattr(raw_header_str, "items"):
            # Header object / dict
            for k, v in raw_header_str.items():
                k_str = str(k)
                v_str = str(v)
                ordered.append((k_str, v_str))
                k_lower = k_str.lower()
                if k_lower not in headers_dict:
                    headers_dict[k_lower] = []
                headers_dict[k_lower].append(v_str)
        elif isinstance(raw_header_str, str):
            # Parse raw header text
            lines = raw_header_str.splitlines()
            current_header = None
            current_value = []
            for line in lines:
                if (line.startswith(" ") or line.startswith("\t")) and current_header:
                    current_value.append(line.strip())
                elif ":" in line:
                    if current_header:
                        val_str = " ".join(current_value)
                        ordered.append((current_header, val_str))
                        k_lower = current_header.lower()
                        if k_lower not in headers_dict:
                            headers_dict[k_lower] = []
                        headers_dict[k_lower].append(val_str)
                    k, v = line.split(":", 1)
                    current_header = k.strip()
                    current_value = [v.strip()]
            if current_header:
                val_str = " ".join(current_value)
                ordered.append((current_header, val_str))
                k_lower = current_header.lower()
                if k_lower not in headers_dict:
                    headers_dict[k_lower] = []
                headers_dict[k_lower].append(val_str)

        final_mapping: Dict[str, Union[str, List[str]]] = {}
        for k, vals in headers_dict.items():
            if len(vals) == 1:
                final_mapping[k] = vals[0]
            else:
                final_mapping[k] = vals

        return ordered, final_mapping
