"""Unix MBOX archive parser for Email Forensic Tool."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Union

from eft.core.exceptions import CorruptFileError, ForensicIngestionError
from eft.ingestion.base import BaseEmailParser
from eft.ingestion.eml_parser import EMLParser
from eft.models.canonical import CanonicalEmail, SourceFileInfo

# Regex matching standard mbox message delimiter line: "From <addr> <timestamp>"
MBOX_FROM_DELIMITER = re.compile(rb"^(From\s+[^\r\n]*)", re.MULTILINE)


class MBOXParser(BaseEmailParser):
    """Parser for Unix MBOX mailbox archive files."""

    def __init__(self) -> None:
        self._eml_parser = EMLParser()

    def parse(
        self,
        file_path_or_data: Union[str, Path, bytes],
        source_info: SourceFileInfo,
    ) -> List[CanonicalEmail]:
        """Parse an MBOX mailbox archive file into a list of CanonicalEmail models."""
        raw_bytes: bytes

        if isinstance(file_path_or_data, bytes):
            raw_bytes = file_path_or_data
        else:
            path = Path(file_path_or_data)
            try:
                with open(path, "rb") as f:
                    raw_bytes = f.read()
            except Exception as e:
                raise ForensicIngestionError(f"Unable to read MBOX file: {e}") from e

        if not raw_bytes.strip():
            raise CorruptFileError(f"Target MBOX archive is empty: {source_info.file_name}")

        messages: List[CanonicalEmail] = []

        try:
            raw_messages = self._split_mbox_messages(raw_bytes)
            if not raw_messages:
                raise CorruptFileError(
                    f"No valid email messages found in MBOX archive: {source_info.file_name}"
                )

            for idx, msg_bytes in enumerate(raw_messages):
                try:
                    # Strip leading mbox 'From ' envelope line before feeding to RFC 5322 parser
                    cleaned_bytes = self._strip_mbox_envelope_line(msg_bytes)
                    parsed_list = self._eml_parser.parse(cleaned_bytes, source_info)
                    for item in parsed_list:
                        item.parsing_diagnostics.append(
                            f"Extracted from MBOX archive entry #{idx + 1}"
                        )
                        messages.append(item)
                except Exception as parse_err:
                    raise CorruptFileError(
                        f"Corrupt message encountered at index {idx} in {source_info.file_name}: {parse_err}"
                    ) from parse_err

        except CorruptFileError:
            raise
        except Exception as e:
            raise CorruptFileError(
                f"Failed to parse MBOX archive {source_info.file_name}: {e}"
            ) from e

        return messages

    def _split_mbox_messages(self, data: bytes) -> List[bytes]:
        """Split raw mbox byte stream into individual RFC 5322 message byte buffers."""
        matches = list(MBOX_FROM_DELIMITER.finditer(data))
        if not matches:
            # If no delimiter found, treat whole buffer as single message if non-empty
            return [data] if data.strip() else []

        messages: List[bytes] = []
        for i, match in enumerate(matches):
            start = match.start()
            end = matches[i + 1].start() if (i + 1 < len(matches)) else len(data)
            msg_data = data[start:end].strip()
            if msg_data:
                messages.append(msg_data)

        return messages

    def _strip_mbox_envelope_line(self, msg_bytes: bytes) -> bytes:
        """Strip initial 'From ...' envelope line if present."""
        if msg_bytes.startswith(b"From "):
            idx = msg_bytes.find(b"\n")
            if idx != -1:
                return msg_bytes[idx + 1 :]
        return msg_bytes
