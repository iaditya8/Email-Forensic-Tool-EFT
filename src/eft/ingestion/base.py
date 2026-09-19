"""Abstract base parser interface for Email Forensic Tool."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Union

from eft.models.canonical import CanonicalEmail, SourceFileInfo


class BaseEmailParser(ABC):
    """Abstract base class for all forensic email format parsers."""

    @abstractmethod
    def parse(
        self,
        file_path_or_data: Union[str, Path, bytes],
        source_info: SourceFileInfo,
    ) -> List[CanonicalEmail]:
        """Parse raw email data into one or more CanonicalEmail objects.

        Args:
            file_path_or_data: Path to the file or in-memory binary data.
            source_info: Forensic file information and cryptographic digests.

        Returns:
            List of parsed CanonicalEmail objects.
        """
        pass
