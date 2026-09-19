"""Core exception definitions for Email Forensic Tool (EFT)."""


class EFTException(Exception):
    """Base exception for all Email Forensic Tool errors."""

    pass


class EvidenceTamperedException(EFTException):
    """Raised when evidence integrity verification fails (e.g. checksum mismatch)."""

    pass


class CorruptFileError(EFTException):
    """Raised when an email evidence file is corrupt, malformed, or truncated."""

    pass


class UnsupportedFormatError(EFTException):
    """Raised when an email file format is not supported or cannot be recognized."""

    pass


class ForensicIngestionError(EFTException):
    """Raised when an unrecoverable error occurs during email parsing or ingestion."""

    pass
