"""Ingestion subsystem for Email Forensic Tool."""

from eft.ingestion.base import BaseEmailParser
from eft.ingestion.eml_parser import EMLParser
from eft.ingestion.engine import EmailIngester
from eft.ingestion.mbox_parser import MBOXParser
from eft.ingestion.msg_parser import MSGParser

__all__ = [
    "BaseEmailParser",
    "EmailIngester",
    "EMLParser",
    "MSGParser",
    "MBOXParser",
]
