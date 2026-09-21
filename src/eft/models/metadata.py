"""Forensic data models for EXIF, Document, PDF, and Multimedia metadata extraction."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from eft.models.threat import RiskSeverity


class GPSCoordinates(BaseModel):
    """Forensic geographical positioning coordinates extracted from EXIF metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    latitude: float = Field(..., description="Decimal degrees latitude (-90.0 to 90.0)")
    longitude: float = Field(..., description="Decimal degrees longitude (-180.0 to 180.0)")
    altitude_meters: Optional[float] = Field(
        default=None, description="Altitude in meters above/below sea level"
    )
    latitude_ref: str = Field(default="N", description="Latitude reference ('N' or 'S')")
    longitude_ref: str = Field(default="E", description="Longitude reference ('E' or 'W')")
    google_maps_url: str = Field(..., description="Clickable Google Maps link for geolocation")
    timestamp_utc: Optional[datetime] = Field(
        default=None, description="GPS satellite timestamp in UTC"
    )


class ImageEXIFMetadata(BaseModel):
    """Extracted EXIF/TIFF and camera metadata from image artifacts."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    camera_make: Optional[str] = Field(default=None, description="Camera or device manufacturer")
    camera_model: Optional[str] = Field(default=None, description="Camera or smartphone model name")
    lens_model: Optional[str] = Field(default=None, description="Camera lens make and model")
    software: Optional[str] = Field(default=None, description="Firmware or image editing software")
    datetime_original: Optional[datetime] = Field(
        default=None, description="Date/time original photo was taken"
    )
    datetime_digitized: Optional[datetime] = Field(
        default=None, description="Date/time image was stored digitally"
    )
    image_width: Optional[int] = Field(default=None, description="Pixel width of image")
    image_height: Optional[int] = Field(default=None, description="Pixel height of image")
    color_space: Optional[str] = Field(
        default=None, description="Color space definition (e.g. sRGB)"
    )
    orientation: Optional[int] = Field(default=None, description="EXIF orientation flag (1-8)")
    iso_speed: Optional[int] = Field(default=None, description="ISO sensitivity speed rating")
    exposure_time: Optional[str] = Field(
        default=None, description="Shutter speed / exposure time (e.g. 1/250s)"
    )
    f_number: Optional[float] = Field(default=None, description="Aperture f-number")
    focal_length_mm: Optional[float] = Field(
        default=None, description="Focal length in millimeters"
    )
    gps: Optional[GPSCoordinates] = Field(
        default=None, description="Extracted GPS location coordinates"
    )
    raw_tags: Dict[str, Any] = Field(
        default_factory=dict, description="Raw dictionary of all parsed tags"
    )


class DocumentMetadata(BaseModel):
    """Extracted metadata properties from Microsoft Office and OpenXML documents."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    title: Optional[str] = Field(default=None, description="Document title")
    subject: Optional[str] = Field(default=None, description="Document subject")
    creator: Optional[str] = Field(default=None, description="Document author or creator user")
    last_modified_by: Optional[str] = Field(
        default=None, description="Username of last editing user"
    )
    created: Optional[datetime] = Field(
        default=None, description="Document creation timestamp in UTC"
    )
    modified: Optional[datetime] = Field(
        default=None, description="Document last modification timestamp in UTC"
    )
    revision: Optional[int] = Field(
        default=None, description="Document revision / version increment number"
    )
    application: Optional[str] = Field(
        default=None, description="Application software that created document"
    )
    app_version: Optional[str] = Field(
        default=None, description="Version of generating application software"
    )
    total_editing_time_minutes: Optional[int] = Field(
        default=None, description="Total editing duration in minutes"
    )
    page_count: Optional[int] = Field(default=None, description="Total document page count")
    word_count: Optional[int] = Field(default=None, description="Total document word count")
    character_count: Optional[int] = Field(
        default=None, description="Total document character count"
    )
    company: Optional[str] = Field(default=None, description="Company or organization metadata")
    custom_properties: Dict[str, str] = Field(
        default_factory=dict, description="Custom document properties"
    )


class PDFStructureMetadata(BaseModel):
    """Extracted structural metadata and active weaponization indicators from PDF artifacts."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    title: Optional[str] = Field(default=None, description="PDF document title from /Info catalog")
    author: Optional[str] = Field(default=None, description="PDF author from /Info catalog")
    subject: Optional[str] = Field(default=None, description="PDF subject descriptor")
    keywords: Optional[str] = Field(default=None, description="PDF search keywords")
    creator: Optional[str] = Field(
        default=None, description="Application that generated original content"
    )
    producer: Optional[str] = Field(
        default=None, description="Software or engine that converted content to PDF"
    )
    creation_date: Optional[datetime] = Field(
        default=None, description="PDF creation timestamp in UTC"
    )
    mod_date: Optional[datetime] = Field(
        default=None, description="PDF modification timestamp in UTC"
    )
    pdf_version: Optional[str] = Field(
        default=None, description="PDF specification version (e.g. '1.7')"
    )
    page_count: Optional[int] = Field(
        default=None, description="Total page count calculated from /Pages catalog"
    )
    is_encrypted: bool = Field(
        default=False, description="Whether document utilizes PDF security / encryption"
    )
    has_javascript: bool = Field(
        default=False, description="Whether PDF contains /JavaScript or /JS action streams"
    )
    has_launch_action: bool = Field(
        default=False, description="Whether PDF contains /Launch arbitrary execution action"
    )
    has_embedded_files: bool = Field(
        default=False, description="Whether PDF contains /EmbeddedFiles attachments"
    )
    has_open_action: bool = Field(
        default=False, description="Whether PDF contains /OpenAction automatic trigger"
    )
    has_acroform: bool = Field(
        default=False, description="Whether PDF contains interactive /AcroForm fields"
    )
    suspicious_elements: List[str] = Field(
        default_factory=list, description="Forensic active threat indicators"
    )


class AudioVideoMetadata(BaseModel):
    """Extracted ID3 and multimedia metadata from audio and video containers."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    title: Optional[str] = Field(default=None, description="Media track / file title")
    artist: Optional[str] = Field(default=None, description="Performing artist or author")
    album: Optional[str] = Field(default=None, description="Album or collection name")
    year: Optional[str] = Field(default=None, description="Release or recording year")
    genre: Optional[str] = Field(default=None, description="Media genre description")
    encoder: Optional[str] = Field(default=None, description="Encoder software or tool")
    duration_seconds: Optional[float] = Field(
        default=None, description="Calculated duration in seconds"
    )
    bitrate_kbps: Optional[int] = Field(default=None, description="Bitrate in kilobits per second")
    comment: Optional[str] = Field(default=None, description="User comments embedded in metadata")


class MetadataAnomaly(BaseModel):
    """Forensic anomaly, timestamp tampering, or weaponized metadata indicator."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    anomaly_type: str = Field(..., description="Categorical identifier for the anomaly")
    severity: RiskSeverity = Field(..., description="Risk severity tier")
    description: str = Field(..., description="Detailed forensic explanation of the anomaly")
    field_name: Optional[str] = Field(
        default=None, description="Target metadata field or attribute name"
    )


class ExtractedMetadataReport(BaseModel):
    """Comprehensive forensic metadata report for evidence files and attachments."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Optional[str] = Field(
        default=None, description="Local path to analyzed file, if available"
    )
    filename: str = Field(..., description="Original evidence filename")
    file_type: str = Field(default="unknown", description="Detected or declared artifact type")
    exif: Optional[ImageEXIFMetadata] = Field(
        default=None, description="Image EXIF and camera metadata"
    )
    document: Optional[DocumentMetadata] = Field(
        default=None, description="Office document metadata"
    )
    pdf: Optional[PDFStructureMetadata] = Field(
        default=None, description="PDF structure and threat metadata"
    )
    multimedia: Optional[AudioVideoMetadata] = Field(
        default=None, description="Audio / video container metadata"
    )
    anomalies: List[MetadataAnomaly] = Field(
        default_factory=list, description="List of detected anomalies"
    )
    threat_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Composite metadata threat score (0-100)"
    )
    threat_severity: RiskSeverity = Field(
        default=RiskSeverity.CLEAN, description="Assigned risk severity level"
    )
    summary: str = Field(default="", description="Executive summary of metadata analysis findings")
    extracted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when metadata extraction was performed",
    )
