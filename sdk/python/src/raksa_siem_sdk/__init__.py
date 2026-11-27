"""Zero-dependency Python SDK for raksa-siem."""

from .client import SiemClient, SiemClientError, validate_endpoint_url
from .correlator import (
    AssetCatalog,
    AssetEntry,
    Correlator,
    Finding,
    PostureScore,
    SequenceRule,
    SequenceStep,
    ThreatFeed,
    Timeline,
    build_timeline,
    compute_posture,
)
from .normalizer import (
    SUPPORTED_FORMATS,
    NormalizedEvent,
    detect_format,
    normalize_file,
    normalize_line,
    normalize_lines,
    normalize_report,
)

SDK_VERSION = "0.2.0"
SCHEMA_VERSION = "1.0"

__all__ = [
    "SDK_VERSION",
    "SCHEMA_VERSION",
    "SUPPORTED_FORMATS",
    "NormalizedEvent",
    "Finding",
    "PostureScore",
    "Timeline",
    "ThreatFeed",
    "AssetEntry",
    "AssetCatalog",
    "SequenceStep",
    "SequenceRule",
    "Correlator",
    "SiemClient",
    "SiemClientError",
    "detect_format",
    "normalize_file",
    "normalize_line",
    "normalize_lines",
    "normalize_report",
    "build_timeline",
    "compute_posture",
    "validate_endpoint_url",
]
