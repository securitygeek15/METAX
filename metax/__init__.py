"""
MetaX — Advanced Metadata Extraction & Digital Forensics Suite.
"""

from metax.core import extract_metadata, calculate_hashes, detect_file_type
from metax.forensics import analyze_forensics
from metax.gps import extract_gps_data
from metax.sanitizer import strip_image_metadata, strip_image_bytes

__version__ = "0.2.0"
__all__ = [
    "extract_metadata",
    "calculate_hashes",
    "detect_file_type",
    "analyze_forensics",
    "extract_gps_data",
    "strip_image_metadata",
    "strip_image_bytes",
]

