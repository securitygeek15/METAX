"""
MetaX Core Extraction Engine.
Extracts cryptographic hashes, format-specific metadata (Image, PDF, Audio, Video),
cleanses raw binary noise, and coordinates forensic analysis.
"""

import hashlib
import json
import os
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional

import exifread
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from PyPDF2 import PdfReader
from mutagen import File as AudioFile

from metax.gps import extract_gps_data
from metax.forensics import analyze_forensics


def calculate_hashes(path: str) -> Dict[str, str]:
    """Computes SHA-256, SHA-1, and MD5 cryptographic hashes."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def detect_file_type(path: str) -> str:
    """Classifies file type by extension and header inspection."""
    ext = os.path.splitext(path)[1].lower()

    if ext in [".jpg", ".jpeg", ".png", ".webp", ".tiff", ".bmp", ".gif", ".heic", ".avif"]:
        return "image"
    elif ext == ".pdf":
        return "pdf"
    elif ext in [".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma"]:
        return "audio"
    elif ext in [".mp4", ".mov", ".mkv", ".avi", ".webm"]:
        return "video"
    else:
        return "generic"


def format_bytes(size: int) -> str:
    """Formats byte counts into human-readable strings."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024.0
    return f"{size:.1f} TB"


def get_hex_dump(path: str, num_bytes: int = 256) -> str:
    """Generates a forensic hex dump of the first num_bytes of a file."""
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            data = f.read(num_bytes)

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_parts = [f"{b:02x}" for b in chunk]
            if len(hex_parts) > 8:
                hex_str = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:])
            else:
                hex_str = " ".join(hex_parts)

            ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_str:<49}  |{ascii_chars}|")
        return "\n".join(lines)
    except Exception as e:
        return f"[Error reading hex: {e}]"


def clean_binary_tag(value: Any, raw: bool = False) -> Any:
    """Prevents large binary blobs from polluting output."""
    if raw:
        return str(value)

    if isinstance(value, (bytes, bytearray)):
        if len(value) > 64 or b"\x00" * 4 in value:
            return f"[Binary Data: {len(value)} bytes]"
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return f"[Binary Data: {len(value)} bytes]"

    text = str(value)
    if "\\x00" in text and len(text) > 80:
        return f"[Binary Stream: {len(text)} chars, null-padded]"
    if len(text) > 400:
        return text[:380] + " ... [Truncated]"

    return text


def parse_xmp(xmp_bytes: Any) -> Dict[str, Any]:
    """Parses XMP XML metadata into a clean dictionary."""
    if not xmp_bytes:
        return {}

    try:
        if isinstance(xmp_bytes, (bytes, bytearray)):
            xmp_str = xmp_bytes.decode("utf-8", errors="ignore")
        else:
            xmp_str = str(xmp_bytes)

        start = xmp_str.find("<x:xmpmeta")
        end = xmp_str.find("</x:xmpmeta>")
        if start == -1 or end == -1:
            return {}

        xmp_xml = xmp_str[start : end + len("</x:xmpmeta>")]
        root = ET.fromstring(xmp_xml)
        parsed = {}

        for elem in root.iter():
            tag = elem.tag.split("}")[-1]
            if elem.text and elem.text.strip():
                parsed[tag] = elem.text.strip()

            for k, v in elem.attrib.items():
                key = k.split("}")[-1]
                parsed[f"{tag}:{key}"] = v

        return parsed
    except Exception:
        return {"note": "XMP metadata present but XML structure non-standard"}


def extract_image_metadata(path: str, raw: bool = False) -> Dict[str, Any]:
    """Extracts rich image metadata: EXIF, Pillow IFD, Dimensions, XMP, GPS."""
    data: Dict[str, Any] = {
        "technical": {},
        "EXIF": {},
        "PIL_EXIF": {},
        "XMP": {},
        "INFO": {},
        "GPS": {},
    }

    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=True)
            for tag, val in tags.items():
                if tag in ["JPEGThumbnail", "TIFFThumbnail"]:
                    data["EXIF"][tag] = "[Embedded Thumbnail Image]"
                else:
                    data["EXIF"][tag] = clean_binary_tag(val, raw=raw)
    except Exception:
        pass

    try:
        with Image.open(path) as img:
            data["technical"]["format"] = img.format
            data["technical"]["mode"] = img.mode
            data["technical"]["width"] = img.width
            data["technical"]["height"] = img.height
            data["technical"]["megapixels"] = round((img.width * img.height) / 1_000_000.0, 2)
            data["technical"]["aspect_ratio"] = f"{img.width}:{img.height}"

            exif = img.getexif()
            if exif:
                for tag_id, val in exif.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    data["PIL_EXIF"][str(tag_name)] = clean_binary_tag(val, raw=raw)

            for k, v in img.info.items():
                if k.lower() == "xmp":
                    data["XMP"] = parse_xmp(v)
                elif k.lower() == "icc_profile":
                    data["INFO"]["icc_profile"] = f"[ICC Color Profile: {len(v)} bytes]"
                else:
                    data["INFO"][k] = clean_binary_tag(v, raw=raw)
    except Exception:
        pass

    combined_exif = {}
    combined_exif.update(data["EXIF"])
    combined_exif.update(data["PIL_EXIF"])
    data["GPS"] = extract_gps_data(combined_exif)

    return {k: v for k, v in data.items() if v}


def extract_pdf_metadata(path: str) -> Dict[str, Any]:
    """Extracts PDF document metadata and page properties."""
    meta: Dict[str, Any] = {
        "document_info": {},
        "technical": {}
    }

    try:
        reader = PdfReader(path)
        meta["technical"]["pages"] = len(reader.pages)
        meta["technical"]["is_encrypted"] = reader.is_encrypted

        if reader.metadata:
            for k, v in reader.metadata.items():
                clean_key = k.lstrip("/")
                meta["document_info"][clean_key] = str(v)
    except Exception as e:
        meta["error"] = f"Failed to parse PDF: {str(e)}"

    return meta


def extract_audio_metadata(path: str) -> Dict[str, Any]:
    """Extracts audio metadata: tags, duration, bitrate, codec."""
    meta: Dict[str, Any] = {
        "tags": {},
        "technical": {}
    }

    try:
        audio = AudioFile(path)
        if audio:
            if hasattr(audio, "info") and audio.info:
                if hasattr(audio.info, "length"):
                    mins = int(audio.info.length // 60)
                    secs = int(audio.info.length % 60)
                    meta["technical"]["duration_seconds"] = round(audio.info.length, 2)
                    meta["technical"]["duration_formatted"] = f"{mins:02d}:{secs:02d}"
                if hasattr(audio.info, "bitrate"):
                    meta["technical"]["bitrate_kbps"] = round(audio.info.bitrate / 1000.0, 1)
                if hasattr(audio.info, "sample_rate"):
                    meta["technical"]["sample_rate_hz"] = audio.info.sample_rate
                if hasattr(audio.info, "channels"):
                    meta["technical"]["channels"] = audio.info.channels

            for key in audio.keys():
                meta["tags"][key] = str(audio[key])
    except Exception as e:
        meta["error"] = f"Failed to parse Audio: {str(e)}"

    return meta


def extract_metadata(path: str, raw: bool = False) -> Dict[str, Any]:
    """Primary API entry point: extracts hashes, metadata, and performs forensic analysis."""
    if not os.path.exists(path):
        return {"error": f"File '{path}' does not exist"}

    abs_path = os.path.abspath(path)
    file_type = detect_file_type(abs_path)
    file_size = os.path.getsize(abs_path)
    hashes = calculate_hashes(abs_path)

    result: Dict[str, Any] = {
        "file": abs_path,
        "filename": os.path.basename(abs_path),
        "file_type": file_type,
        "file_size_bytes": file_size,
        "file_size_formatted": format_bytes(file_size),
        "hashes": hashes,
        "sha256": hashes["sha256"],
        "hex_preview": get_hex_dump(abs_path, num_bytes=128),
        "metadata": {},
        "analysis": {},
    }

    if file_type == "image":
        img_meta = extract_image_metadata(abs_path, raw=raw)
        result["metadata"] = img_meta
        result["gps"] = img_meta.get("GPS", {"has_gps": False})
    elif file_type == "pdf":
        result["metadata"] = extract_pdf_metadata(abs_path)
    elif file_type == "audio":
        result["metadata"] = extract_audio_metadata(abs_path)
    else:
        result["metadata"] = {"note": "Generic binary file, cryptographic hashes and basic attributes computed"}

    result["analysis"] = analyze_forensics(result)

    return result

