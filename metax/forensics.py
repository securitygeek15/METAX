"""
MetaX Forensic Analysis Engine.
Analyzes extracted metadata for signatures of manipulation, generative AI,
timestamp inconsistencies, metadata stripping, and software tampering.
"""

from datetime import datetime
import json
import os
import re
from typing import Dict, Any, List, Optional, Tuple


EDITORS = {
    "Adobe Photoshop": ["photoshop", "adobe photoshop"],
    "Adobe Lightroom": ["lightroom", "adobe lightroom"],
    "GIMP": ["gimp", "gnu image manipulation"],
    "Affinity Photo": ["affinity photo", "serif affinity"],
    "Canva": ["canva"],
    "Snapseed": ["snapseed"],
    "Photopea": ["photopea"],
    "Paint.NET": ["paint.net"],
    "CorelDRAW / PaintShop": ["coreldraw", "paintshop"],
    "Apple Photos / Preview": ["apple photos", "macos preview", "quartz pdfcontext"],
    "Windows Photos": ["windows 11", "windows 10", "microsoft photo", "windows photo editor"],
    "Capture One": ["capture one", "phase one"],
}

AI_TOOLS = {
    "Topaz Gigapixel / Photo AI": ["topaz", "gigapixel", "topaz photo ai", "topaz denoise", "topaz sharpen"],
    "Stable Diffusion": ["stable diffusion", "automatic1111", "comfyui", "fooocus", "invokeai", "stablediffusion", "sd-metadata"],
    "Midjourney": ["midjourney"],
    "DALL-E / OpenAI": ["dall-e", "dalle", "openai"],
    "Adobe Firefly": ["firefly", "adobe firefly"],
    "Magnific AI": ["magnific"],
    "NovelAI": ["novelai"],
    "Flux": ["flux.1", "blackforestlabs"],
    "Upscaler / ESRGAN": ["esrgan", "realesrgan", "swinir", "gfpgan"],
}

CAMERA_MAKERS = [
    "canon", "nikon", "sony", "fujifilm", "apple", "samsung", "google",
    "panasonic", "leica", "olympus", "pentax", "hasselblad", "huawei",
    "xiaomi", "oneplus", "motorola", "gopro", "dji"
]

SOCIAL_MESSENGERS = {
    "WhatsApp": ["whatsapp"],
    "Telegram": ["telegram"],
    "Twitter / X": ["twitter", "x-tweet"],
    "Instagram": ["instagram"],
    "Facebook": ["facebook"],
    "Discord": ["discord"],
    "Reddit": ["reddit"],
}


def _parse_exif_date(date_str: str) -> Optional[datetime]:
    """Tries to parse standard EXIF date format 'YYYY:MM:DD HH:MM:SS', ISO, or PDF dates."""
    if not date_str or not isinstance(date_str, str):
        return None
    date_str = date_str.strip()

    # Handle PDF format D:YYYYMMDDHHmmSS...
    if date_str.startswith("D:"):
        raw_digits = re.sub(r"\D", "", date_str[2:])
        if len(raw_digits) >= 14:
            try:
                return datetime.strptime(raw_digits[:14], "%Y%m%d%H%M%S")
            except ValueError:
                pass
        elif len(raw_digits) >= 8:
            try:
                return datetime.strptime(raw_digits[:8], "%Y%m%d")
            except ValueError:
                pass

    cleaned = re.sub(r"[+-]\d{2}[:']\d{2}'?$", "", date_str)
    cleaned = cleaned.replace("Z", "")

    formats = [
        "%Y:%m:%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y:%m:%d %H:%M",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            pass

    return None


def analyze_timestamps(metadata: Dict[str, Any], file_path: Optional[str] = None) -> Dict[str, Any]:
    """Forensically cross-examines file timestamps."""
    ts_report: Dict[str, Any] = {
        "original_date": None,
        "digitized_date": None,
        "modify_date": None,
        "fs_created": None,
        "fs_modified": None,
        "anomalies": [],
        "timeline_consistent": True,
    }

    exif = metadata.get("EXIF", {})
    pil_exif = metadata.get("PIL_EXIF", {})
    doc_info = metadata.get("document_info", {})
    pdf_meta = metadata if metadata.get("/CreationDate") or metadata.get("/ModDate") else doc_info

    orig_str = (
        exif.get("EXIF DateTimeOriginal") or
        exif.get("Image DateTimeOriginal") or
        pil_exif.get("DateTimeOriginal") or
        pdf_meta.get("/CreationDate") or
        pdf_meta.get("CreationDate")
    )
    digi_str = (
        exif.get("EXIF DateTimeDigitized") or
        pil_exif.get("DateTimeDigitized")
    )
    mod_str = (
        exif.get("Image DateTime") or
        pil_exif.get("DateTime") or
        pdf_meta.get("/ModDate") or
        pdf_meta.get("ModDate")
    )

    orig_dt = _parse_exif_date(orig_str) if orig_str else None
    digi_dt = _parse_exif_date(digi_str) if digi_str else None
    mod_dt = _parse_exif_date(mod_str) if mod_str else None

    if orig_dt:
        ts_report["original_date"] = orig_dt.isoformat()
    if digi_dt:
        ts_report["digitized_date"] = digi_dt.isoformat()
    if mod_dt:
        ts_report["modify_date"] = mod_dt.isoformat()

    fs_mtime_dt = None
    if file_path and os.path.exists(file_path):
        try:
            stat = os.stat(file_path)
            fs_mtime_dt = datetime.fromtimestamp(stat.st_mtime)
            ts_report["fs_modified"] = fs_mtime_dt.isoformat()
            ts_report["fs_created"] = datetime.fromtimestamp(stat.st_ctime).isoformat()
        except Exception:
            pass

    now = datetime.now()

    if orig_dt and orig_dt > now:
        ts_report["anomalies"].append("Future capture timestamp detected (clock drift or synthetic)")
        ts_report["timeline_consistent"] = False

    if orig_dt and mod_dt:
        diff_seconds = (mod_dt - orig_dt).total_seconds()
        if diff_seconds > 60:
            ts_report["anomalies"].append(
                f"File modified {int(diff_seconds // 60)} minutes after capture (post-processing trace)"
            )
        elif diff_seconds < -60:
            ts_report["anomalies"].append("Modification date precedes original creation date (timestamp tampering)")
            ts_report["timeline_consistent"] = False

    if orig_dt and fs_mtime_dt:
        if (orig_dt - fs_mtime_dt).total_seconds() > 86400:
            ts_report["anomalies"].append("Filesystem timestamp significantly precedes EXIF original timestamp")
            ts_report["timeline_consistent"] = False

    return ts_report


def analyze_forensics(extracted_data: Dict[str, Any]) -> Dict[str, Any]:
    """Master forensic analyzer."""
    file_type = extracted_data.get("file_type", "unknown")
    metadata = extracted_data.get("metadata", {})
    file_path = extracted_data.get("file")

    result: Dict[str, Any] = {
        "verdict": "UNVERIFIED",
        "verdict_badge": "UNVERIFIED",
        "integrity_score": 100,
        "is_edited": False,
        "is_ai_generated": False,
        "is_stripped": False,
        "confidence": "Low",
        "detected_software": [],
        "detected_ai_tools": [],
        "indicators": [],
        "timestamp_analysis": {},
    }

    flat_text = json.dumps(metadata, default=str).lower()

    for tool_name, signatures in EDITORS.items():
        if any(sig in flat_text for sig in signatures):
            result["is_edited"] = True
            result["detected_software"].append(tool_name)
            result["indicators"].append(f"Editor signature detected: {tool_name}")

    for ai_name, signatures in AI_TOOLS.items():
        if any(sig in flat_text for sig in signatures):
            result["is_ai_generated"] = True
            result["detected_ai_tools"].append(ai_name)
            result["indicators"].append(f"AI tool marker detected: {ai_name}")

    ai_prompt_keywords = ["parameters:", "prompt:", "negative_prompt:", "steps:", "sampler:", "cfg scale:", "denoising strength:"]
    if any(kw in flat_text for kw in ai_prompt_keywords):
        result["is_ai_generated"] = True
        result["indicators"].append("Generative AI diffusion prompt/parameters block detected")

    for messenger, sigs in SOCIAL_MESSENGERS.items():
        if any(sig in flat_text for sig in sigs) or (file_path and any(sig in os.path.basename(file_path).lower() for sig in sigs)):
            result["indicators"].append(f"Social media / messenger signature detected: {messenger}")

    camera_detected = any(maker in flat_text for maker in CAMERA_MAKERS)
    has_exif = bool(metadata.get("EXIF") or metadata.get("PIL_EXIF"))
    has_xmp = bool(metadata.get("XMP"))

    ts_analysis = analyze_timestamps(metadata, file_path)
    result["timestamp_analysis"] = ts_analysis
    for anomaly in ts_analysis["anomalies"]:
        result["indicators"].append(anomaly)

    if file_type == "image":
        if not has_exif and not has_xmp:
            result["is_stripped"] = True
            result["indicators"].append("Complete EXIF/XMP metadata absence (stripped by platform, screenshot, or privacy tool)")
        elif not has_exif and has_xmp:
            result["is_stripped"] = True
            result["indicators"].append("Partial stripping: EXIF removed but XMP block preserved")
        elif has_exif and not camera_detected and not result["is_edited"]:
            result["indicators"].append("Synthetic EXIF without recognized camera hardware manufacturer")

    score = 100
    if result["is_ai_generated"]:
        score -= 70
    elif result["is_edited"]:
        score -= 40

    if result["is_stripped"]:
        score -= 30

    if ts_analysis["anomalies"]:
        score -= (15 * len(ts_analysis["anomalies"]))

    if not camera_detected and file_type == "image":
        score -= 10

    score = max(0, min(100, score))
    result["integrity_score"] = score

    if result["is_ai_generated"]:
        result["verdict"] = "AI GENERATED / ENHANCED"
        result["verdict_badge"] = "AI DETECTED"
        result["confidence"] = "High"
    elif result["is_edited"]:
        result["verdict"] = "DIGITALLY ALTERED / EDITED"
        result["verdict_badge"] = "EDITED"
        result["confidence"] = "High"
    elif result["is_stripped"]:
        result["verdict"] = "METADATA STRIPPED / LAUNDERED"
        result["verdict_badge"] = "STRIPPED"
        result["confidence"] = "Medium"
    elif camera_detected and has_exif and ts_analysis["timeline_consistent"]:
        result["verdict"] = "AUTHENTIC CAMERA ORIGINAL"
        result["verdict_badge"] = "AUTHENTIC"
        result["confidence"] = "High"
    elif file_type == "pdf":
        result["verdict"] = "PDF DOCUMENT ARTIFACT"
        result["verdict_badge"] = "DOCUMENT"
        result["confidence"] = "Medium"
    elif file_type == "audio":
        result["verdict"] = "AUDIO MEDIA ARTIFACT"
        result["verdict_badge"] = "AUDIO"
        result["confidence"] = "Medium"
    else:
        result["verdict"] = "STANDARD ARTIFACT / LOW TAMPERING"
        result["verdict_badge"] = "INTACT"
        result["confidence"] = "Medium"

    return result

