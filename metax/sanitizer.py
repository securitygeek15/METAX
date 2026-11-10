"""
MetaX Privacy Sanitizer.
Strips EXIF, GPS, XMP, author metadata, and device identifiers from images.
"""

import io
import os
from typing import Dict, Any, Tuple
from PIL import Image


def strip_image_metadata(input_path: str, output_path: str) -> Dict[str, Any]:
    """Reads an image, recreates pixel data without any metadata, and saves to output_path."""
    if not os.path.exists(input_path):
        return {"success": False, "error": "Input file does not exist"}

    original_size = os.path.getsize(input_path)

    try:
        with Image.open(input_path) as img:
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(list(img.getdata()))

            fmt = img.format if img.format else "JPEG"
            if fmt.upper() in ["JPG", "JPEG"]:
                clean_img.save(output_path, "JPEG", quality=95, optimize=True)
            elif fmt.upper() == "PNG":
                clean_img.save(output_path, "PNG", optimize=True)
            elif fmt.upper() == "WEBP":
                clean_img.save(output_path, "WEBP", quality=95)
            else:
                clean_img.save(output_path)

        new_size = os.path.getsize(output_path)
        return {
            "success": True,
            "original_path": input_path,
            "output_path": output_path,
            "original_size_bytes": original_size,
            "new_size_bytes": new_size,
            "bytes_saved": original_size - new_size,
            "stripped": ["EXIF", "GPS Coordinates", "Camera Model", "Timestamps", "XMP", "IPTC", "Thumbnail"]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def strip_image_bytes(input_bytes: bytes, filename: str = "cleaned.jpg") -> Tuple[bytes, Dict[str, Any]]:
    """Strips metadata from in-memory image bytes and returns cleaned bytes."""
    try:
        in_stream = io.BytesIO(input_bytes)
        with Image.open(in_stream) as img:
            fmt = img.format if img.format else "JPEG"
            data = list(img.getdata())
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(data)

            out_stream = io.BytesIO()
            if fmt.upper() in ["JPG", "JPEG"]:
                clean_img.save(out_stream, "JPEG", quality=95, optimize=True)
            elif fmt.upper() == "PNG":
                clean_img.save(out_stream, "PNG", optimize=True)
            elif fmt.upper() == "WEBP":
                clean_img.save(out_stream, "WEBP", quality=95)
            else:
                clean_img.save(out_stream, fmt)

            out_bytes = out_stream.getvalue()
            return out_bytes, {
                "success": True,
                "original_bytes": len(input_bytes),
                "clean_bytes": len(out_bytes),
                "stripped": ["EXIF", "GPS", "Device ID", "XMP", "Timestamps"]
            }
    except Exception as e:
        return input_bytes, {"success": False, "error": str(e)}

