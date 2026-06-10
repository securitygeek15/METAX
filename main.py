import argparse
import exifread
from PyPDF2 import PdfReader
from mutagen import File as AudioFile
import hashlib
import os
import json
from PIL import Image
from PIL.ExifTags import TAGS
import xml.etree.ElementTree as ET


def get_sha256(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def detect_file_type(path):
    ext = os.path.splitext(path)[1].lower()

    if ext in [".jpg", ".jpeg", ".png", ".webp", ".tiff"]:
        return "image"
    elif ext == ".pdf":
        return "pdf"
    elif ext in [".mp3", ".wav", ".flac", ".ogg", ".m4a"]:
        return "audio"
    else:
        return "unknown"




def parse_xmp(xmp_bytes):
    try:
        xmp_str = xmp_bytes.decode("utf-8", errors="ignore")

        start = xmp_str.find("<x:xmpmeta")
        end = xmp_str.find("</x:xmpmeta>")
        if start == -1 or end == -1:
            return {}

        xmp_xml = xmp_str[start:end + len("</x:xmpmeta>")]

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
        return {"error": "Failed to parse XMP metadata"}






def analyze_image_metadata(metadata):
    analysis = {
        "Edited" : False , 
        "ai_related" : False, 
        "Software_Detected": [], 
        "Metadata_Stripped": False, 
        "Confidence": "low"
    }

    flat_text = json.dumps(metadata).lower()

    EDITORS = ["photoshop", "lightroom" , "gimp" , "topaz" , "gigapixel" , "stable diffusion" , "midjourney", "dall'e" , "firefly"]

    for tool in EDITORS:
        if tool in flat_text:
            analysis["Edited"] = True
            analysis["Software_Detected"].append(tool)

    
    AI_HINTS = ["topaz" , "gigapixel", "ai", "diffusion"]
    if any(ai in flat_text for ai in AI_HINTS):
        analysis["ai_related"] = True 

    
    if "exif" not in metadata and "xmp" in metadata:
        analysis["Metadata_Stripped"] = True
    
    if analysis["Edited"] or analysis["ai_related"]:
        analysis["Confidence"] = "high"
    
    return analysis


def clean_binary_info(key, value):
    if isinstance(value, (bytes, bytearray)):
        return {
            "type": "binary",
            "size_bytes": len(value),
            "note": "Use --raw to view full binary data"
        }

    text = str(value)

    if "\\x00" in text or len(text) > 300:
        return {
            "type": "binary_text",
            "length": len(text),
            "preview": text[:80] + "...",
            "note": "Truncated for readability"
        }

    return text



def extract_image_metadata(path):
    metadata = {
        "EXIF": {},
        "PIL_EXIF": {},
        "XMP": {},
        "INFO": {}
    }

   
    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=True)

        for tag, value in tags.items():
            metadata["EXIF"][tag] = str(value)
    except Exception:
        pass


    try:
        img = Image.open(path)

       
        exif = img.getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                metadata["PIL_EXIF"][str(tag)] = str(value)

        
        for key, value in img.info.items():
            if key.lower() == "xmp":
                metadata["XMP"] = parse_xmp(value)
            else:
                metadata["INFO"][key] = clean_binary_info(key, value)


    except Exception:
        pass

    
    metadata = {k: v for k, v in metadata.items() if v}

    if not metadata:
        return {
            "info": "No metadata found",
            "reason": "Image likely stripped, screenshot, or optimized"
        }

    return metadata


def extract_pdf_metadata(path):
    metadata = {}
    reader = PdfReader(path)

    if reader.metadata:
        for key, value in reader.metadata.items():
            metadata[key] = str(value)

    return metadata


def extract_audio_metadata(path):
    metadata = {}
    audio = AudioFile(path)

    if audio:
        for key in audio.keys():
            metadata[key] = str(audio[key])

    return metadata


def extract_metadata(path):
    result = {}

    file_type = detect_file_type(path)

    result["file"] = os.path.abspath(path)
    result["file_type"] = file_type
    result["file_size_bytes"] = os.path.getsize(path)
    result["sha256"] = get_sha256(path)

    if file_type == "image":
        image_meta = extract_image_metadata(path)
        result["metadata"] = image_meta
        result["analysis"] = analyze_image_metadata(image_meta)


    elif file_type == "pdf":
        result["metadata"] = extract_pdf_metadata(path)

    elif file_type == "audio":
        result["metadata"] = extract_audio_metadata(path)

    else:
        result["metadata"] = {"error": "Unsupported file type"}

    return result



def main():
    parser = argparse.ArgumentParser(
        description="MetaX — Advanced Metadata & Forensics Tool"
    )

    parser.add_argument("file", help="Target file path")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--out", help="Save output to file")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("❌ File does not exist")
        return

    data = extract_metadata(args.file)

    if args.json:
        output = json.dumps(data, indent=4)
    else:
        output = ""
        for key, value in data.items():
            output += f"{key}:\n{value}\n\n"

    print(output)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"✅ Output saved to {args.out}")


if __name__ == "__main__":
    main()
