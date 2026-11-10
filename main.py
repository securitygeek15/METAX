"""
MetaX — Advanced Metadata Extraction & Forensic Analysis Tool.
Run via CLI, launch the minimalist web interface, or run the desktop GUI.
"""

import argparse
import json
import os
import sys
from typing import Dict, Any

from metax.core import extract_metadata, detect_file_type
from metax.sanitizer import strip_image_metadata
from metax.web_server import start_server
from metax.desktop_gui import start_gui


def print_monochrome_report(data: Dict[str, Any]):
    """Renders a surgical, minimalist monochrome forensic report in the terminal."""
    analysis = data.get("analysis", {})
    hashes = data.get("hashes", {})
    gps = data.get("gps", {})
    filename = data.get("filename", os.path.basename(data.get("file", "unknown")))
    file_type = (data.get("file_type") or "unknown").upper()
    size_str = data.get("file_size_formatted", f"{data.get('file_size_bytes', 0)} B")

    print("\n" + "═" * 68)
    print(f"  🧠 META // X  —  FORENSIC ARTIFACT ANALYSIS")
    print("═" * 68)

    # 1. Artifact Identity
    print(f"  FILE        : {filename}")
    print(f"  TYPE        : {file_type}")
    print(f"  SIZE        : {size_str}")
    print(f"  PATH        : {data.get('file')}")
    print("─" * 68)

    # 2. Cryptographic Triad
    print(f"  SHA-256     : {hashes.get('sha256', data.get('sha256'))}")
    print(f"  SHA-1       : {hashes.get('sha1', 'N/A')}")
    print(f"  MD5         : {hashes.get('md5', 'N/A')}")
    print("─" * 68)

    # 3. Forensic Verdict & Scoring
    verdict = analysis.get("verdict", "UNVERIFIED")
    badge = analysis.get("verdict_badge", "INFO")
    score = analysis.get("integrity_score", 100)
    conf = analysis.get("confidence", "Medium")

    print(f"  VERDICT     : [{badge}] {verdict}")
    print(f"  INTEGRITY   : {score} / 100  (Confidence: {conf})")

    if analysis.get("detected_software"):
        print(f"  EDITORS     : {', '.join(analysis['detected_software'])}")
    if analysis.get("detected_ai_tools"):
        print(f"  AI TOOLS    : {', '.join(analysis['detected_ai_tools'])}")

    indicators = analysis.get("indicators", [])
    if indicators:
        print("  INDICATORS  :")
        for ind in indicators:
            print(f"    • {ind}")
    else:
        print("  INDICATORS  : No manipulation or tampering signatures found")

    # 4. GPS Geolocation
    if gps and gps.get("has_gps"):
        print("─" * 68)
        print("  GEOLOCATION : GPS COORDINATES DETECTED")
        print(f"    Decimal   : {gps.get('formatted_coordinates')}")
        print(f"    DMS       : {gps.get('latitude_dms')} {gps.get('longitude_dms')}")
        if gps.get("altitude_meters") is not None:
            print(f"    Altitude  : {gps.get('altitude_meters')} meters")
        print(f"    OSM Map   : {gps.get('osm_url')}")
        print(f"    Google Map: {gps.get('maps_url')}")

    # 5. Temporal Timeline
    ts = analysis.get("timestamp_analysis", {})
    if ts and any(ts.get(k) for k in ["original_date", "modify_date", "fs_modified"]):
        print("─" * 68)
        print("  TIMELINE    :")
        if ts.get("original_date"):
            print(f"    Original  : {ts['original_date']}")
        if ts.get("modify_date"):
            print(f"    Modified  : {ts['modify_date']}")
        if ts.get("fs_modified"):
            print(f"    Filesystem: {ts['fs_modified']}")
        if ts.get("anomalies"):
            print("    Anomalies :")
            for a in ts["anomalies"]:
                print(f"      [!] {a}")

    # 6. Metadata Summary Count
    meta = data.get("metadata", {})
    sub_counts = []
    for k, v in meta.items():
        if isinstance(v, dict):
            sub_counts.append(f"{k} ({len(v)})")
    if sub_counts:
        print("─" * 68)
        print(f"  REGISTRIES  : {', '.join(sub_counts)}")

    print("═" * 68 + "\n")


def scan_directory(dir_path: str, output_json: bool = False):
    """Scans all supported files in a folder and prints a forensic summary matrix."""
    if not os.path.isdir(dir_path):
        print(f"❌ Error: '{dir_path}' is not a directory.")
        return

    supported_exts = {".jpg", ".jpeg", ".png", ".webp", ".pdf", ".mp3", ".wav", ".flac", ".mp4", ".mov"}
    files = [
        os.path.join(dir_path, f) for f in os.listdir(dir_path)
        if os.path.splitext(f)[1].lower() in supported_exts
    ]

    if not files:
        print(f"[!] No supported media/document files found in '{dir_path}'.")
        return

    print(f"\n📂 Batch Scanning Directory: {dir_path} ({len(files)} target files)")
    print("═" * 78)
    print(f"{'FILENAME':<24} {'TYPE':<8} {'INTEGRITY':<11} {'VERDICT':<25} {'GPS'}")
    print("─" * 78)

    all_results = []
    for f in sorted(files):
        data = extract_metadata(f)
        all_results.append(data)
        fname = os.path.basename(f)
        if len(fname) > 22:
            fname = fname[:19] + "..."
        ftype = data.get("file_type", "unknown")
        an = data.get("analysis", {})
        score = f"{an.get('integrity_score', 100)}/100"
        badge = an.get("verdict_badge", "INFO")
        has_gps = "YES" if data.get("gps", {}).get("has_gps") else "-"
        print(f"{fname:<24} {ftype:<8} {score:<11} {badge:<25} {has_gps}")

    print("═" * 78 + "\n")


def resolve_target_file(target: str) -> str:
    """Intelligently resolves target file across cwd, project subdirs, and prefix matching."""
    if not target or os.path.exists(target):
        return target

    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, target),
        os.path.join(script_dir, "METAX", target),
        os.path.join(os.path.dirname(script_dir), target),
        os.path.join(os.path.dirname(script_dir), "METAX", target),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c

    # Prefix match if truncated (e.g. 'test.' or 'test')
    search_dirs = [os.getcwd(), script_dir, os.path.join(script_dir, "METAX"), os.path.dirname(script_dir)]
    matches = []
    clean_prefix = os.path.basename(target).rstrip(".")
    for d in search_dirs:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.lower().startswith(clean_prefix.lower()) and not f.startswith("."):
                    p = os.path.join(d, f)
                    if os.path.isfile(p) and p not in matches:
                        matches.append(p)

    if len(matches) == 1:
        print(f"[*] Auto-resolved '{target}' -> {matches[0]}")
        return matches[0]
    elif len(matches) > 1:
        unique_names = list(dict.fromkeys(os.path.basename(m) for m in matches))
        print(f"❌ File '{target}' does not exist. Matching sample files found:")
        for name in unique_names:
            print(f"   • {name}")
        sys.exit(1)

    return target


def main():
    parser = argparse.ArgumentParser(
        description="MetaX — Advanced Metadata & Forensic Analysis Tool"
    )

    parser.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Target file or directory path (leave empty to open Web UI)"
    )
    parser.add_argument("--json", action="store_true", help="Output full report as formatted JSON")
    parser.add_argument("--raw", action="store_true", help="Preserve raw binary and un-truncated values")
    parser.add_argument("--out", help="Save output report to file")
    parser.add_argument("--strip", nargs="?", const="AUTO", help="Strip all EXIF/GPS metadata from target image")
    parser.add_argument("--ui", "--web", action="store_true", help="Launch the Minimalist Monochrome Web UI")
    parser.add_argument("--gui", action="store_true", help="Launch the Desktop GUI window")
    parser.add_argument("--batch", help="Batch scan a folder of artifacts")
    parser.add_argument("--port", type=int, default=None, help="Port for local web server (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch browser on --ui")

    args = parser.parse_args()

    # 1. Desktop GUI flag
    if args.gui:
        start_gui()
        return

    # 2. Web UI flag (or no arguments specified at all)
    if args.ui or (args.file is None and not args.batch):
        start_server(port=args.port, open_browser=not args.no_browser)
        return

    # 3. Batch folder scan
    if args.batch:
        scan_directory(args.batch, output_json=args.json)
        return

    # 4. Target file check
    target_path = resolve_target_file(args.file)
    if not os.path.exists(target_path):
        print(f"❌ Error: File '{target_path}' does not exist.")
        sys.exit(1)

    if os.path.isdir(target_path):
        scan_directory(target_path, output_json=args.json)
        return

    # 5. Metadata Stripping feature
    if args.strip:
        out_name = args.strip
        if out_name == "AUTO":
            dirname, fname = os.path.split(target_path)
            out_name = os.path.join(dirname, f"clean_{fname}")

        res = strip_image_metadata(target_path, out_name)
        if res.get("success"):
            print(f"✅ Metadata Stripped Successfully:")
            print(f"   Original : {target_path} ({res['original_size_bytes']} bytes)")
            print(f"   Cleaned  : {out_name} ({res['new_size_bytes']} bytes)")
            print(f"   Removed  : {', '.join(res['stripped'])}")
        else:
            print(f"❌ Sanitization Failed: {res.get('error')}")
        return

    # 6. Extract & Analyze Metadata
    data = extract_metadata(target_path, raw=args.raw)

    if args.json:
        output_str = json.dumps(data, indent=2, default=str)
        print(output_str)
    else:
        print_monochrome_report(data)
        output_str = json.dumps(data, indent=2, default=str)

    # 7. Save output if requested
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            if args.out.endswith(".json"):
                json.dump(data, f, indent=2, default=str)
            else:
                f.write(output_str)
        print(f"✅ Report saved to: {args.out}")


if __name__ == "__main__":
    main()
