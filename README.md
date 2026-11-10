# 🧠 MetaX — Advanced Metadata & Forensic Intelligence Suite

<div align="center">

```
███╗   ███╗███████╗████████╗ █████╗ ██╗  ██╗
████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚██╗██╔╝
██╔████╔██║█████╗     ██║   ███████║ ╚███╔╝ 
██║╚██╔╝██║██╔══╝     ██║   ██╔══██║ ██╔██╗ 
██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██╔╝ ██╗
╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Surgical Digital Forensics & Metadata Analysis in Pure Monochrome.**

[![Python](https://img.shields.io/badge/Python-3.9%2B-000000?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![UI](https://img.shields.io/badge/UI-Minimalist%20Monochrome-111111?style=for-the-badge)](https://github.com/securitygeek15/METAX)
[![License](https://img.shields.io/badge/License-MIT-333333?style=for-the-badge)](LICENSE)

</div>

---

## ⚡ Overview

**MetaX** is an advanced metadata extraction and forensic analysis engine engineered to understand **what metadata actually signifies**, not merely dump raw bytes.

Unlike traditional tools that simply print key-value pairs, MetaX applies a **forensic heuristic layer** to detect digital tampering, generative AI generation, software editing footprints, metadata stripping/laundering, and temporal timeline inconsistencies.

Now equipped with a **minimalist aesthetic monochrome web UI**, a **native desktop GUI**, and an **upgraded surgical terminal CLI**.

---

## ✨ Key Capabilities

### 🎨 Minimalist Aesthetic Monochrome UI
- **Obsidian & Stark White**: High-contrast, surgical interface inspired by Dieter Rams and minimalist typography.
- **Interactive Drag & Drop**: Drop evidence files (JPG, PNG, WEBP, PDF, MP3, WAV, MP4, MOV).
- **Forensic Assessment Header**: Live integrity index (0–100), verdict badges, and detected manipulation indicators.
- **Embedded Monochrome Geolocation Map**: Real-time rendering of GPS pins with decimal degrees, DMS, and map links.
- **Temporal Timeline**: Chronological comparison of capture date, digitized date, modification date, and filesystem writes.
- **Searchable Metadata Explorer**: Filter hundreds of EXIF, XMP, and container tags with instant sub-millisecond search.
- **Privacy Sanitizer**: 1-click strip of all EXIF, GPS, and personal device identifiers to protect user privacy.
- **Dual Interface**: Run as a modern browser web application or as a native desktop window.

### 🧠 Forensic Tamper Intelligence
- **Generative AI Detection**: Identifies markers for Midjourney, Stable Diffusion, DALL-E, Adobe Firefly, Topaz Gigapixel, Flux, and AI diffusion prompts/parameters.
- **Photo Editor Detection**: Identifies traces of Photoshop, Lightroom, GIMP, Affinity, Canva, Snapseed, Photopea, Paint.NET, and OS editors.
- **Timestamp Mismatch Forensics**: Detects post-processing delays, timeline inconsistencies, and future-dated synthetic timestamps.
- **Metadata Laundering & Stripping Analysis**: Detects social media re-compression (WhatsApp, Telegram, X/Twitter, Instagram) and missing sensor data.
- **Forensic Integrity Index (0–100)**: Quantitative scoring of file trustworthiness.

### 🔍 Deep Extraction & Normalization
- **Images**: EXIF, Pillow IFDs, XMP XML parsing, ICC profile summaries, dimensions, and aspect ratio.
- **GPS Extraction**: Normalized Decimal Coordinates (`28.646610° N, 77.159943° E`), DMS, Altitude, and direct OpenStreetMap / Google Maps URLs.
- **PDF Documents**: Author, Title, Subject, Creation Date, Mod Date, Page Count, and encryption status.
- **Audio & Media**: ID3, Vorbis, FLAC tags, duration, bitrate, sample rate, channels, and encoder signatures (`Lavf`, etc.).
- **Cryptographic Hashes**: SHA-256, SHA-1, and MD5 computed simultaneously.
- **Noise Elimination**: Large binary blobs and thousands of null bytes are cleanly summarized instead of cluttering output.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/securitygeek15/METAX.git
cd METAX

# Using uv (recommended - instant setup)
uv run python main.py --ui

# Or using standard pip & venv
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install exifread pillow PyPDF2 mutagen
```

---

## 🖥️ Usage

### 1. Launch Minimalist Monochrome Web UI
```bash
# Launches the local web server and automatically opens your browser:
python main.py --ui

# Or use the direct launcher:
python app.py
```
> Access at: `http://127.0.0.1:8765`

### 2. Launch Native Desktop GUI
```bash
# Opens the native desktop GUI window:
python main.py --gui

# Or use the direct launcher:
python gui.py
```

### 3. Surgical Monochrome CLI Analysis
```bash
# Analyze an artifact in the terminal
python main.py test.jpg

# Output clean structured JSON
python main.py test.jpg --json

# Save report to file (JSON or Markdown)
python main.py test.jpg --out report.json
```

### 4. Privacy Sanitizer (Strip Metadata)
```bash
# Strip all EXIF, GPS, and tracking metadata from an image:
python main.py test.jpg --strip

# Or specify a custom clean output path:
python main.py test.jpg --strip sanitized_photo.jpg
```

### 5. Batch Folder Scanning
```bash
# Scan an entire directory of files and generate a forensic matrix:
python main.py --batch ./evidence_folder/
```

---

## 📊 Sample Terminal Output

```
════════════════════════════════════════════════════════════════════
  🧠 META // X  —  FORENSIC ARTIFACT ANALYSIS
════════════════════════════════════════════════════════════════════
  FILE        : test.jpg
  TYPE        : IMAGE
  SIZE        : 204.8 KB
  PATH        : /evidence/test.jpg
────────────────────────────────────────────────────────────────────
  SHA-256     : 0250bc91b8012c3eea991f80c372ed853747c0e3954eb1e50c966ffd2895bfd4
  SHA-1       : ac8ae5f3b662d1ca30f4251d75a068fe54a55ae8
  MD5         : aae6348df69d87b437e3ad233c7d608c
────────────────────────────────────────────────────────────────────
  VERDICT     : [EDITED] DIGITALLY ALTERED / EDITED
  INTEGRITY   : 60 / 100  (Confidence: High)
  EDITORS     : Windows Photos
  INDICATORS  :
    • Editor signature detected: Windows Photos
────────────────────────────────────────────────────────────────────
  GEOLOCATION : GPS COORDINATES DETECTED
    Decimal   : 28.646610, 77.159943
    DMS       : 28° 38' 47.80" N 77° 9' 35.79" E
    OSM Map   : https://www.openstreetmap.org/?mlat=28.64661&mlon=77.159943#map=16/28.64661/77.159943
    Google Map: https://www.google.com/maps?q=28.64661,77.159943
────────────────────────────────────────────────────────────────────
  TIMELINE    :
    Original  : 2025-09-07T12:55:01
    Filesystem: 2025-09-07T12:55:04.326196
────────────────────────────────────────────────────────────────────
  REGISTRIES  : technical (6), EXIF (12), PIL_EXIF (4), INFO (6), GPS (10)
════════════════════════════════════════════════════════════════════
```

---

## 📂 Project Structure

```
METAX/
├── metax/
│   ├── __init__.py           # Package exports & versioning
│   ├── core.py               # Extraction engine (Image, Audio, PDF, Video, Generic)
│   ├── forensics.py          # Tamper, AI detection, Anomaly & Integrity scoring
│   ├── gps.py                # GPS DMS -> Decimal conversion & mapping URLs
│   ├── sanitizer.py          # Privacy metadata stripper
│   ├── web_server.py         # Standard-library threaded HTTP/REST server
│   ├── web/
│   │   ├── index.html        # Minimalist monochrome web UI
│   │   ├── style.css         # Dark monochrome design system
│   │   └── app.js            # Interactive client, map rendering, export & search
│   └── desktop_gui.py        # Native Tkinter desktop GUI
├── main.py                   # Master CLI & runner
├── app.py                    # Direct web UI launcher
├── gui.py                    # Direct desktop GUI launcher
├── pyproject.toml            # Project configuration & dependencies
└── README.md                 # Documentation
```

---

## 📜 License

MIT License — free for research, academic, personal, and commercial forensics workflows.

Created by **Security Geek** & Enhanced with **MetaX Forensic Intelligence**.
