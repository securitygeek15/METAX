# MetaX

> Advanced Digital Artifact & Metadata Forensic Analysis Engine

[![Python](https://img.shields.io/badge/Python-3.9%2B-000000?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Interface](https://img.shields.io/badge/Interface-Web%20%7C%20GUI%20%7C%20CLI-000000?style=flat-square)](https://github.com/securitygeek15/METAX)
[![License](https://img.shields.io/badge/License-MIT-000000?style=flat-square)](LICENSE)

---

## Executive Summary

**MetaX** is a digital forensic analysis and metadata interpretation engine designed to extract, normalize, and evaluate embedded file telemetry.

Traditional metadata dumping utilities present raw tag registries without context. MetaX introduces a heuristic forensic interpretation layer that detects file tampering, generative artificial intelligence signatures, image editor traces, metadata laundering, and chronological anomalies.

The system features three distinct operational interfaces:
- **Monochrome Web Workspace**: An interactive, zero-telemetry local web application.
- **Desktop GUI**: A native desktop application built with a high-contrast dark theme.
- **Terminal CLI**: A high-speed command-line interface engineered for automated pipelines and script integration.

---

## Technical Capabilities

### Forensic Tamper Intelligence
- **Generative AI Detection**: Identifies markers and parameter blocks associated with Midjourney, Stable Diffusion (Automatic1111, ComfyUI, Fooocus), DALL-E, Adobe Firefly, Topaz Gigapixel, Flux, and AI diffusion prompt blocks.
- **Image Editor Identification**: Detects signatures left by manipulation software, including Adobe Photoshop, Adobe Lightroom, GIMP, Affinity Photo, Canva, Snapseed, Photopea, and Paint.NET.
- **Temporal Inconsistency Detection**: Cross-examines original hardware capture timestamps, digitization dates, modification dates, and filesystem records to detect post-processing delays and clock anomalies.
- **Metadata Laundering & Stripping Analysis**: Evaluates whether file structures exhibit indicators of platform re-compression (e.g., messaging platforms and social networks) or intentional metadata sanitization.
- **Integrity Index**: Generates a standardized confidence score (0 to 100) quantifying artifact authenticity.

### Extraction and Normalization
- **Image Telemetry**: Standardized EXIF tags, Pillow IFD structures, parsed XMP XML blocks, and ICC profile summaries across JPEG, PNG, WEBP, and TIFF containers.
- **Geolocation Resolution**: Parses and computes exact decimal coordinates (`Latitude`, `Longitude`), standard Degrees-Minutes-Seconds (DMS) notation, altitude measurements, and direct OpenStreetMap and Google Maps references.
- **Document Forensics**: Extracts structural metadata from PDF files, including author identity, software producer, creation dates, modification dates, page counts, and encryption flags.
- **Audio Telemetry**: Decodes container parameters from MP3, WAV, FLAC, and OGG formats, including ID3 tags, bitrates, sample rates, channel configurations, and encoder signatures (`Lavf`, etc.).
- **Cryptographic Triad**: Computes SHA-256, SHA-1, and MD5 cryptographic digests concurrently.
- **Binary Noise Cleansing**: Filters excessive null-padded buffers and binary streams to maintain report legibility while preserving full data integrity in raw mode.

### Privacy Sanitization
- Reconstructs raw pixel data into fresh containers without embedded EXIF, GPS, XMP, device serials, or software identifiers, generating clean files for safe distribution.

---

## Interfaces

### 1. Minimalist Monochrome Web Interface
- High-contrast obsidian design system with an architectural grid backdrop.
- Interactive drag-and-drop workspace supporting multiple file formats.
- Real-time embedded OpenStreetMap monochrome locator.
- Instant search and filtering across hundreds of extracted tags.
- Direct report export in structured JSON and Markdown formats.
- Single-click privacy sanitization and file download.

### 2. Native Desktop GUI
- Cross-platform native window interface styled with a bespoke dark theme.
- Integrated file browser and quick-loading sample artifacts.
- Filterable treeview registry for detailed tag inspection.
- Tabbed panels for Forensic Overview, Geolocation, Temporal Analysis, and Raw JSON.

### 3. Terminal Interface
- Structured monochrome console reporting with box-drawing formatting.
- Batch scanning capability with summary matrix generation.
- Machine-readable JSON output mode.

---

## Installation

### Prerequisites
- Python 3.9 or higher

### Setup

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/securitygeek15/METAX.git
cd METAX

# Using uv (recommended for isolated, rapid setup)
uv run python main.py --ui

# Or using standard python virtual environment
python -m venv .venv

# Activate on Windows:
.venv\Scripts\activate

# Activate on Linux / macOS:
# source .venv/bin/activate

pip install exifread pillow PyPDF2 mutagen
```

### Docker Deployment

Build and start the container with Docker Compose:

```bash
docker compose up -d
```
The monochrome web workspace will be available at `http://localhost:8765`.

Alternatively, build and run via Docker CLI:

```bash
# Build the image
docker build -t metax .

# Run the web studio
docker run -d -p 8765:8765 --name metax-forensics metax

# Run ad-hoc CLI analysis inside a container
docker run --rm -v "$(pwd):/app/evidence" metax evidence/test.jpg
```

---

## Operational Guide

### Web Workspace
Launch the local web server and open the browser interface automatically:

```bash
python app.py
# Or:
python main.py --ui
```
Default local address: `http://127.0.0.1:8765`

### Desktop Application
Launch the standalone native window:

```bash
python gui.py
# Or:
python main.py --gui
```

### Command-Line Execution

Analyze an individual artifact:
```bash
python main.py test.jpg
```

Generate structured JSON output:
```bash
python main.py test.jpg --json
```

Export forensic report to disk:
```bash
python main.py test.jpg --out forensic_report.json
```

Strip all metadata and GPS tracking from an image:
```bash
python main.py test.jpg --strip
# Or specify destination filename:
python main.py test.jpg --strip clean_artifact.jpg
```

Batch scan an entire directory:
```bash
python main.py --batch ./evidence_directory/
```

---

## Terminal Report Sample

```text
====================================================================
  META // X  --  FORENSIC ARTIFACT ANALYSIS
====================================================================
  FILE        : test.jpg
  TYPE        : IMAGE
  SIZE        : 204.8 KB
  PATH        : C:\evidence\test.jpg
--------------------------------------------------------------------
  SHA-256     : 0250bc91b8012c3eea991f80c372ed853747c0e3954eb1e50c966ffd2895bfd4
  SHA-1       : ac8ae5f3b662d1ca30f4251d75a068fe54a55ae8
  MD5         : aae6348df69d87b437e3ad233c7d608c
--------------------------------------------------------------------
  VERDICT     : [EDITED] DIGITALLY ALTERED / EDITED
  INTEGRITY   : 60 / 100  (Confidence: High)
  EDITORS     : Windows Photos
  INDICATORS  :
    - Editor signature detected: Windows Photos
--------------------------------------------------------------------
  GEOLOCATION : GPS COORDINATES DETECTED
    Decimal   : 28.646610, 77.159943
    DMS       : 28 deg 38' 47.80" N 77 deg 9' 35.79" E
    OSM Map   : https://www.openstreetmap.org/?mlat=28.64661&mlon=77.159943#map=16/28.64661/77.159943
    Google Map: https://www.google.com/maps?q=28.64661,77.159943
--------------------------------------------------------------------
  TIMELINE    :
    Original  : 2025-09-07T12:55:01
    Filesystem: 2026-11-10T22:00:46
--------------------------------------------------------------------
  REGISTRIES  : technical (6), EXIF (12), PIL_EXIF (4), INFO (6), GPS (10)
====================================================================
```

---

## Repository Architecture

```text
METAX/
|-- metax/
|   |-- __init__.py           Package initialization and interface exports
|   |-- core.py               Extraction engine for images, documents, and audio
|   |-- forensics.py          Tamper evaluation and integrity scoring algorithms
|   |-- gps.py                Coordinate calculation, DMS parsing, and map linking
|   |-- sanitizer.py          Metadata stripping and privacy sanitization routines
|   |-- web_server.py         Threaded HTTP/REST server implementation
|   |-- desktop_gui.py        Native Tkinter desktop application
|   `-- web/
|       |-- index.html        Monochrome web interface layout
|       |-- style.css         Dark monochrome typography and layout rules
|       `-- app.js            Client-side state, map rendering, and export logic
|-- app.py                    Direct web workspace launcher
|-- gui.py                    Direct desktop application launcher
|-- main.py                   Primary entry point and command-line parser
|-- pyproject.toml            Project packaging and dependency specification
|-- uv.lock                   Reproducible dependency lockfile
`-- README.md                 Documentation
```

---

## License

This software is released under the **MIT License**. Permitted for educational, forensic research, and production workflows.

Authored by **Security Geek**. Enhanced with **MetaX Forensic Intelligence**.
