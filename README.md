# 🧠 MetaX

MetaX is a Python-based **metadata extraction and forensic analysis tool** focused on **understanding what metadata means**, not just dumping raw fields.

Unlike traditional tools (such as ExifTool) that mainly display metadata, MetaX adds an **analysis layer** to detect image editing, AI involvement, and metadata integrity.

> ⚠️ MetaX is intended for learning, research, and digital forensics experimentation.

---

## ✨ Features

### 🔍 Metadata Extraction
- **Images**
  - EXIF (ExifRead + Pillow)
  - XMP (parsed and human-readable)
  - ICC profiles (summarized, not raw dumps)
  - Software and processing traces
- **PDFs**
  - Document metadata
- **Audio**
  - Format-level metadata
- **Cryptographic hashing**
  - SHA-256 file hashing

---

### 🧠 Forensic Analysis
- Detects whether an image was **edited**
- Detects **AI-related software** (e.g. Topaz, Photoshop)
- Identifies **metadata stripping / laundering**
- Provides a confidence-based forensic conclusion

MetaX focuses on **interpretation**, not just extraction.

---

## 🚀 Installation

### Requirements
- Python 3.9+

### Clone the repository
```bash
git clone https://github.com/<your-username>/MetaX.git
cd MetaX
```

### Create a virtual environment (recommended)
```bash
python -m venv .venv
.venv\Scripts\activate
```

### Install dependencies
```bash
pip install exifread pillow PyPDF2 mutagen
```

---

## 🛠️ Usage

### Basic usage
```bash
python main.py image.jpg
```

### JSON output
```bash
python main.py image.jpg --json
```

### Save output to file
```bash
python main.py image.jpg --json --out report.json
```

### Using uv
```bash
uv run .\main.py image.jpg --json --out report.json
```

---

## 📄 Example Output (simplified)

```json
{
  "file_type": "image",
  "sha256": "be0feb0aa734196e445167369cfe3ec2ffb86bbf56ef8990557dd4227bcaedf6",
  "metadata": {
    "XMP": {
      "CreatorTool": "Topaz Gigapixel AI 8.2.2"
    }
  },
  "analysis": {
    "edited": true,
    "ai_related": true,
    "software_detected": [
      "photoshop",
      "topaz",
      "gigapixel"
    ],
    "metadata_stripped": false,
    "confidence": "high"
  }
}
```


---

## 🧠 Roadmap

- Timestamp mismatch detection
- Metadata laundering detection
- Folder scanning & forensic reports
- Output normalization and severity scoring
- GUI forensic viewer

---

## 📜 License

MIT License

---

## 👤 Author

Created by **Security Geek**

Interested in digital forensics, cybersecurity, or metadata analysis?  
Feel free to explore, fork, and contribute.
