/**
 * METAX — Minimalist Monochrome Forensic Frontend
 */

let currentAnalysis = null;
let currentRawFile = null;
let activeTab = "all";
let flattenedTags = [];

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const loadingSpinner = document.getElementById("loading-spinner");
const reportContainer = document.getElementById("report-container");
const searchBox = document.getElementById("search-box");
const tabButtons = document.querySelectorAll(".meta-tab-btn");

document.addEventListener("DOMContentLoaded", () => {
  setupDropzone();
  setupSampleButtons();
  setupSearchAndTabs();
  setupCopyButtons();
  setupExportButtons();
});

function setupDropzone() {
  dropzone.addEventListener("click", () => fileInput.click());

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("drag-over");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("drag-over");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag-over");
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  });
}

function setupSampleButtons() {
  document.querySelectorAll(".sample-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sampleName = btn.getAttribute("data-sample");
      loadSample(sampleName);
    });
  });
}

function setupSearchAndTabs() {
  searchBox.addEventListener("input", () => {
    renderMetadataTable();
  });

  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activeTab = btn.getAttribute("data-tab");
      renderMetadataTable();
    });
  });
}

function setupCopyButtons() {
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-copy-target");
      const targetEl = document.getElementById(targetId);
      if (targetEl && targetEl.textContent) {
        navigator.clipboard.writeText(targetEl.textContent.trim());
        const originalText = btn.textContent;
        btn.textContent = "COPIED";
        btn.style.borderColor = "var(--border-bright)";
        setTimeout(() => {
          btn.textContent = originalText;
          btn.style.borderColor = "";
        }, 1200);
      }
    });
  });
}

function setupExportButtons() {
  document.getElementById("btn-export-json").addEventListener("click", () => {
    if (!currentAnalysis) return;
    const blob = new Blob([JSON.stringify(currentAnalysis, null, 2)], { type: "application/json" });
    downloadBlob(blob, `metax_${currentAnalysis.filename || "artifact"}_report.json`);
  });

  document.getElementById("btn-export-markdown").addEventListener("click", () => {
    if (!currentAnalysis) return;
    const md = generateMarkdownReport(currentAnalysis);
    const blob = new Blob([md], { type: "text/markdown" });
    downloadBlob(blob, `metax_${currentAnalysis.filename || "artifact"}_forensics.md`);
  });

  document.getElementById("strip-metadata-btn").addEventListener("click", () => {
    stripAndDownload();
  });

  document.getElementById("btn-scan-another").addEventListener("click", () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
}

async function handleFileUpload(file) {
  currentRawFile = file;
  showLoading(true);

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      body: formData,
    });
    const data = await res.json();
    displayReport(data, file);
  } catch (err) {
    alert("Analysis failed: " + err.message);
  } finally {
    showLoading(false);
  }
}

async function loadSample(sampleName) {
  currentRawFile = null;
  showLoading(true);

  try {
    const res = await fetch(`/api/sample?name=${encodeURIComponent(sampleName)}`);
    const data = await res.json();
    displayReport(data, null, sampleName);
  } catch (err) {
    alert("Failed to load sample: " + err.message);
  } finally {
    showLoading(false);
  }
}

async function stripAndDownload() {
  if (!currentAnalysis) return;

  const btn = document.getElementById("strip-metadata-btn");
  const origText = btn.innerHTML;
  btn.innerHTML = "SANITIZING...";

  try {
    let res;
    if (currentRawFile) {
      const formData = new FormData();
      formData.append("file", currentRawFile);
      res = await fetch("/api/strip", { method: "POST", body: formData });
    } else {
      const sampleName = currentAnalysis.filename;
      res = await fetch(`/api/strip?sample=${encodeURIComponent(sampleName)}`);
    }

    if (res.ok) {
      const blob = await res.blob();
      const baseName = currentAnalysis.filename || "sanitized_image.jpg";
      downloadBlob(blob, `clean_${baseName}`);
    } else {
      const err = await res.json();
      alert("Sanitization error: " + (err.error || "Unknown"));
    }
  } catch (e) {
    alert("Strip error: " + e.message);
  } finally {
    btn.innerHTML = origText;
  }
}

function showLoading(active) {
  if (active) {
    loadingSpinner.classList.add("active");
    reportContainer.classList.remove("visible");
  } else {
    loadingSpinner.classList.remove("active");
  }
}

function displayReport(data, fileObj = null, sampleName = null) {
  currentAnalysis = data;
  reportContainer.classList.add("visible");

  const analysis = data.analysis || {};
  document.getElementById("verdict-text").textContent = analysis.verdict || "ANALYSIS COMPLETE";

  const badgeEl = document.getElementById("verdict-badge");
  badgeEl.textContent = analysis.verdict_badge || "VERIFIED";

  const score = analysis.integrity_score !== undefined ? analysis.integrity_score : 100;
  document.getElementById("integrity-score").textContent = score;
  document.getElementById("score-bar-fill").style.width = `${score}%`;

  const indContainer = document.getElementById("verdict-indicators-container");
  indContainer.innerHTML = "";
  (analysis.indicators || []).forEach((ind) => {
    const span = document.createElement("span");
    span.className = "indicator-badge";
    span.textContent = ind;
    indContainer.appendChild(span);
  });

  if ((analysis.indicators || []).length === 0) {
    const span = document.createElement("span");
    span.className = "indicator-badge";
    span.textContent = "No manipulation signatures detected";
    indContainer.appendChild(span);
  }

  document.getElementById("file-name").textContent = data.filename || "Unknown";
  document.getElementById("file-size").textContent = data.file_size_formatted || `${data.file_size_bytes} B`;
  document.getElementById("file-type-badge").textContent = (data.file_type || "UNKNOWN").toUpperCase();

  const tech = (data.metadata && data.metadata.technical) || {};
  const dimRow = document.getElementById("dimensions-row");
  const durRow = document.getElementById("duration-row");

  if (tech.width && tech.height) {
    dimRow.style.display = "flex";
    document.getElementById("file-dimensions").textContent = `${tech.width} × ${tech.height} (${tech.megapixels || "?"} MP)`;
  } else {
    dimRow.style.display = "none";
  }

  if (tech.duration_formatted) {
    durRow.style.display = "flex";
    document.getElementById("file-duration").textContent = `${tech.duration_formatted} (${tech.bitrate_kbps || "?"} kbps)`;
  } else {
    durRow.style.display = "none";
  }

  const hashes = data.hashes || {};
  document.getElementById("hash-sha256").textContent = hashes.sha256 || data.sha256 || "-";
  document.getElementById("hash-sha1").textContent = hashes.sha1 || "-";
  document.getElementById("hash-md5").textContent = hashes.md5 || "-";

  const previewImg = document.getElementById("preview-img");
  const previewPlaceholder = document.getElementById("preview-placeholder");

  if (data.file_type === "image") {
    if (fileObj) {
      previewImg.src = URL.createObjectURL(fileObj);
      previewImg.style.display = "block";
      previewPlaceholder.style.display = "none";
    } else if (sampleName) {
      previewImg.src = `/api/thumbnail?name=${encodeURIComponent(sampleName)}`;
      previewImg.style.display = "block";
      previewPlaceholder.style.display = "none";
    } else {
      previewImg.style.display = "none";
      previewPlaceholder.style.display = "block";
      previewPlaceholder.textContent = "IMAGE PREVIEW";
    }
  } else if (data.file_type === "pdf") {
    previewImg.style.display = "none";
    previewPlaceholder.style.display = "block";
    previewPlaceholder.textContent = "PDF DOCUMENT";
  } else if (data.file_type === "audio") {
    previewImg.style.display = "none";
    previewPlaceholder.style.display = "block";
    previewPlaceholder.textContent = "AUDIO FILE";
  } else {
    previewImg.style.display = "none";
    previewPlaceholder.style.display = "block";
    previewPlaceholder.textContent = "BINARY ARTIFACT";
  }

  const gps = data.gps || {};
  const gpsSection = document.getElementById("gps-section");
  if (gps && gps.has_gps) {
    gpsSection.style.display = "block";
    document.getElementById("gps-coords-display").textContent = gps.formatted_coordinates || `${gps.latitude}, ${gps.longitude}`;
    document.getElementById("gps-dms-display").textContent = `${gps.latitude_dms || ""} ${gps.longitude_dms || ""}`;
    document.getElementById("osm-link").href = gps.osm_url || "#";
    document.getElementById("gmaps-link").href = gps.maps_url || "#";

    const lat = gps.latitude;
    const lon = gps.longitude;
    const bbox = `${lon - 0.008},${lat - 0.006},${lon + 0.008},${lat + 0.006}`;
    const iframeSrc = `https://www.openstreetmap.org/export/embed.html?bbox=${encodeURIComponent(bbox)}&layer=mapnik&marker=${lat}%2C${lon}`;
    document.getElementById("map-iframe").src = iframeSrc;
  } else {
    gpsSection.style.display = "none";
  }

  const ts = analysis.timestamp_analysis || {};
  document.getElementById("date-orig").textContent = ts.original_date ? ts.original_date.replace("T", " ") : "Not Recorded";
  document.getElementById("date-mod").textContent = ts.modify_date ? ts.modify_date.replace("T", " ") : "Not Recorded";
  document.getElementById("date-fs").textContent = ts.fs_modified ? ts.fs_modified.replace("T", " ") : "Not Available";

  const tlBadge = document.getElementById("timeline-status-badge");
  tlBadge.textContent = ts.timeline_consistent ? "CONSISTENT" : "ANOMALOUS";

  const anomBox = document.getElementById("anomalies-box");
  const anomList = document.getElementById("anomalies-list");
  anomList.innerHTML = "";

  if (ts.anomalies && ts.anomalies.length > 0) {
    anomBox.style.display = "block";
    ts.anomalies.forEach((anom) => {
      const item = document.createElement("div");
      item.className = "anomaly-item";
      item.innerHTML = `<span class="anomaly-bullet">▲</span><span>${anom}</span>`;
      anomList.appendChild(item);
    });
  } else {
    anomBox.style.display = "none";
  }

  flattenMetadata(data);
  renderMetadataTable();

  reportContainer.scrollIntoView({ behavior: "smooth" });
}

function flattenMetadata(data) {
  flattenedTags = [];
  const meta = data.metadata || {};

  function traverse(obj, prefix = "", category = "all") {
    if (!obj || typeof obj !== "object") return;

    for (const key of Object.keys(obj)) {
      const val = obj[key];
      const fullKey = prefix ? `${prefix} : ${key}` : key;

      if (val && typeof val === "object" && !Array.isArray(val) && Object.keys(val).length > 0) {
        traverse(val, fullKey, category);
      } else {
        flattenedTags.push({
          category: category,
          key: fullKey,
          value: typeof val === "object" ? JSON.stringify(val) : String(val),
        });
      }
    }
  }

  if (meta.EXIF) traverse(meta.EXIF, "", "exif");
  if (meta.PIL_EXIF) traverse(meta.PIL_EXIF, "", "exif");
  if (meta.XMP) traverse(meta.XMP, "", "xmp");
  if (meta.technical) traverse(meta.technical, "", "tech");
  if (meta.INFO) traverse(meta.INFO, "", "tech");
  if (meta.document_info) traverse(meta.document_info, "", "doc");
  if (meta.tags) traverse(meta.tags, "", "audio");

  document.getElementById("tag-count-badge").textContent = `${flattenedTags.length} TAGS`;
}

function renderMetadataTable() {
  const tbody = document.getElementById("metadata-table-body");
  tbody.innerHTML = "";

  const query = searchBox.value.trim().toLowerCase();

  const filtered = flattenedTags.filter((item) => {
    if (activeTab === "exif" && item.category !== "exif") return false;
    if (activeTab === "xmp" && item.category !== "xmp") return false;
    if (activeTab === "tech" && item.category !== "tech") return false;

    if (query) {
      return item.key.toLowerCase().includes(query) || item.value.toLowerCase().includes(query);
    }
    return true;
  });

  if (filtered.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="2" style="text-align: center; color: var(--text-muted); padding: 24px;">NO MATCHING METADATA TAGS FOUND</td>`;
    tbody.appendChild(tr);
    return;
  }

  filtered.forEach((item) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="meta-key-col">${escapeHtml(item.key)}</td>
      <td class="meta-val-col">${escapeHtml(item.value)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function generateMarkdownReport(data) {
  const a = data.analysis || {};
  const h = data.hashes || {};
  const g = data.gps || {};

  return `# 🧠 METAX Forensic Report

**File:** \`${data.filename}\`  
**Size:** \`${data.file_size_formatted || data.file_size_bytes + " bytes"}\`  
**Type:** \`${data.file_type}\`  
**Forensic Verdict:** \`${a.verdict}\` (Integrity: ${a.integrity_score}/100)

---

## 🔒 Cryptographic Hashes
- **SHA-256:** \`${h.sha256 || data.sha256}\`
- **SHA-1:** \`${h.sha1 || "N/A"}\`
- **MD5:** \`${h.md5 || "N/A"}\`

---

## 🔍 Forensic Analysis
- **Verdict:** ${a.verdict}
- **Edited:** ${a.is_edited ? "YES" : "NO"}
- **Generative AI Detected:** ${a.is_ai_generated ? "YES" : "NO"}
- **Metadata Stripped:** ${a.is_stripped ? "YES" : "NO"}
- **Confidence:** ${a.confidence}
${a.detected_software && a.detected_software.length ? "- **Software Detected:** " + a.detected_software.join(", ") : ""}
${a.detected_ai_tools && a.detected_ai_tools.length ? "- **AI Tools Identified:** " + a.detected_ai_tools.join(", ") : ""}

### Forensic Indicators
${(a.indicators || []).map((i) => `- ${i}`).join("\n") || "No suspicious anomalies."}

---

## 📍 Geolocation
${
  g.has_gps
    ? `- **Coordinates:** ${g.formatted_coordinates}
- **DMS:** ${g.latitude_dms} ${g.longitude_dms}
- **Google Maps:** [Link](${g.maps_url})
- **OpenStreetMap:** [Link](${g.osm_url})`
    : "_No GPS geotag metadata embedded._"
}

---
*Report generated by MetaX Digital Forensics Engine*
`;
}

