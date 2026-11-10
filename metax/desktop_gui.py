"""
MetaX Desktop GUI — Minimalist Monochrome Forensic Explorer.
Built with Tkinter/TTK styled with a bespoke dark monochrome theme.
Zero external GUI dependencies.
"""

import json
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional, Dict, Any

from metax.core import extract_metadata
from metax.sanitizer import strip_image_metadata


COLOR_VOID = "#050505"
COLOR_BG = "#0a0a0c"
COLOR_SURFACE = "#121216"
COLOR_CARD = "#18181e"
COLOR_BORDER = "#27272f"
COLOR_TEXT_PRIMARY = "#ffffff"
COLOR_TEXT_SECONDARY = "#a1a1aa"
COLOR_TEXT_MUTED = "#52525b"
COLOR_ACCENT = "#ffffff"
FONT_MONO = ("Consolas", 9)
FONT_MONO_BOLD = ("Consolas", 10, "bold")
FONT_TITLE = ("Segoe UI", 12, "bold")


class MetaXDesktopApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("META // X — Forensic Metadata Explorer")
        self.root.geometry("1060x700")
        self.root.minsize(850, 550)
        self.root.configure(bg=COLOR_VOID)

        self.current_data: Optional[Dict[str, Any]] = None
        self.current_file_path: Optional[str] = None

        self.setup_styles()
        self.build_ui()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=COLOR_BG, foreground=COLOR_TEXT_PRIMARY, font=FONT_MONO)
        style.configure("TFrame", background=COLOR_BG)
        style.configure("Surface.TFrame", background=COLOR_SURFACE)
        style.configure("Card.TFrame", background=COLOR_CARD)

        style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT_PRIMARY, font=FONT_MONO)
        style.configure("Muted.TLabel", background=COLOR_BG, foreground=COLOR_TEXT_MUTED, font=("Consolas", 8))
        style.configure("Primary.TButton", background=COLOR_SURFACE, foreground=COLOR_TEXT_PRIMARY, borderwidth=1, relief="flat", font=FONT_MONO_BOLD, padding=6)
        style.map("Primary.TButton", background=[("active", COLOR_CARD), ("pressed", COLOR_BORDER)], foreground=[("active", COLOR_TEXT_PRIMARY)])

        style.configure("Treeview", background=COLOR_VOID, foreground=COLOR_TEXT_PRIMARY, fieldbackground=COLOR_VOID, borderwidth=0, font=FONT_MONO, rowheight=24)
        style.map("Treeview", background=[("selected", COLOR_CARD)], foreground=[("selected", COLOR_TEXT_PRIMARY)])
        style.configure("Treeview.Heading", background=COLOR_SURFACE, foreground=COLOR_TEXT_SECONDARY, font=FONT_MONO_BOLD, borderwidth=1, relief="flat")

        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=COLOR_SURFACE, foreground=COLOR_TEXT_SECONDARY, padding=[12, 6], font=FONT_MONO)
        style.map("TNotebook.Tab", background=[("selected", COLOR_CARD)], foreground=[("selected", COLOR_TEXT_PRIMARY)])

    def build_ui(self):
        header = tk.Frame(self.root, bg=COLOR_VOID, height=54)
        header.pack(fill="x", side="top", padx=16, pady=10)

        brand_frame = tk.Frame(header, bg=COLOR_VOID)
        brand_frame.pack(side="left")

        logo = tk.Label(brand_frame, text="[ MX ]", font=("Consolas", 11, "bold"), bg=COLOR_TEXT_PRIMARY, fg=COLOR_VOID, padx=6, pady=2)
        logo.pack(side="left", padx=(0, 10))

        title = tk.Label(brand_frame, text="META // X", font=("Consolas", 13, "bold"), bg=COLOR_VOID, fg=COLOR_TEXT_PRIMARY)
        title.pack(side="left")

        subtitle = tk.Label(brand_frame, text="  FORENSIC ARTIFACT EXPLORER", font=("Consolas", 9), bg=COLOR_VOID, fg=COLOR_TEXT_MUTED)
        subtitle.pack(side="left")

        btn_frame = tk.Frame(header, bg=COLOR_VOID)
        btn_frame.pack(side="right")

        browse_btn = tk.Button(
            btn_frame,
            text="+ OPEN EVIDENCE FILE",
            command=self.browse_file,
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
            activebackground=COLOR_CARD,
            activeforeground=COLOR_TEXT_PRIMARY,
            relief="groove",
            bd=1,
            font=FONT_MONO_BOLD,
            padx=10,
            pady=4,
            cursor="hand2"
        )
        browse_btn.pack(side="right", padx=(8, 0))

        for sample in ["test.mp3", "test.pdf", "test.jpg"]:
            btn = tk.Button(
                btn_frame,
                text=sample,
                command=lambda s=sample: self.load_sample(s),
                bg=COLOR_VOID,
                fg=COLOR_TEXT_MUTED,
                activebackground=COLOR_SURFACE,
                activeforeground=COLOR_TEXT_PRIMARY,
                relief="flat",
                bd=0,
                font=("Consolas", 8),
                padx=6,
                cursor="hand2"
            )
            btn.pack(side="right", padx=2)

        main_paned = tk.PanedWindow(self.root, orient="horizontal", bg=COLOR_BORDER, bd=1, sashwidth=4)
        main_paned.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        left_panel = tk.Frame(main_paned, bg=COLOR_BG, width=320)
        main_paned.add(left_panel, minsize=280)

        ov_card = tk.LabelFrame(left_panel, text=" [ ARTIFACT PROPERTIES ] ", font=FONT_MONO_BOLD, bg=COLOR_BG, fg=COLOR_TEXT_SECONDARY, bd=1, relief="solid")
        ov_card.pack(fill="x", padx=10, pady=10)

        self.lbl_filename = tk.Label(ov_card, text="File: No file loaded", anchor="w", fg=COLOR_TEXT_PRIMARY, bg=COLOR_BG)
        self.lbl_filename.pack(fill="x", padx=10, pady=(6, 2))

        self.lbl_filesize = tk.Label(ov_card, text="Size: -", anchor="w", fg=COLOR_TEXT_MUTED, bg=COLOR_BG)
        self.lbl_filesize.pack(fill="x", padx=10, pady=2)

        self.lbl_filetype = tk.Label(ov_card, text="Type: -", anchor="w", fg=COLOR_TEXT_MUTED, bg=COLOR_BG)
        self.lbl_filetype.pack(fill="x", padx=10, pady=(2, 8))

        hash_card = tk.LabelFrame(left_panel, text=" [ CRYPTOGRAPHIC HASHES ] ", font=FONT_MONO_BOLD, bg=COLOR_BG, fg=COLOR_TEXT_SECONDARY, bd=1, relief="solid")
        hash_card.pack(fill="x", padx=10, pady=10)

        self.hash_entries = {}
        for h_name in ["SHA-256", "SHA-1", "MD5"]:
            f = tk.Frame(hash_card, bg=COLOR_BG)
            f.pack(fill="x", padx=10, pady=4)
            lbl = tk.Label(f, text=h_name, font=("Consolas", 8, "bold"), fg=COLOR_TEXT_MUTED, bg=COLOR_BG, anchor="w")
            lbl.pack(fill="x")
            val_box = tk.Entry(f, font=("Consolas", 8), bg=COLOR_SURFACE, fg=COLOR_TEXT_PRIMARY, bd=1, relief="solid")
            val_box.pack(fill="x", pady=2)
            self.hash_entries[h_name] = val_box

        action_card = tk.LabelFrame(left_panel, text=" [ ACTIONS ] ", font=FONT_MONO_BOLD, bg=COLOR_BG, fg=COLOR_TEXT_SECONDARY, bd=1, relief="solid")
        action_card.pack(fill="x", padx=10, pady=10)

        strip_btn = tk.Button(
            action_card,
            text="STRIP METADATA (CLEAN FILE)",
            command=self.strip_current_file,
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
            relief="groove",
            bd=1,
            font=("Consolas", 8, "bold"),
            pady=4,
            cursor="hand2"
        )
        strip_btn.pack(fill="x", padx=10, pady=4)

        export_json_btn = tk.Button(
            action_card,
            text="EXPORT JSON REPORT",
            command=self.export_json,
            bg=COLOR_BG,
            fg=COLOR_TEXT_SECONDARY,
            relief="solid",
            bd=1,
            font=("Consolas", 8),
            pady=4,
            cursor="hand2"
        )
        export_json_btn.pack(fill="x", padx=10, pady=4)

        export_md_btn = tk.Button(
            action_card,
            text="EXPORT MARKDOWN REPORT",
            command=self.export_markdown,
            bg=COLOR_BG,
            fg=COLOR_TEXT_SECONDARY,
            relief="solid",
            bd=1,
            font=("Consolas", 8),
            pady=4,
            cursor="hand2"
        )
        export_md_btn.pack(fill="x", padx=10, pady=4)

        right_panel = tk.Frame(main_paned, bg=COLOR_BG)
        main_paned.add(right_panel, minsize=500)

        verdict_frame = tk.Frame(right_panel, bg=COLOR_SURFACE, bd=1, relief="solid")
        verdict_frame.pack(fill="x", padx=10, pady=10)

        v_inner = tk.Frame(verdict_frame, bg=COLOR_SURFACE)
        v_inner.pack(fill="x", padx=14, pady=12)

        self.lbl_verdict_title = tk.Label(v_inner, text="AWAITING ARTIFACT", font=("Segoe UI", 13, "bold"), fg=COLOR_TEXT_PRIMARY, bg=COLOR_SURFACE)
        self.lbl_verdict_title.pack(anchor="w")

        self.lbl_verdict_sub = tk.Label(v_inner, text="Integrity Score: --/100", font=FONT_MONO, fg=COLOR_TEXT_MUTED, bg=COLOR_SURFACE)
        self.lbl_verdict_sub.pack(anchor="w", pady=(2, 6))

        self.lbl_indicators = tk.Label(v_inner, text="", font=FONT_MONO, fg=COLOR_TEXT_SECONDARY, bg=COLOR_SURFACE, wraplength=580, justify="left")
        self.lbl_indicators.pack(anchor="w")

        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        tab_meta = ttk.Frame(self.notebook)
        self.notebook.add(tab_meta, text=" Metadata Explorer ")

        search_frame = tk.Frame(tab_meta, bg=COLOR_BG)
        search_frame.pack(fill="x", padx=6, pady=6)
        tk.Label(search_frame, text="FILTER: ", font=FONT_MONO_BOLD, fg=COLOR_TEXT_MUTED, bg=COLOR_BG).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_metadata_tree)
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, bg=COLOR_SURFACE, fg=COLOR_TEXT_PRIMARY, bd=1, relief="solid", font=FONT_MONO)
        search_entry.pack(side="left", fill="x", expand=True, padx=4)

        tree_frame = tk.Frame(tab_meta, bg=COLOR_VOID)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        self.meta_tree = ttk.Treeview(tree_frame, columns=("Tag", "Value"), show="headings")
        self.meta_tree.heading("Tag", text="TAG / ATTRIBUTE")
        self.meta_tree.heading("Value", text="DECODED VALUE")
        self.meta_tree.column("Tag", width=220, anchor="w")
        self.meta_tree.column("Value", width=420, anchor="w")

        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.meta_tree.yview)
        self.meta_tree.configure(yscrollcommand=sb.set)
        self.meta_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        tab_gps = ttk.Frame(self.notebook)
        self.notebook.add(tab_gps, text=" GPS Geolocation ")

        self.gps_text = tk.Text(tab_gps, bg=COLOR_VOID, fg=COLOR_TEXT_PRIMARY, font=FONT_MONO, bd=0, padx=14, pady=14)
        self.gps_text.pack(fill="both", expand=True)

        tab_time = ttk.Frame(self.notebook)
        self.notebook.add(tab_time, text=" Temporal Analysis ")

        self.time_text = tk.Text(tab_time, bg=COLOR_VOID, fg=COLOR_TEXT_PRIMARY, font=FONT_MONO, bd=0, padx=14, pady=14)
        self.time_text.pack(fill="both", expand=True)

        tab_json = ttk.Frame(self.notebook)
        self.notebook.add(tab_json, text=" Raw JSON ")

        self.json_text = tk.Text(tab_json, bg=COLOR_VOID, fg=COLOR_TEXT_PRIMARY, font=FONT_MONO, bd=0, padx=14, pady=14)
        self.json_text.pack(fill="both", expand=True)

    def browse_file(self):
        filepath = filedialog.askopenfilename(
            title="Select Artifact for Analysis",
            filetypes=[
                ("All Supported Files", "*.jpg;*.jpeg;*.png;*.webp;*.pdf;*.mp3;*.wav;*.flac;*.mp4;*.mov"),
                ("Images", "*.jpg;*.jpeg;*.png;*.webp;*.tiff"),
                ("PDF Documents", "*.pdf"),
                ("Audio Files", "*.mp3;*.wav;*.flac;*.ogg;*.m4a"),
                ("All Files", "*.*")
            ]
        )
        if filepath:
            self.analyze_file(filepath)

    def load_sample(self, sample_name: str):
        p = os.path.abspath(sample_name)
        if os.path.exists(p):
            self.analyze_file(p)
        else:
            messagebox.showerror("Error", f"Sample file '{sample_name}' not found.")

    def analyze_file(self, filepath: str):
        try:
            data = extract_metadata(filepath)
            self.current_data = data
            self.current_file_path = filepath
            self.render_data(data)
        except Exception as e:
            messagebox.showerror("Analysis Error", str(e))

    def render_data(self, data: Dict[str, Any]):
        self.lbl_filename.config(text=f"File: {data.get('filename')}")
        self.lbl_filesize.config(text=f"Size: {data.get('file_size_formatted')}")
        self.lbl_filetype.config(text=f"Type: {data.get('file_type', '').upper()}")

        h = data.get("hashes", {})
        for name, key in [("SHA-256", "sha256"), ("SHA-1", "sha1"), ("MD5", "md5")]:
            entry = self.hash_entries.get(name)
            if entry:
                entry.delete(0, tk.END)
                entry.insert(0, h.get(key, ""))

        an = data.get("analysis", {})
        verdict = an.get("verdict", "UNKNOWN")
        score = an.get("integrity_score", 100)
        self.lbl_verdict_title.config(text=f"VERDICT: {verdict}")
        self.lbl_verdict_sub.config(text=f"Forensic Integrity Index: {score} / 100  |  Confidence: {an.get('confidence', 'Medium')}")

        indicators = an.get("indicators", [])
        if indicators:
            self.lbl_indicators.config(text="● " + "\n● ".join(indicators))
        else:
            self.lbl_indicators.config(text="● No manipulation or tampering signatures identified.")

        self.gps_text.delete("1.0", tk.END)
        gps = data.get("gps", {})
        if gps.get("has_gps"):
            self.gps_text.insert(tk.END, "=== GPS GEOLOCATION EXTRACTED ===\n\n")
            self.gps_text.insert(tk.END, f"Decimal Coordinates: {gps.get('formatted_coordinates')}\n")
            self.gps_text.insert(tk.END, f"DMS Latitude:        {gps.get('latitude_dms')}\n")
            self.gps_text.insert(tk.END, f"DMS Longitude:       {gps.get('longitude_dms')}\n")
            if gps.get("altitude_meters") is not None:
                self.gps_text.insert(tk.END, f"Altitude:            {gps.get('altitude_meters')} meters\n")
            self.gps_text.insert(tk.END, f"\nOpenStreetMap Link:  {gps.get('osm_url')}\n")
            self.gps_text.insert(tk.END, f"Google Maps Link:    {gps.get('maps_url')}\n")
        else:
            self.gps_text.insert(tk.END, "No GPS geolocation tags found in this artifact.\n")

        self.time_text.delete("1.0", tk.END)
        ts = an.get("timestamp_analysis", {})
        self.time_text.insert(tk.END, "=== TEMPORAL ANALYSIS ===\n\n")
        self.time_text.insert(tk.END, f"Original Capture Date:    {ts.get('original_date') or 'Not Recorded'}\n")
        self.time_text.insert(tk.END, f"Software Modify Date:     {ts.get('modify_date') or 'Not Recorded'}\n")
        self.time_text.insert(tk.END, f"Filesystem Modified:      {ts.get('fs_modified') or 'Not Available'}\n")
        self.time_text.insert(tk.END, f"Timeline Consistent:      {'YES' if ts.get('timeline_consistent') else 'ANOMALY DETECTED'}\n\n")

        if ts.get("anomalies"):
            self.time_text.insert(tk.END, "Identified Temporal Anomalies:\n")
            for a in ts["anomalies"]:
                self.time_text.insert(tk.END, f"  [!] {a}\n")

        self.json_text.delete("1.0", tk.END)
        self.json_text.insert(tk.END, json.dumps(data, indent=2, default=str))

        self.populate_treeview()

    def populate_treeview(self):
        self.meta_tree.delete(*self.meta_tree.get_children())
        if not self.current_data:
            return

        meta = self.current_data.get("metadata", {})
        query = self.search_var.get().strip().lower()

        def add_dict(d, prefix=""):
            for k, v in d.items():
                full_key = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, dict):
                    add_dict(v, full_key)
                else:
                    v_str = str(v)
                    if query and query not in full_key.lower() and query not in v_str.lower():
                        continue
                    self.meta_tree.insert("", "end", values=(full_key, v_str))

        add_dict(meta)

    def filter_metadata_tree(self, *args):
        self.populate_treeview()

    def strip_current_file(self):
        if not self.current_file_path or not os.path.exists(self.current_file_path):
            messagebox.showinfo("Strip", "Please load an image file first.")
            return

        out_path = filedialog.asksaveasfilename(
            title="Save Sanitized Image",
            defaultextension=".jpg",
            initialfile=f"clean_{os.path.basename(self.current_file_path)}"
        )
        if out_path:
            res = strip_image_metadata(self.current_file_path, out_path)
            if res.get("success"):
                messagebox.showinfo("Success", f"Sanitized image saved to:\n{out_path}\nAll EXIF, GPS, and personal metadata removed.")
            else:
                messagebox.showerror("Error", res.get("error", "Sanitization failed"))

    def export_json(self):
        if not self.current_data:
            return
        out_path = filedialog.asksaveasfilename(
            title="Save JSON Forensic Report",
            defaultextension=".json",
            initialfile=f"metax_{self.current_data.get('filename')}_report.json"
        )
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(self.current_data, f, indent=2, default=str)
            messagebox.showinfo("Saved", f"Forensic JSON report saved to:\n{out_path}")

    def export_markdown(self):
        if not self.current_data:
            return
        out_path = filedialog.asksaveasfilename(
            title="Save Markdown Report",
            defaultextension=".md",
            initialfile=f"metax_{self.current_data.get('filename')}_report.md"
        )
        if out_path:
            d = self.current_data
            an = d.get("analysis", {})
            h = d.get("hashes", {})
            g = d.get("gps", {})
            md = f"# 🧠 METAX Forensic Report: {d.get('filename')}\n\n"
            md += f"- **Verdict:** {an.get('verdict')}\n"
            md += f"- **Integrity Score:** {an.get('integrity_score')}/100\n"
            md += f"- **SHA-256:** `{h.get('sha256')}`\n\n"
            if g.get("has_gps"):
                md += f"## 📍 Coordinates\n{g.get('formatted_coordinates')} ({g.get('latitude_dms')} {g.get('longitude_dms')})\n\n"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(md)
            messagebox.showinfo("Saved", f"Markdown report saved to:\n{out_path}")


def start_gui():
    root = tk.Tk()
    app = MetaXDesktopApp(root)
    sample_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test.jpg")
    if os.path.exists(sample_path):
        app.analyze_file(sample_path)
    root.mainloop()


if __name__ == "__main__":
    start_gui()

