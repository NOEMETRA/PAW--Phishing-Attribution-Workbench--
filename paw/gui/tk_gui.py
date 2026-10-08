"""Complete PAW GUI - All functionality in one interface.

Features:
- File Analysis: Select .eml files/directories, run quick/full/forensic analysis
- Case Management: View cases, verify integrity, export, update with new data
- Intelligence: Query historical cases, geographic reports, victim database
- Tools: URL detonation, content deobfuscation
- Monitoring: Canary server control, tunnel management, live hit monitoring

Usage: python -m paw gui
"""
import os
import sys
import json
import subprocess
import threading
import time
from pathlib import Path
from tkinter import Tk, Frame, Label, Entry, Button, Text, StringVar, END, BOTH, LEFT, RIGHT, TOP, BOTTOM, X, Y, NW, W
from tkinter import messagebox, filedialog, scrolledtext, BooleanVar, font
from tkinter import ttk
from tkinter.ttk import LabelFrame, Style

try:
    import requests
except Exception:
    requests = None

# Global sentinel module references (populated dynamically in __init__)
CampaignDatabase = None
SentinelMonitor = None


class PawTkGui:
    def _setup_working_directory(self):
        """Automatically find and set the PAW working directory"""
        try:
            # Get the directory where this GUI file is located
            gui_dir = Path(__file__).parent  # paw/gui/
            paw_dir = gui_dir.parent.parent  # PAW/

            # Verify this is the correct PAW directory (should contain paw/ and requirements.txt)
            if (paw_dir / 'paw').is_dir() and (paw_dir / 'requirements.txt').exists():
                # Change to PAW directory so python -m paw commands work
                os.chdir(paw_dir)
                # Add PAW directory to Python path if not already there
                if str(paw_dir) not in sys.path:
                    sys.path.insert(0, str(paw_dir))
                print(f"PAW working directory set to: {paw_dir}")
            else:
                messagebox.showerror("PAW Error",
                    "Could not locate PAW directory. Please run the GUI from within the PAW project structure.")
        except Exception as e:
            messagebox.showerror("PAW Setup Error",
                f"Failed to setup working directory: {e}")

    def __init__(self, root):
        # Auto-setup working directory
        self._setup_working_directory()

        # Import sentinel modules after path is set up
        global CampaignDatabase, SentinelMonitor
        try:
            from paw.sentinel.database import CampaignDatabase as _CampaignDatabase
            from paw.sentinel.monitor import SentinelMonitor as _SentinelMonitor
            CampaignDatabase = _CampaignDatabase
            SentinelMonitor = _SentinelMonitor
            print("DEBUG: Sentinel modules imported successfully")
        except Exception as e:
            print(f"DEBUG: Sentinel modules import failed: {e}")
            CampaignDatabase = None
            SentinelMonitor = None

        self.root = root
        root.title("🔍 PAW - Professional Analysis Workstation")
        root.geometry('1300x850')
        root.configure(bg='#f0f2f5')

        # Modern styling
        self.style = Style()
        self.setup_modern_theme()

        # Custom fonts
        self.title_font = font.Font(family="Segoe UI", size=10, weight="bold")
        self.button_font = font.Font(family="Segoe UI", size=9)

        # State
        self.canary_proc = None
        self.tunnel_proc = None
        self._tail_thread = None
        self._stop_read = False
        self.email_enabled = False
        self.current_process = None  # For tracking running analysis

        # Initialize status variables BEFORE creating tabs
        self.status_var = StringVar(value="🟢 Ready - All systems operational")
        self.monitor_status_var = StringVar(value="Monitor: Not Available")
        self.campaign_name_var = StringVar()

        # Initialize Sentinel Monitor
        self.sentinel_monitor = None
        if SentinelMonitor:
            try:
                self.sentinel_monitor = SentinelMonitor()
            except Exception as e:
                print(f"Warning: Could not initialize Sentinel Monitor: {e}")

        # Create main container with padding
        main_frame = Frame(root, bg='#f0f2f5')
        main_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Header
        self.create_header(main_frame)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=BOTH, expand=True, pady=(10,0))

        # Analysis Tab
        self.create_analysis_tab()

        # Cases Tab
        self.create_cases_tab()

        # Intelligence Tab
        self.create_intelligence_tab()

        # Tools Tab
        self.create_tools_tab()

        # Geographic Tab
        self.create_geographic_tab()

        # Monitoring Tab
        self.create_monitoring_tab()

        # Status bar
        status_bar = Label(main_frame, textvariable=self.status_var, bg='#e8f4fd', fg='#2c3e50',
                          font=("Segoe UI", 9), relief="flat", anchor="w", padx=10, pady=5)
        status_bar.pack(fill=X, side=BOTTOM, pady=(10,0))

    def setup_modern_theme(self):
        """Setup modern ttk theme with custom colors"""
        try:
            # Use 'clam' theme as base for customization
            self.style.theme_use('clam')

            # Configure colors
            self.style.configure('TFrame', background='#f0f2f5')
            self.style.configure('TLabel', background='#f0f2f5', foreground='#2c3e50', font=('Segoe UI', 9))
            self.style.configure('TButton', font=('Segoe UI', 9, 'bold'), padding=6)
            self.style.configure('TEntry', padding=4, relief='flat')
            self.style.configure('TCombobox', padding=4)

            # Tab styling
            self.style.configure('TNotebook', background='#f0f2f5', tabmargins=[2, 5, 2, 0])
            self.style.configure('TNotebook.Tab', background='#ffffff', foreground='#2c3e50',
                               font=('Segoe UI', 10, 'bold'), padding=[15, 8], borderwidth=0)
            self.style.map('TNotebook.Tab',
                          background=[('selected', '#0078d4'), ('active', '#e8f4fd')],
                          foreground=[('selected', '#ffffff')])

            # LabelFrame styling
            self.style.configure('TLabelframe', background='#f0f2f5', foreground='#2c3e50',
                               font=('Segoe UI', 10, 'bold'), borderwidth=1, relief='solid')
            self.style.configure('TLabelframe.Label', background='#f0f2f5', foreground='#0078d4',
                               font=('Segoe UI', 10, 'bold'))

        except:
            pass  # Fallback to default theme if styling fails

    def create_header(self, parent):
        """Create modern header with logo and title"""
        header_frame = Frame(parent, bg='#0078d4', height=60)
        header_frame.pack(fill=X, pady=(0, 5))
        header_frame.pack_propagate(False)

        # Logo/Icon
        logo_label = Label(header_frame, text="🔍", bg='#0078d4', fg='white',
                          font=('Segoe UI', 24), padx=15)
        logo_label.pack(side=LEFT)

        # Title
        title_label = Label(header_frame, text="PAW Professional Analysis Workstation",
                           bg='#0078d4', fg='white', font=('Segoe UI', 16, 'bold'))
        title_label.pack(side=LEFT, padx=(0, 20))

        # Subtitle
        subtitle_label = Label(header_frame, text="Complete Email Analysis & Intelligence Platform",
                              bg='#0078d4', fg='#e8f4fd', font=('Segoe UI', 9))
        subtitle_label.pack(side=LEFT)

    def create_analysis_tab(self):
        tab = Frame(self.notebook, bg='#f8f9fa')
        self.notebook.add(tab, text="� Analysis")

        # File selection with modern styling
        f_file = LabelFrame(tab, text="📎 File Selection")
        f_file.pack(fill=X, padx=15, pady=10)

        inner_file = Frame(f_file, bg='#f8f9fa')
        inner_file.pack(fill=X, padx=10, pady=10)

        Label(inner_file, text="📧 Email file/directory:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=0, sticky=W, pady=5)
        self.analysis_file_var = StringVar()
        Entry(inner_file, textvariable=self.analysis_file_var, width=50, font=('Segoe UI', 9)).grid(row=0, column=1, padx=(10,5), pady=5)

        Button(inner_file, text="📂 Browse File", command=self.browse_analysis_file,
               bg='#0078d4', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=0, column=2, padx=5, pady=5)
        Button(inner_file, text="📁 Browse Directory", command=self.browse_analysis_dir,
               bg='#28a745', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=0, column=3, padx=5, pady=5)

        # Analysis options
        f_options = LabelFrame(tab, text="⚙️ Forensic Analysis Options")
        f_options.pack(fill=X, padx=15, pady=10)

        inner_options = Frame(f_options, bg='#f8f9fa')
        inner_options.pack(fill=X, padx=10, pady=10)

        # Language
        Label(inner_options, text="� Report Language:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=0, sticky=W, pady=5)
        self.analysis_lang = StringVar(value="en")
        Entry(inner_options, textvariable=self.analysis_lang, width=10, font=('Segoe UI', 9)).grid(row=0, column=1, padx=(10,20), pady=5)

        # Checkboxes for options
        self.stix_var = BooleanVar()
        self.abuse_var = BooleanVar()
        self.forensic_var = BooleanVar()
        self.no_egress_var = BooleanVar(value=True)  # Safe default

        Label(inner_options, text="🔧 Export Options:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=2, sticky=W, padx=(20,0), pady=5)

        ttk.Checkbutton(inner_options, text="📊 STIX bundle", variable=self.stix_var).grid(row=0, column=3, padx=10, pady=5)
        ttk.Checkbutton(inner_options, text="🚨 Abuse package", variable=self.abuse_var).grid(row=0, column=4, padx=10, pady=5)
        ttk.Checkbutton(inner_options, text="🔒 No external contact", variable=self.no_egress_var).grid(row=0, column=5, padx=10, pady=5)

        # Run button
        f_run = Frame(tab, bg='#f8f9fa')
        f_run.pack(fill=X, padx=15, pady=10)
        self.run_analysis_btn = Button(f_run, text="� Run Forensic Analysis", command=self.run_analysis,
               bg='#dc3545', fg='white', font=('Segoe UI', 11, 'bold'),
               relief='flat', padx=25, pady=8, height=1)
        self.run_analysis_btn.pack(side=LEFT, padx=10)
        
        self.stop_analysis_btn = Button(f_run, text="⏹️ Stop Analysis", command=self.stop_analysis,
               bg='#6c757d', fg='white', font=('Segoe UI', 11, 'bold'),
               relief='flat', padx=25, pady=8, height=1, state='disabled')
        self.stop_analysis_btn.pack(side=LEFT, padx=10)

        # Results area
        f_results = LabelFrame(tab, text="📋 Analysis Results")
        f_results.pack(fill=BOTH, expand=True, padx=15, pady=10)

        inner_results = Frame(f_results, bg='#f8f9fa')
        inner_results.pack(fill=BOTH, expand=True, padx=10, pady=10)

        Label(inner_results, text="📄 Output:", bg='#f8f9fa', font=self.title_font).pack(anchor=NW)
        self.analysis_text = scrolledtext.ScrolledText(inner_results, height=15, font=('Consolas', 9),
                                                      bg='#ffffff', fg='#2c3e50', insertbackground='#0078d4')
        self.analysis_text.pack(fill=BOTH, expand=True, pady=(5,0))

    def create_cases_tab(self):
        tab = Frame(self.notebook, bg='#f8f9fa')
        self.notebook.add(tab, text="📁 Cases")

        # Case selection
        f_case = LabelFrame(tab, text="📋 Case Management")
        f_case.pack(fill=X, padx=15, pady=10)

        inner_case = Frame(f_case, bg='#f8f9fa')
        inner_case.pack(fill=X, padx=10, pady=10)

        Label(inner_case, text="📂 Case:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=0, sticky=W, pady=5)
        self.case_var = StringVar()
        self.cases_combo = ttk.Combobox(inner_case, textvariable=self.case_var, width=40, font=('Segoe UI', 9))
        self.cases_combo.grid(row=0, column=1, padx=(10,10), pady=5)
        Button(inner_case, text="🔄 Refresh", command=self.refresh_cases,
               bg='#17a2b8', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=0, column=2, padx=5, pady=5)
        self.cases_combo.bind("<<ComboboxSelected>>", lambda e: self.case_var.set(self.cases_combo.get()))

        # Case actions
        f_actions = LabelFrame(tab, text="🛠️ Case Operations")
        f_actions.pack(fill=X, padx=15, pady=10)

        inner_actions = Frame(f_actions, bg='#f8f9fa')
        inner_actions.pack(fill=X, padx=10, pady=10)

        Button(inner_actions, text="✅ Verify Integrity", command=self.verify_case,
               bg='#28a745', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=0, column=0, padx=5, pady=5)
        Button(inner_actions, text="📦 Export ZIP", command=self.export_case,
               bg='#007bff', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=0, column=1, padx=5, pady=5)
        Button(inner_actions, text="🔄 Update with New Data", command=self.update_case,
               bg='#ffc107', fg='#212529', font=self.button_font, relief='flat', padx=15).grid(row=0, column=2, padx=5, pady=5)
        Button(inner_actions, text="📋 Show Headers & URLs", command=self.show_headers_urls,
               bg='#6c757d', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=0, column=3, padx=5, pady=5)

        # Case info
        f_info = LabelFrame(tab, text="ℹ️ Case Information")
        f_info.pack(fill=BOTH, expand=True, padx=15, pady=10)

        inner_info = Frame(f_info, bg='#f8f9fa')
        inner_info.pack(fill=BOTH, expand=True, padx=10, pady=10)

        Label(inner_info, text="📄 Details:", bg='#f8f9fa', font=self.title_font).pack(anchor=NW)
        self.case_text = scrolledtext.ScrolledText(inner_info, height=15, font=('Consolas', 9),
                                                  bg='#ffffff', fg='#2c3e50', insertbackground='#0078d4')
        self.case_text.pack(fill=BOTH, expand=True, pady=(5,0))

        # Initialize
        self.refresh_cases()

    def create_intelligence_tab(self):
        tab = Frame(self.notebook, bg='#f8f9fa')
        self.notebook.add(tab, text="🕵️ Intelligence")

        # Query section
        f_query = LabelFrame(tab, text="🔍 Historical Case Queries")
        f_query.pack(fill=X, padx=15, pady=10)

        inner_query = Frame(f_query, bg='#f8f9fa')
        inner_query.pack(fill=X, padx=10, pady=10)

        Label(inner_query, text="🎯 Query by:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=0, sticky=W, pady=5)
        self.query_type = StringVar(value="ip")
        ttk.Combobox(inner_query, textvariable=self.query_type, width=12,
                     values=["ip", "domain", "asn", "org"], font=('Segoe UI', 9)).grid(row=0, column=1, padx=(10,15), pady=5)

        Label(inner_query, text="📝 Value:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=2, sticky=W, pady=5)
        self.query_value = StringVar()
        Entry(inner_query, textvariable=self.query_value, width=25, font=('Segoe UI', 9)).grid(row=0, column=3, padx=(10,15), pady=5)

        Label(inner_query, text="📅 Days back:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=4, sticky=W, pady=5)
        self.query_days = StringVar(value="30")
        Entry(inner_query, textvariable=self.query_days, width=8, font=('Segoe UI', 9)).grid(row=0, column=5, padx=(10,15), pady=5)

        Button(inner_query, text="🔎 Search", command=self.run_query,
               bg='#0078d4', fg='white', font=self.button_font, relief='flat', padx=20).grid(row=0, column=6, padx=10, pady=5)

        # Geographic reports
        f_geo = LabelFrame(tab, text="🌍 Geographic Intelligence")
        f_geo.pack(fill=X, padx=15, pady=10)

        inner_geo = Frame(f_geo, bg='#f8f9fa')
        inner_geo.pack(fill=X, padx=10, pady=10)

        Label(inner_geo, text="📂 Case (optional):", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        self.geo_case = StringVar()
        ttk.Combobox(inner_geo, textvariable=self.geo_case, values=self._list_cases(), width=30, font=('Segoe UI', 9)).pack(side=LEFT, padx=(0,20))

        Button(inner_geo, text="📊 Generate Report", command=self.generate_geo_report,
               bg='#28a745', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=10)
        Button(inner_geo, text="📈 Show Statistics", command=self.show_geo_stats,
               bg='#17a2b8', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=10)

        # Victim database
        f_db = LabelFrame(tab, text="👥 Victim Intelligence Database")
        f_db.pack(fill=BOTH, expand=True, padx=15, pady=10)

        db_controls = Frame(f_db, bg='#f8f9fa')
        db_controls.pack(fill=X, padx=10, pady=5)

        Button(db_controls, text="👀 Show Latest Victims", command=self.show_last_victim,
               bg='#6f42c1', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(db_controls, text="💾 Export All to JSON", command=self.export_victims,
               bg='#e83e8c', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(db_controls, text="🔢 Count Victims", command=self.count_victims,
               bg='#fd7e14', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)

        inner_db = Frame(f_db, bg='#f8f9fa')
        inner_db.pack(fill=BOTH, expand=True, padx=10, pady=(5,10))

        Label(inner_db, text="📊 Database Results:", bg='#f8f9fa', font=self.title_font).pack(anchor=NW)
        self.db_text = scrolledtext.ScrolledText(inner_db, height=12, font=('Consolas', 9),
                                                bg='#ffffff', fg='#2c3e50', insertbackground='#0078d4')
        self.db_text.pack(fill=BOTH, expand=True, pady=(5,0))

    def create_tools_tab(self):
        tab = Frame(self.notebook, bg='#f8f9fa')
        self.notebook.add(tab, text="🔧 Tools")

        # Detonation section
        f_det = LabelFrame(tab, text="💣 URL Detonation")
        f_det.pack(fill=X, padx=15, pady=10)

        inner_det = Frame(f_det, bg='#f8f9fa')
        inner_det.pack(fill=X, padx=10, pady=10)

        Label(inner_det, text="🔗 URL:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=0, sticky=W, pady=5)
        self.det_url = StringVar()
        Entry(inner_det, textvariable=self.det_url, width=40, font=('Segoe UI', 9)).grid(row=0, column=1, padx=(10,15), pady=5)

        Label(inner_det, text="📂 Case:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=2, sticky=W, pady=5)
        self.det_case = StringVar()
        ttk.Combobox(inner_det, textvariable=self.det_case, values=self._list_cases(), width=20, font=('Segoe UI', 9)).grid(row=0, column=3, padx=(10,15), pady=5)

        Label(inner_det, text="⏱️ Timeout:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=4, sticky=W, pady=5)
        self.det_timeout = StringVar(value="35")
        Entry(inner_det, textvariable=self.det_timeout, width=8, font=('Segoe UI', 9)).grid(row=0, column=5, padx=(10,15), pady=5)

        Button(inner_det, text="🚀 Detonate", command=self.run_detonation,
               bg='#dc3545', fg='white', font=self.button_font, relief='flat', padx=20).grid(row=0, column=6, padx=10, pady=5)

        # Deobfuscation section
        f_deob = LabelFrame(tab, text="🔓 Content Deobfuscation")
        f_deob.pack(fill=BOTH, expand=True, padx=15, pady=10)

        deob_controls = Frame(f_deob, bg='#f8f9fa')
        deob_controls.pack(fill=X, padx=10, pady=5)

        Label(deob_controls, text="📝 Input type:", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        self.deob_type = StringVar(value="text")
        ttk.Combobox(deob_controls, textvariable=self.deob_type, width=12,
                     values=["text", "file", "url"], font=('Segoe UI', 9)).pack(side=LEFT, padx=(0,20))

        Label(deob_controls, text="📄 Content:", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        self.deob_content = StringVar()
        Entry(deob_controls, textvariable=self.deob_content, width=30, font=('Segoe UI', 9)).pack(side=LEFT, padx=(0,10))
        Button(deob_controls, text="📂 Browse File", command=self.browse_deob_file,
               bg='#6c757d', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=10)
        Button(deob_controls, text="🔍 Analyze", command=self.run_deobfuscation,
               bg='#0078d4', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=10)

        inner_deob = Frame(f_deob, bg='#f8f9fa')
        inner_deob.pack(fill=BOTH, expand=True, padx=10, pady=(5,10))

        Label(inner_deob, text="📋 Analysis Results:", bg='#f8f9fa', font=self.title_font).pack(anchor=NW)
        self.deob_text = scrolledtext.ScrolledText(inner_deob, height=15, font=('Consolas', 9),
                                                  bg='#ffffff', fg='#2c3e50', insertbackground='#0078d4')
        self.deob_text.pack(fill=BOTH, expand=True, pady=(5,0))

    def create_geographic_tab(self):
        """Geographic Intelligence & Victim Analysis Tab"""
        tab = Frame(self.notebook, bg='#f8f9fa')
        self.notebook.add(tab, text="🌍 Geographic")

        # Victim Analysis Section
        f_analysis = LabelFrame(tab, text="🔬 Victim IP Analysis")
        f_analysis.pack(fill=X, padx=15, pady=10)

        inner_analysis = Frame(f_analysis, bg='#f8f9fa')
        inner_analysis.pack(fill=X, padx=10, pady=10)

        Label(inner_analysis, text="📂 Case (optional):", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        self.geo_case_var = StringVar()
        ttk.Combobox(inner_analysis, textvariable=self.geo_case_var, values=['All Cases'] + self._list_cases(), 
                    width=25, font=('Segoe UI', 9)).pack(side=LEFT, padx=(0,20))
        self.geo_case_var.set('All Cases')

        Button(inner_analysis, text="🔍 Analyze Victims", command=self.analyze_victims_geographic,
               bg='#0078d4', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(inner_analysis, text="📊 Show Stats", command=self.show_geographic_stats,
               bg='#17a2b8', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(inner_analysis, text="🚨 Identify Attackers", command=self.identify_attackers,
               bg='#dc3545', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)

        # Report Generation Section
        f_reports = LabelFrame(tab, text="📄 Report Generation")
        f_reports.pack(fill=X, padx=15, pady=10)

        inner_reports = Frame(f_reports, bg='#f8f9fa')
        inner_reports.pack(fill=X, padx=10, pady=10)

        Label(inner_reports, text="📋 Format:", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        self.geo_format_var = StringVar(value="html")
        ttk.Combobox(inner_reports, textvariable=self.geo_format_var, values=['html', 'json', 'both'], 
                    width=10, font=('Segoe UI', 9), state='readonly').pack(side=LEFT, padx=(0,20))

        Button(inner_reports, text="📊 Generate Report", command=self.generate_geographic_report,
               bg='#28a745', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(inner_reports, text="📂 Open Reports Folder", command=self.open_reports_folder,
               bg='#6c757d', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)

        # Statistics Display
        f_stats = LabelFrame(tab, text="📈 Geographic Statistics")
        f_stats.pack(fill=BOTH, expand=True, padx=15, pady=10)

        inner_stats = Frame(f_stats, bg='#f8f9fa')
        inner_stats.pack(fill=BOTH, expand=True, padx=10, pady=10)

        self.geo_text = scrolledtext.ScrolledText(inner_stats, height=20, font=('Consolas', 9),
                                                  bg='#ffffff', fg='#2c3e50', insertbackground='#0078d4')
        self.geo_text.pack(fill=BOTH, expand=True)

    def create_monitoring_tab(self):
        tab = Frame(self.notebook, bg='#f8f9fa')
        self.notebook.add(tab, text="📊 Monitoring")

        # Canary controls
        f_canary = LabelFrame(tab, text="🐦 Canary Server")
        f_canary.pack(fill=X, padx=15, pady=10)

        inner_canary = Frame(f_canary, bg='#f8f9fa')
        inner_canary.pack(fill=X, padx=10, pady=10)

        Label(inner_canary, text="🔌 Local Port:", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        self.port_var = StringVar(value="8081")
        Entry(inner_canary, textvariable=self.port_var, width=8, font=('Segoe UI', 9)).pack(side=LEFT, padx=(0,20))

        Button(inner_canary, text="▶️ Start Canary", command=self.start_canary,
               bg='#28a745', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(inner_canary, text="⏹️ Stop Canary", command=self.stop_canary,
               bg='#dc3545', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)

        # Tunnel controls - AUTO NGROK
        f_tunnel = LabelFrame(tab, text="🌐 Public Tunnel (Ngrok/Cloudflare)")
        f_tunnel.pack(fill=X, padx=15, pady=10)

        inner_tunnel = Frame(f_tunnel, bg='#f8f9fa')
        inner_tunnel.pack(fill=X, padx=10, pady=10)

        Label(inner_tunnel, text="🔌 Canary Port:", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        Label(inner_tunnel, textvariable=self.port_var, bg='#f8f9fa', fg='#0078d4', 
              font=('Segoe UI', 9, 'bold')).pack(side=LEFT, padx=(0,20))

        Label(inner_tunnel, text="🌐 Tunnel Type:", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        self.tunnel_type_var = StringVar(value="ngrok")
        ttk.Combobox(inner_tunnel, textvariable=self.tunnel_type_var, values=['ngrok', 'cloudflared', 'localtunnel'], 
                    width=12, font=('Segoe UI', 9), state='readonly').pack(side=LEFT, padx=(0,20))

        Button(inner_tunnel, text="🚀 Auto Start Tunnel", command=self.auto_start_tunnel,
               bg='#28a745', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(inner_tunnel, text="⏹️ Stop Tunnel", command=self.stop_tunnel,
               bg='#dc3545', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        
        # Public URL display
        inner_tunnel2 = Frame(f_tunnel, bg='#f8f9fa')
        inner_tunnel2.pack(fill=X, padx=10, pady=(0,10))
        
        Label(inner_tunnel2, text="🔗 Public URL:", bg='#f8f9fa', font=self.title_font).pack(side=LEFT, padx=(0,10))
        self.public_url_var = StringVar(value="Not started")
        Entry(inner_tunnel2, textvariable=self.public_url_var, width=50, font=('Segoe UI', 9), 
              state='readonly', fg='#0078d4').pack(side=LEFT, padx=(0,10), fill=X, expand=True)
        Button(inner_tunnel2, text="📋 Copy", command=self.copy_public_url,
               bg='#6c757d', fg='white', font=self.button_font, relief='flat', padx=10).pack(side=LEFT, padx=5)
        Button(inner_tunnel2, text="🔍 Test", command=self.test_public_url,
               bg='#17a2b8', fg='white', font=self.button_font, relief='flat', padx=10).pack(side=LEFT, padx=5)

        self.email_btn = Button(inner_tunnel, text="📧 Email: OFF", command=self.toggle_email,
                               bg='#6c757d', fg='white', font=self.button_font, relief='flat', padx=15)
        self.email_btn.pack(side=LEFT, padx=15)

        # Sentinel Monitor controls
        f_sentinel = LabelFrame(tab, text="🤖 Sentinel Monitor")
        f_sentinel.pack(fill=X, padx=15, pady=10)

        inner_sentinel = Frame(f_sentinel, bg='#f8f9fa')
        inner_sentinel.pack(fill=X, padx=10, pady=10)

        # Monitor control buttons
        Button(inner_sentinel, text="▶️ Start Monitor", command=self.start_sentinel_monitor,
               bg='#28a745', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(inner_sentinel, text="⏹️ Stop Monitor", command=self.stop_sentinel_monitor,
               bg='#dc3545', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(inner_sentinel, text="📊 Status", command=self.show_monitor_status,
               bg='#17a2b8', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)

        # Monitor status display
        Label(inner_sentinel, textvariable=self.monitor_status_var, bg='#f8f9fa', fg='#2c3e50',
              font=('Segoe UI', 9, 'bold')).pack(side=RIGHT, padx=10)

        # Real-time Dashboard
        f_dashboard = LabelFrame(tab, text="📊 Real-Time Dashboard")
        f_dashboard.pack(fill=X, padx=15, pady=10)

        inner_dashboard = Frame(f_dashboard, bg='#f8f9fa')
        inner_dashboard.pack(fill=X, padx=10, pady=10)

        # Stats display
        stats_frame = Frame(inner_dashboard, bg='#f8f9fa')
        stats_frame.pack(fill=X, pady=5)

        # Row 1: Campaigns & Victims
        Label(stats_frame, text="🎯 Active Campaigns:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=0, sticky=W, padx=10, pady=3)
        self.stats_campaigns_var = StringVar(value="0")
        Label(stats_frame, textvariable=self.stats_campaigns_var, bg='#f8f9fa', fg='#0078d4', 
              font=('Segoe UI', 11, 'bold')).grid(row=0, column=1, sticky=W, pady=3)

        Label(stats_frame, text="👥 Total Victims:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=2, sticky=W, padx=10, pady=3)
        self.stats_victims_var = StringVar(value="0")
        Label(stats_frame, textvariable=self.stats_victims_var, bg='#f8f9fa', fg='#28a745', 
              font=('Segoe UI', 11, 'bold')).grid(row=0, column=3, sticky=W, pady=3)

        # Row 2: Attackers & Alerts
        Label(stats_frame, text="🚨 Attackers:", bg='#f8f9fa', font=self.title_font).grid(row=1, column=0, sticky=W, padx=10, pady=3)
        self.stats_attackers_var = StringVar(value="0")
        Label(stats_frame, textvariable=self.stats_attackers_var, bg='#f8f9fa', fg='#dc3545', 
              font=('Segoe UI', 11, 'bold')).grid(row=1, column=1, sticky=W, pady=3)

        Label(stats_frame, text="⚠️ Recent Alerts (24h):", bg='#f8f9fa', font=self.title_font).grid(row=1, column=2, sticky=W, padx=10, pady=3)
        self.stats_alerts_var = StringVar(value="0")
        Label(stats_frame, textvariable=self.stats_alerts_var, bg='#f8f9fa', fg='#ffc107', 
              font=('Segoe UI', 11, 'bold')).grid(row=1, column=3, sticky=W, pady=3)

        # Refresh button
        Button(inner_dashboard, text="🔄 Refresh Stats", command=self.refresh_dashboard_stats,
               bg='#17a2b8', fg='white', font=self.button_font, relief='flat', padx=15).pack(pady=10)

        # Auto-refresh checkbox
        self.auto_refresh_var = BooleanVar(value=False)
        ttk.Checkbutton(inner_dashboard, text="Auto-refresh every 30 seconds", 
                       variable=self.auto_refresh_var, command=self.toggle_auto_refresh).pack()

        # Campaign management
        f_campaign = LabelFrame(tab, text="🎯 Campaign Management")
        f_campaign.pack(fill=X, padx=15, pady=10)

        inner_campaign = Frame(f_campaign, bg='#f8f9fa')
        inner_campaign.pack(fill=X, padx=10, pady=10)

        Label(inner_campaign, text="📂 Case:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=0, sticky=W, pady=5)
        self.monitor_case = StringVar()
        ttk.Combobox(inner_campaign, textvariable=self.monitor_case, values=self._list_cases(), width=25, font=('Segoe UI', 9)).grid(row=0, column=1, padx=(10,15), pady=5)

        Label(inner_campaign, text="🔗 URL:", bg='#f8f9fa', font=self.title_font).grid(row=0, column=2, sticky=W, pady=5)
        self.monitor_url = StringVar()
        Entry(inner_campaign, textvariable=self.monitor_url, width=30, font=('Segoe UI', 9)).grid(row=0, column=3, padx=(10,15), pady=5)

        Button(inner_campaign, text="➕ Add Campaign", command=self.add_monitor_campaign,
               bg='#0078d4', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=0, column=4, padx=5, pady=5)
        Button(inner_campaign, text="📋 List Campaigns", command=self.list_monitor_campaigns,
               bg='#6c757d', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=0, column=5, padx=5, pady=5)

        # Remove campaign section
        Label(inner_campaign, text="🗑️ Remove by ID:", bg='#f8f9fa', font=self.title_font).grid(row=1, column=0, sticky=W, pady=5)
        self.remove_campaign_id = StringVar()
        Entry(inner_campaign, textvariable=self.remove_campaign_id, width=25, font=('Segoe UI', 9)).grid(row=1, column=1, padx=(10,15), pady=5)
        Button(inner_campaign, text="➖ Remove Campaign", command=self.remove_monitor_campaign,
               bg='#dc3545', fg='white', font=self.button_font, relief='flat', padx=15).grid(row=1, column=4, padx=5, pady=5)

        # Live monitoring
        f_monitor = LabelFrame(tab, text="📡 Live Monitoring")
        f_monitor.pack(fill=BOTH, expand=True, padx=15, pady=10)

        monitor_controls = Frame(f_monitor, bg='#f8f9fa')
        monitor_controls.pack(fill=X, padx=10, pady=5)

        Button(monitor_controls, text="👁️ Start Live Tail", command=self.start_live_tail,
               bg='#0078d4', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(monitor_controls, text="⏸️ Stop Live Tail", command=self.stop_live_tail,
               bg='#ffc107', fg='#212529', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(monitor_controls, text="🔄 Refresh Hits", command=self.refresh_hits,
               bg='#28a745', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)
        Button(monitor_controls, text="🖱️ Simulate Click", command=self.simulate_local_click,
               bg='#e83e8c', fg='white', font=self.button_font, relief='flat', padx=15).pack(side=LEFT, padx=5)

        inner_monitor = Frame(f_monitor, bg='#f8f9fa')
        inner_monitor.pack(fill=BOTH, expand=True, padx=10, pady=(5,10))

        Label(inner_monitor, text="📋 Live Output:", bg='#f8f9fa', font=self.title_font).pack(anchor=NW)
        self.monitor_text = scrolledtext.ScrolledText(inner_monitor, height=20, font=('Consolas', 9),
                                                     bg='#ffffff', fg='#2c3e50', insertbackground='#0078d4')
        self.monitor_text.pack(fill=BOTH, expand=True, pady=(5,0))

    # ----------------- Analysis methods -----------------
    def browse_analysis_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Email files", "*.eml"), ("All files", "*.*")])
        if filename:
            self.analysis_file_var.set(filename)

    def browse_analysis_dir(self):
        dirname = filedialog.askdirectory()
        if dirname:
            self.analysis_file_var.set(dirname)

    def run_analysis(self):
        file_path = self.analysis_file_var.get().strip()
        if not file_path:
            messagebox.showerror("Error", "Please select a file or directory")
            return

        # Always use forensic analysis
        cmd = [sys.executable, '-m', 'paw', 'forensic', file_path, '--lang', 'en']
        if self.stix_var.get():
            cmd.append('--stix')
        if self.abuse_var.get():
            cmd.append('--abuse')
        if self.no_egress_var.get():
            cmd.append('--no-egress')

        self._run_command(cmd, self.analysis_text, "Analysis")

    def stop_analysis(self):
        """Stop the currently running analysis"""
        if hasattr(self, 'current_process') and self.current_process:
            try:
                self.status_var.set("Stopping analysis...")
                self.current_process.terminate()
                try:
                    self.current_process.wait(timeout=5)  # Give it 5 seconds to terminate gracefully
                except subprocess.TimeoutExpired:
                    self.current_process.kill()  # Force kill if it doesn't terminate
                
                def update_stopped():
                    self.analysis_text.insert(END, "\n⏹️ Analysis stopped by user\n")
                    self.analysis_text.see(END)
                    self.status_var.set("Analysis stopped")
                    # Re-enable run button, disable stop button
                    if hasattr(self, 'run_analysis_btn'):
                        self.run_analysis_btn.config(state='normal')
                    if hasattr(self, 'stop_analysis_btn'):
                        self.stop_analysis_btn.config(state='disabled')
                
                self.root.after(0, update_stopped)
                self.current_process = None
                
            except Exception as e:
                self.status_var.set(f"Error stopping analysis: {e}")
        else:
            messagebox.showinfo("Info", "No analysis is currently running")

    # ----------------- Case methods -----------------
    def verify_case(self):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showerror("Error", "Please select a case")
            return

        cmd = [sys.executable, '-m', 'paw', 'verify', '--case', case]
        self._run_command(cmd, self.case_text, "Case Verification")

    def export_case(self):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showerror("Error", "Please select a case")
            return

        cmd = [sys.executable, '-m', 'paw', 'export', '--case', case, '--format', 'zip']
        self._run_command(cmd, self.case_text, "Case Export")

    def update_case(self):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showerror("Error", "Please select a case")
            return

        cmd = [sys.executable, '-m', 'paw', 'update', '--case', case]
        self._run_command(cmd, self.case_text, "Case Update")

    def show_headers_urls(self):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showerror("Error", "Please select a case")
            return

        case_dir = Path('cases') / case
        headers_file = case_dir / 'headers.json'
        urls_file = case_dir / 'urls.json'

        output = f"Case: {case}\n\n"

        if headers_file.exists():
            try:
                headers = json.loads(headers_file.read_text())
                output += "Headers:\n" + json.dumps(headers, indent=2) + "\n\n"
            except Exception as e:
                output += f"Error reading headers: {e}\n\n"

        if urls_file.exists():
            try:
                urls = json.loads(urls_file.read_text())
                output += "URLs:\n" + json.dumps(urls, indent=2)
            except Exception as e:
                output += f"Error reading URLs: {e}"

        self.case_text.delete('1.0', END)
        self.case_text.insert(END, output)

    # ----------------- Intelligence methods -----------------
    def run_query(self):
        query_type = self.query_type.get()
        value = self.query_value.get().strip()
        days = self.query_days.get().strip()

        if not value:
            messagebox.showerror("Error", "Please enter a query value")
            return

        cmd = [sys.executable, '-m', 'paw', 'query', '--by', query_type, '--value', value, '--days', days]
        self._run_command(cmd, self.db_text, "Query")

    def generate_geo_report(self):
        case = self.geo_case.get().strip()
        cmd = [sys.executable, '-m', 'paw', 'geographic', 'report']
        if case:
            cmd.extend(['--case', case])
        cmd.append('--output')
        cmd.append('both')
        self._run_command(cmd, self.db_text, "Geographic Report")

    def show_geo_stats(self):
        case = self.geo_case.get().strip()
        cmd = [sys.executable, '-m', 'paw', 'geographic', 'stats']
        if case:
            cmd.extend(['--case', case])
        self._run_command(cmd, self.db_text, "Geographic Stats")

    def count_victims(self):
        if CampaignDatabase is None:
            self.db_text.delete('1.0', END)
            self.db_text.insert(END, 'CampaignDatabase not available')
            return

        try:
            db = CampaignDatabase()
            victims = db.get_victim_intelligence()
            count = len(victims)
            self.db_text.delete('1.0', END)
            self.db_text.insert(END, f'Total victims in database: {count}')
        except Exception as e:
            self.db_text.delete('1.0', END)
            self.db_text.insert(END, f'Error: {e}')

    # ----------------- Tools methods -----------------
    def run_detonation(self):
        url = self.det_url.get().strip()
        case = self.det_case.get().strip()
        timeout = self.det_timeout.get().strip()

        if not url and not case:
            messagebox.showerror("Error", "Please provide either a URL or select a case")
            return

        cmd = [sys.executable, '-m', 'paw', 'detonate', '--timeout', timeout]
        if url:
            cmd.extend(['--url', url])
        if case:
            cmd.extend(['--case', case])

        self._run_command(cmd, self.deob_text, "Detonation")

    def browse_deob_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.deob_content.set(filename)

    def run_deobfuscation(self):
        content_type = self.deob_type.get()
        content = self.deob_content.get().strip()

        if not content:
            messagebox.showerror("Error", "Please provide content to analyze")
            return

        cmd = [sys.executable, '-m', 'paw', 'deobfuscate']
        if content_type == 'text':
            cmd.extend(['--text', content])
        elif content_type == 'file':
            cmd.extend(['--file', content])
        elif content_type == 'url':
            cmd.extend(['--url', content])

        self._run_command(cmd, self.deob_text, "Deobfuscation")

    # ----------------- Monitoring methods -----------------
    def start_canary(self):
        if self.canary_proc and self.canary_proc.poll() is None:
            self._log('🐦 Canary already running')
            return
        case = self.case_var.get().strip()
        port = self.port_var.get().strip()
        if not case or not port:
            self._log('⚠️ Provide case and port')
            return
        py = sys.executable
        cmd = [py, '-m', 'paw', 'canary', '--case', case, '--port', port]
        self._log(f'🚀 Starting canary: {cmd}')
        try:
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'  # Force UTF-8 encoding
            if not self.email_enabled:
                env.pop('PAW_SMTP_USER', None)
                env.pop('PAW_SMTP_PASS', None)
            self.canary_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', env=env, cwd=os.getcwd())
            threading.Thread(target=self._read_proc_output, args=(self.canary_proc, self.monitor_text), daemon=True).start()
        except Exception as e:
            self._log(f'❌ Failed to start canary: {e}')

    def stop_canary(self):
        if not self.canary_proc:
            self._log('ℹ️ No canary process')
            return
        try:
            self.canary_proc.terminate()
            self._log('⏹️ Sent terminate to canary process')
        except Exception as e:
            self._log(f'❌ Error stopping canary: {e}')

    def start_tunnel(self):
        if self.tunnel_proc and self.tunnel_proc.poll() is None:
            self._log('🌐 Tunnel already running')
            return
        port = self.tunnel_port_var.get().strip()
        canary_port = self.port_var.get().strip()

        # Check for port conflict
        if port == canary_port and self.canary_proc and self.canary_proc.poll() is None:
            messagebox.showwarning("Port Conflict",
                f"Tunnel port {port} conflicts with running canary server on port {canary_port}.\n\n"
                "Please use a different port for the tunnel service.")
            return

        template = self.tunnel_cmd.get().strip()
        cmd_str = template.format(port=port) if '{port}' in template else f"{template} {port}"
        self._log(f'🚀 Starting tunnel: {cmd_str}')
        try:
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'  # Force UTF-8 encoding
            self.tunnel_proc = subprocess.Popen(cmd_str, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', shell=True, env=env, cwd=os.getcwd())
            threading.Thread(target=self._read_proc_output, args=(self.tunnel_proc, self.monitor_text), daemon=True).start()
        except Exception as e:
            self._log(f'❌ Failed to start tunnel: {e}')

    def stop_tunnel(self):
        if not self.tunnel_proc:
            self._log('ℹ️ No tunnel process')
            return
        try:
            self.tunnel_proc.terminate()
            self.public_url_var.set("Not started")
            self._log('⏹️ Sent terminate to tunnel process')
        except Exception as e:
            self._log(f'❌ Error stopping tunnel: {e}')

    def auto_start_tunnel(self):
        """Auto-start tunnel with ngrok/cloudflared"""
        if self.tunnel_proc and self.tunnel_proc.poll() is None:
            self._log('🌐 Tunnel already running')
            return

        canary_port = self.port_var.get().strip()
        tunnel_type = self.tunnel_type_var.get()

        if not canary_port:
            messagebox.showerror("Error", "Please set canary port first")
            return

        # Check if canary is running
        if not self.canary_proc or self.canary_proc.poll() is not None:
            messagebox.showwarning("Warning", 
                "Canary server is not running!\n\n"
                "Please start the canary server first, then start the tunnel.")
            return

        self._log(f'🚀 Starting {tunnel_type} tunnel for port {canary_port}...')
        
        try:
            if tunnel_type == 'ngrok':
                cmd = ['ngrok', 'http', canary_port]
            elif tunnel_type == 'cloudflared':
                cmd = ['cloudflared', 'tunnel', '--url', f'http://localhost:{canary_port}']
            elif tunnel_type == 'localtunnel':
                cmd = ['npx', 'localtunnel', '--port', canary_port]
            else:
                raise ValueError(f"Unknown tunnel type: {tunnel_type}")

            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'  # Force UTF-8 encoding
            self.tunnel_proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                encoding='utf-8',
                errors='replace',
                env=env, 
                cwd=os.getcwd()
            )
            
            # Start thread to read output and extract public URL
            threading.Thread(target=self._read_tunnel_output, args=(self.tunnel_proc,), daemon=True).start()
            
            self._log(f'✅ {tunnel_type} tunnel started successfully')
            messagebox.showinfo("Success", 
                f"{tunnel_type} tunnel started!\n\n"
                f"Watch the monitor output for the public URL.")
            
        except FileNotFoundError:
            messagebox.showerror("Error", 
                f"{tunnel_type} not found!\n\n"
                f"Please install it first:\n"
                f"• ngrok: https://ngrok.com/download\n"
                f"• cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/\n"
                f"• localtunnel: npm install -g localtunnel")
        except Exception as e:
            self._log(f'❌ Failed to start tunnel: {e}')
            messagebox.showerror("Error", f"Failed to start tunnel: {e}")

    def _read_tunnel_output(self, proc):
        """Read tunnel output and extract public URL"""
        import re
        try:
            for line in proc.stdout:
                if not line:
                    break
                
                ts = time.strftime('%H:%M:%S')
                self.monitor_text.insert(END, f'[{ts}] {line.rstrip()}\n')
                self.monitor_text.see(END)
                
                # Extract public URL from different tunnel services
                url = None
                
                # ngrok: Forwarding https://abc123.ngrok.io -> http://localhost:8787
                ngrok_match = re.search(r'https://[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app)', line)
                if ngrok_match:
                    url = ngrok_match.group(0)
                
                # cloudflared: https://abc123.trycloudflare.com
                cf_match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', line)
                if cf_match:
                    url = cf_match.group(0)
                
                # localtunnel: your url is: https://abc123.loca.lt
                lt_match = re.search(r'https://[a-z0-9-]+\.loca\.lt', line)
                if lt_match:
                    url = lt_match.group(0)
                
                if url:
                    def update_url():
                        self.public_url_var.set(url)
                        self._log(f'✅ Public URL ready: {url}')
                        messagebox.showinfo("Tunnel Ready", 
                            f"🌐 Public URL:\n\n{url}\n\n"
                            f"Share this URL to track phishing clicks!")
                    self.root.after(0, update_url)
                    
        except Exception as e:
            ts = time.strftime('%H:%M:%S')
            self.monitor_text.insert(END, f'[{ts}] Error reading tunnel output: {e}\n')

    def copy_public_url(self):
        """Copy public URL to clipboard"""
        url = self.public_url_var.get()
        if url == "Not started":
            messagebox.showwarning("Warning", "No tunnel running")
            return
        
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            self.root.update()
            messagebox.showinfo("Copied", f"URL copied to clipboard:\n{url}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {e}")

    def test_public_url(self):
        """Test public URL in browser"""
        url = self.public_url_var.get()
        if url == "Not started":
            messagebox.showwarning("Warning", "No tunnel running")
            return
        
        try:
            import webbrowser
            webbrowser.open(url)
            self._log(f'🔍 Opened {url} in browser')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open URL: {e}")

    def start_live_tail(self):
        if self._tail_thread and self._tail_thread.is_alive():
            self._log('👁️ Live tail already running')
            return
        case = self.case_var.get().strip()
        if not case:
            self._log('⚠️ Select a case first')
            return
        self._stop_read = False
        self._tail_thread = threading.Thread(target=self._live_tail_worker, daemon=True)
        self._tail_thread.start()
        self._log('👁️ Started live tail')

    def stop_live_tail(self):
        self._stop_read = True
        self._log('⏸️ Stopped live tail')

    def _live_tail_worker(self):
        case = self.case_var.get().strip()
        hits_path = Path('cases') / case / 'canary' / 'hits.jsonl'
        if not hits_path.exists():
            self._log(f'❌ Hits file does not exist: {hits_path}')
            return

        try:
            with open(hits_path, 'r', encoding='utf-8') as f:
                f.seek(0, 2)  # Go to end
                while not self._stop_read:
                    line = f.readline()
                    if line:
                        self._log(f'🎯 HIT: {line.strip()}')
                    else:
                        time.sleep(1)
        except Exception as e:
            self._log(f'❌ Error in live tail: {e}')

    def refresh_hits(self):
        case = self.case_var.get().strip()
        if not case:
            self._log('⚠️ Set case to refresh hits')
            return
        hits_path = Path('cases') / case / 'canary' / 'hits.jsonl'
        if not hits_path.exists():
            self._log(f'❌ No hits file: {hits_path}')
            return
        try:
            lines = hits_path.read_text(encoding='utf-8').splitlines()
            self._log(f'📊 Last {min(20,len(lines))} hits:')
            for l in lines[-20:]:
                self._log(l)
        except Exception as e:
            self._log(f'❌ Error reading hits: {e}')

    def simulate_local_click(self):
        port = self.port_var.get().strip()
        if not port:
            self._log('⚠️ Set port first')
            return
        url = f'http://localhost:{port}/'
        if requests:
            try:
                resp = requests.get(url, timeout=5)
                self._log(f'🖱️ Simulated click: {resp.status_code}')
            except Exception as e:
                self._log(f'❌ Error simulating click: {e}')
        else:
            self._log('⚠️ requests not available for simulation')

    # ----------------- Shared utility methods -----------------
    def _list_cases(self):
        p = Path('cases')
        if not p.exists():
            return []
        return sorted([d.name for d in p.iterdir() if d.is_dir()])

    def refresh_cases(self):
        vals = self._list_cases()
        self.cases_combo['values'] = vals
        if vals:
            self.cases_combo.set(vals[0])
            self.case_var.set(vals[0])
        self._log(f'📂 Found {len(vals)} cases')

    def _log(self, msg):
        ts = time.strftime('%H:%M:%S')
        try:
            self.monitor_text.insert(END, f'[{ts}] {msg}\n')
            self.monitor_text.see(END)
        except Exception:
            pass

    def _run_command(self, cmd, text_widget, operation_name):
        """Run a command in a separate thread with real-time output"""
        self.status_var.set(f"Running {operation_name}...")
        text_widget.insert(END, "Running: {' '.join(cmd)}\n\n")
        text_widget.insert(END, "⚠️ Note: PAW's detailed progress output is not shown in GUI.\n")
        text_widget.insert(END, "   Use terminal for full output (example): paw analyze --lang da file.eml\n")
        text_widget.insert(END, "   Note: `paw quick` is a fast preset and does NOT accept --lang. Use `paw analyze` to pass language.\n\n")
        text_widget.insert(END, "⏳ Starting analysis process...\n")
        text_widget.see(END)
        
        # Disable the run button, enable stop button
        if operation_name == "Analysis":
            if hasattr(self, 'run_analysis_btn'):
                self.run_analysis_btn.config(state='disabled')
            if hasattr(self, 'stop_analysis_btn'):
                self.stop_analysis_btn.config(state='normal')
        
        def run_in_thread():
            try:
                # Use Popen for real-time output
                # Adjust timeout based on analysis type
                if operation_name == "Analysis":
                    if "quick" in cmd:
                        timeout_seconds = 60  # 1 minute for quick analysis
                    elif "forensic" in cmd:
                        timeout_seconds = 900  # 15 minutes for forensic
                    else:
                        timeout_seconds = 600  # 10 minutes for full analysis (increased for testing)
                else:
                    timeout_seconds = 60
                # Force UTF-8 encoding to handle Unicode characters (fixes 'charmap' codec errors on Windows)
                env = os.environ.copy()
                env['PYTHONIOENCODING'] = 'utf-8'
                
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True, 
                    encoding='utf-8',
                    errors='replace',  # Replace characters that can't be decoded instead of crashing
                    cwd=os.getcwd(),
                    bufsize=1,  # Line buffered
                    universal_newlines=True,
                    env=env
                )
                
                # Save reference to current process for stopping
                if operation_name == "Analysis":
                    self.current_process = process
                
                def update_status(msg):
                    def _update():
                        text_widget.insert(END, msg)
                        text_widget.see(END)
                    self.root.after(0, _update)
                
                update_status("✅ Process started successfully\n")
                update_status("📊 Reading output in real-time...\n\n")
                
                # Read output in real-time
                def read_output():
                    stdout_lines = 0
                    stderr_lines = 0
                    
                    while True:
                        # Read from stdout
                        output = process.stdout.readline()
                        if output:
                            stdout_lines += 1
                            def update_output():
                                text_widget.insert(END, f"[STDOUT] {output}")
                                text_widget.see(END)
                            self.root.after(0, update_output)
                        
                        # Read from stderr  
                        error = process.stderr.readline()
                        if error:
                            stderr_lines += 1
                            def update_error():
                                text_widget.insert(END, f"[STDERR] {error}")
                                text_widget.see(END)
                            self.root.after(0, update_error)
                        
                        # Check if process is done
                        if output == '' and error == '' and process.poll() is not None:
                            break
                        
                        # Small delay to prevent busy waiting
                        time.sleep(0.01)
                    
                    # Read any remaining output
                    remaining_stdout = process.stdout.read()
                    if remaining_stdout:
                        def update_remaining():
                            text_widget.insert(END, f"[STDOUT] {remaining_stdout}")
                            text_widget.see(END)
                        self.root.after(0, update_remaining)
                    
                    remaining_stderr = process.stderr.read()
                    if remaining_stderr:
                        def update_remaining_err():
                            text_widget.insert(END, f"[STDERR] {remaining_stderr}")
                            text_widget.see(END)
                        self.root.after(0, update_remaining_err)
                    
                    # Check return code and update status
                    return_code = process.poll()
                    def update_final_status():
                        text_widget.insert(END, f"\n📈 Analysis Summary:\n")
                        text_widget.insert(END, f"   • STDOUT lines: {stdout_lines}\n")
                        text_widget.insert(END, f"   • STDERR lines: {stderr_lines}\n")
                        text_widget.insert(END, f"   • Exit code: {return_code}\n\n")
                        
                        if return_code == 0:
                            self.status_var.set(f"{operation_name} completed successfully")
                            text_widget.insert(END, "✅ Analysis completed successfully!\n")
                        else:
                            self.status_var.set(f"{operation_name} failed (exit code {return_code})")
                            text_widget.insert(END, f"❌ Analysis failed with exit code {return_code}\n")
                        
                        # Re-enable run button, disable stop button
                        if operation_name == "Analysis":
                            if hasattr(self, 'run_analysis_btn'):
                                self.run_analysis_btn.config(state='normal')
                            if hasattr(self, 'stop_analysis_btn'):
                                self.stop_analysis_btn.config(state='disabled')
                            self.current_process = None
                    
                    self.root.after(0, update_final_status)
                
                # Start reading output in a separate thread
                output_thread = threading.Thread(target=read_output, daemon=True)
                output_thread.start()
                
                # Wait for process with timeout
                try:
                    process.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=5)  # Give it 5 seconds to terminate gracefully
                    except subprocess.TimeoutExpired:
                        process.kill()  # Force kill if it doesn't terminate
                    
                    def update_timeout():
                        text_widget.insert(END, f"\n⚠️ TIMEOUT: Command took longer than {timeout_seconds} seconds and was terminated.\n")
                        text_widget.insert(END, "This might indicate the analysis is taking too long or got stuck.\n")
                        text_widget.insert(END, "Try using 'quick' analysis or check the command manually in terminal.\n")
                        self.status_var.set(f"{operation_name} timed out")
                        # Re-enable run button, disable stop button
                        if operation_name == "Analysis":
                            if hasattr(self, 'run_analysis_btn'):
                                self.run_analysis_btn.config(state='normal')
                            if hasattr(self, 'stop_analysis_btn'):
                                self.stop_analysis_btn.config(state='disabled')
                            self.current_process = None
                    
                    self.root.after(0, update_timeout)
                
            except Exception as e:
                def update_error():
                    text_widget.insert(END, f"❌ Error running command: {e}\n")
                    text_widget.insert(END, f"Error type: {type(e).__name__}\n")
                    self.status_var.set(f"{operation_name} error")
                    # Re-enable run button, disable stop button
                    if operation_name == "Analysis":
                        if hasattr(self, 'run_analysis_btn'):
                            self.run_analysis_btn.config(state='normal')
                        if hasattr(self, 'stop_analysis_btn'):
                            self.stop_analysis_btn.config(state='disabled')
                        self.current_process = None
                
                self.root.after(0, update_error)
        
        # Start the command in a separate thread
        thread = threading.Thread(target=run_in_thread, daemon=True)
        thread.start()

    def _read_proc_output(self, proc, text_widget):
        try:
            for line in proc.stdout:
                if not line:
                    break
                ts = time.strftime('%H:%M:%S')
                text_widget.insert(END, f'[{ts}] {line.rstrip()}\n')
                text_widget.see(END)
        except Exception as e:
            ts = time.strftime('%H:%M:%S')
            text_widget.insert(END, f'[{ts}] Error reading proc output: {e}\n')

    def toggle_email(self):
        self.email_enabled = not self.email_enabled
        if self.email_enabled:
            self.email_btn.config(text="📧 Email: ON", bg='#28a745')
        else:
            self.email_btn.config(text="📧 Email: OFF", bg='#6c757d')

    # ----------------- DB methods -----------------
    def show_last_victim(self):
        if CampaignDatabase is None:
            self.db_text.delete('1.0', END)
            self.db_text.insert(END, 'CampaignDatabase not importable in this environment')
            return
        try:
            db = CampaignDatabase()
            victims = db.get_victim_intelligence()
            self.db_text.delete('1.0', END)
            if not victims:
                self.db_text.insert(END, 'No victims in DB')
                return
            last = victims[0]
            self.db_text.insert(END, json.dumps(last, indent=2, ensure_ascii=False))
        except Exception as e:
            self.db_text.delete('1.0', END)
            self.db_text.insert(END, f'Error reading DB: {e}')

    def export_victims(self):
        if CampaignDatabase is None:
            messagebox.showerror("Error", "Database not available")
            return

        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not filename:
            return

        try:
            db = CampaignDatabase()
            victims = db.get_victim_intelligence()
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(victims, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Success", f"Exported {len(victims)} victims to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

    def start_sentinel_monitor(self):
        """Start the Sentinel Monitor for continuous phishing campaign monitoring"""
        if self.sentinel_monitor is None:
            messagebox.showerror("Error", "Sentinel Monitor not available")
            return

        try:
            self.sentinel_monitor.start()
            messagebox.showinfo("Success", "Sentinel Monitor started successfully")
            self.show_monitor_status()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitor: {e}")

    def stop_sentinel_monitor(self):
        """Stop the Sentinel Monitor"""
        if self.sentinel_monitor is None:
            messagebox.showerror("Error", "Sentinel Monitor not available")
            return

        try:
            self.sentinel_monitor.stop()
            messagebox.showinfo("Success", "Sentinel Monitor stopped")
            self.show_monitor_status()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop monitor: {e}")

    def show_monitor_status(self):
        """Update the monitor status display"""
        if self.sentinel_monitor is None:
            self.monitor_status_var.set("Monitor: Not Available")
            return

        try:
            if self.sentinel_monitor.is_running():
                status = "Running"
            else:
                status = "Stopped"
            self.monitor_status_var.set(f"Monitor: {status}")
        except Exception as e:
            self.monitor_status_var.set(f"Monitor: Error - {e}")

    def add_monitor_campaign(self):
        """Add a new campaign to monitor"""
        if self.sentinel_monitor is None:
            messagebox.showerror("Error", "Sentinel Monitor not available")
            return

        case_id = self.monitor_case.get().strip()
        url = self.monitor_url.get().strip()
        
        if not case_id or not url:
            messagebox.showerror("Error", "Please select a case and enter a URL")
            return

        try:
            campaign_id = self.sentinel_monitor.add_campaign(case_id, url)
            messagebox.showinfo("Success", f"Campaign '{case_id}' added to monitoring")
            self.list_monitor_campaigns()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add campaign: {e}")

    def remove_monitor_campaign(self):
        """Remove a campaign from monitoring"""
        if self.sentinel_monitor is None:
            messagebox.showerror("Error", "Sentinel Monitor not available")
            return

        campaign_id = self.remove_campaign_id.get().strip()
        if not campaign_id:
            messagebox.showerror("Error", "Please enter a campaign ID to remove")
            return

        try:
            success = self.sentinel_monitor.remove_campaign(campaign_id)
            if success:
                messagebox.showinfo("Success", f"Campaign '{campaign_id}' removed from monitoring")
                self.remove_campaign_id.set("")  # Clear the field
            else:
                messagebox.showerror("Error", f"Campaign '{campaign_id}' not found")
            self.list_monitor_campaigns()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove campaign: {e}")

    def list_monitor_campaigns(self):
        """List all monitored campaigns"""
        if self.sentinel_monitor is None:
            self.monitor_text.delete('1.0', END)
            self.monitor_text.insert(END, "Sentinel Monitor not available")
            return

        try:
            campaigns = self.sentinel_monitor.get_all_campaigns()
            self.monitor_text.delete('1.0', END)
            if campaigns:
                self.monitor_text.insert(END, "Monitored Campaigns:\n\n")
                for campaign in campaigns:
                    campaign_id = campaign.get('id', 'Unknown')
                    case_id = campaign.get('case_id', 'Unknown')
                    url = campaign.get('url', 'Unknown')
                    status = campaign.get('status', 'Unknown')
                    self.monitor_text.insert(END, f"• ID: {campaign_id}\n  Case: {case_id}, URL: {url}, Status: {status}\n\n")
            else:
                self.monitor_text.insert(END, "No campaigns currently monitored")
        except Exception as e:
            self.monitor_text.delete('1.0', END)
            self.monitor_text.insert(END, f"Error listing campaigns: {e}")

    def refresh_dashboard_stats(self):
        """Refresh real-time dashboard statistics"""
        try:
            from paw.sentinel.database import CampaignDatabase
            db = CampaignDatabase()
            
            # Get campaigns
            campaigns = db.get_active_campaigns()
            self.stats_campaigns_var.set(str(len(campaigns)))
            
            # Get victims
            victims = db.get_victim_intelligence()
            self.stats_victims_var.set(str(len(victims)))
            
            # Count attackers (analyzed victims with risk >= 7)
            attackers = [v for v in victims if v.get('analyzed_status') == 'analyzed' and v.get('risk_score', 0) >= 7]
            self.stats_attackers_var.set(str(len(attackers)))
            
            # Count recent alerts (last 24h) - for now, show unanalyzed victims as pending alerts
            from datetime import datetime, timedelta
            cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
            recent_victims = [v for v in victims if v.get('created_at', '') > cutoff]
            self.stats_alerts_var.set(str(len(recent_victims)))
            
            self._log(f'📊 Dashboard stats refreshed: {len(campaigns)} campaigns, {len(victims)} victims, {len(attackers)} attackers')
            
        except Exception as e:
            self._log(f'❌ Error refreshing stats: {e}')

    def toggle_auto_refresh(self):
        """Toggle auto-refresh of dashboard stats"""
        if self.auto_refresh_var.get():
            self._start_auto_refresh()
        else:
            self._stop_auto_refresh()

    def _start_auto_refresh(self):
        """Start auto-refresh thread"""
        if not hasattr(self, '_auto_refresh_running') or not self._auto_refresh_running:
            self._auto_refresh_running = True
            threading.Thread(target=self._auto_refresh_worker, daemon=True).start()
            self._log('🔄 Auto-refresh enabled (30s interval)')

    def _stop_auto_refresh(self):
        """Stop auto-refresh thread"""
        self._auto_refresh_running = False
        self._log('⏸️ Auto-refresh disabled')

    def _auto_refresh_worker(self):
        """Worker thread for auto-refresh"""
        while self._auto_refresh_running:
            try:
                self.refresh_dashboard_stats()
            except Exception as e:
                self._log(f'❌ Auto-refresh error: {e}')
            time.sleep(30)  # Refresh every 30 seconds

    def show_monitor_hits(self):
        """Show recent monitoring hits"""
        if self.sentinel_monitor is None:
            self.monitor_text.delete('1.0', END)
            self.monitor_text.insert(END, "Sentinel Monitor not available")
            return

        try:
            hits = self.sentinel_monitor.get_recent_hits()
            self.monitor_text.delete('1.0', END)
            if hits:
                self.monitor_text.insert(END, "Recent Monitoring Hits:\n\n")
                for hit in hits:
                    self.monitor_text.insert(END, f"• {hit}\n")
            else:
                self.monitor_text.insert(END, "No recent hits")
        except Exception as e:
            self.monitor_text.delete('1.0', END)
            self.monitor_text.insert(END, f"Error getting hits: {e}")

    # ----------------- Geographic methods -----------------
    def analyze_victims_geographic(self):
        """Analyze victim IPs with geographic intelligence"""
        case = self.geo_case_var.get().strip()
        case_filter = None if case == 'All Cases' else case
        
        cmd = [sys.executable, '-m', 'paw', 'geographic', 'analyze']
        if case_filter:
            cmd.extend(['--case', case_filter])
        
        self.geo_text.delete('1.0', END)
        self.geo_text.insert(END, "🔍 Starting geographic analysis...\n\n")
        self._run_command(cmd, self.geo_text, "Geographic Analysis")

    def show_geographic_stats(self):
        """Show geographic statistics"""
        case = self.geo_case_var.get().strip()
        case_filter = None if case == 'All Cases' else case
        
        cmd = [sys.executable, '-m', 'paw', 'geographic', 'stats']
        if case_filter:
            cmd.extend(['--case', case_filter])
        
        self.geo_text.delete('1.0', END)
        self.geo_text.insert(END, "📊 Loading geographic statistics...\n\n")
        self._run_command(cmd, self.geo_text, "Geographic Stats")

    def identify_attackers(self):
        """Identify potential attackers from victim data"""
        case = self.geo_case_var.get().strip()
        case_filter = None if case == 'All Cases' else case
        
        self.geo_text.delete('1.0', END)
        self.geo_text.insert(END, "🚨 Analyzing victim patterns to identify attackers...\n\n")
        
        try:
            from paw.sentinel.database import CampaignDatabase
            db = CampaignDatabase()
            victims = db.get_victim_intelligence()
            
            if case_filter:
                victims = [v for v in victims if v.get('case_id') == case_filter]
            
            if not victims:
                self.geo_text.insert(END, "No victims found to analyze\n")
                return
            
            # Classify victims vs attackers
            attackers = []
            legitimate_victims = []
            
            for victim in victims:
                if victim.get('analyzed_status') != 'analyzed':
                    continue
                    
                geo_data = victim.get('geolocation_data', {})
                risk_score = victim.get('risk_score', 0)
                
                # Attacker indicators
                is_vpn = geo_data.get('is_vpn', False)
                is_proxy = geo_data.get('is_proxy', False)
                is_tor = geo_data.get('is_tor', False)
                is_hosting = geo_data.get('is_hosting', False)
                
                if is_vpn or is_proxy or is_tor or is_hosting or risk_score >= 7:
                    attackers.append(victim)
                else:
                    legitimate_victims.append(victim)
            
            # Display results
            self.geo_text.insert(END, f"{'='*60}\n")
            self.geo_text.insert(END, f"📊 ATTACKER IDENTIFICATION REPORT\n")
            self.geo_text.insert(END, f"{'='*60}\n\n")
            
            self.geo_text.insert(END, f"✅ Legitimate Victims: {len(legitimate_victims)}\n")
            self.geo_text.insert(END, f"🚨 Potential Attackers: {len(attackers)}\n")
            self.geo_text.insert(END, f"📈 Attacker Ratio: {len(attackers)/(len(victims) or 1)*100:.1f}%\n\n")
            
            if attackers:
                self.geo_text.insert(END, f"🚨 IDENTIFIED ATTACKERS:\n")
                self.geo_text.insert(END, f"{'-'*60}\n")
                for attacker in attackers:
                    ip = attacker.get('victim_ip', 'Unknown')
                    geo = attacker.get('geolocation_data', {})
                    country = geo.get('country', 'Unknown')
                    city = geo.get('city', 'Unknown')
                    risk = attacker.get('risk_score', 0)
                    
                    indicators = []
                    if geo.get('is_vpn'): indicators.append('VPN')
                    if geo.get('is_proxy'): indicators.append('PROXY')
                    if geo.get('is_tor'): indicators.append('TOR')
                    if geo.get('is_hosting'): indicators.append('DATACENTER')
                    
                    self.geo_text.insert(END, f"\n🔴 {ip} ({country}, {city})\n")
                    self.geo_text.insert(END, f"   Risk Score: {risk}/10\n")
                    self.geo_text.insert(END, f"   Indicators: {', '.join(indicators) if indicators else 'High Risk Score'}\n")
            
            self.geo_text.insert(END, f"\n{'='*60}\n")
            
        except Exception as e:
            self.geo_text.insert(END, f"❌ Error: {e}\n")

    def generate_geographic_report(self):
        """Generate geographic intelligence report"""
        case = self.geo_case_var.get().strip()
        case_filter = None if case == 'All Cases' else case
        output_format = self.geo_format_var.get()
        
        cmd = [sys.executable, '-m', 'paw', 'geographic', 'report', '--output', output_format]
        if case_filter:
            cmd.extend(['--case', case_filter])
        
        self.geo_text.delete('1.0', END)
        self.geo_text.insert(END, f"📄 Generating {output_format.upper()} report...\n\n")
        self._run_command(cmd, self.geo_text, "Geographic Report")

    def open_reports_folder(self):
        """Open the geographic reports folder"""
        import os
        import subprocess
        reports_dir = os.path.join(os.getcwd(), 'reports', 'geographic')
        
        if not os.path.exists(reports_dir):
            messagebox.showerror("Error", f"Reports directory not found: {reports_dir}")
            return
        
        try:
            if sys.platform == 'win32':
                os.startfile(reports_dir)
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', reports_dir])
            else:
                subprocess.Popen(['xdg-open', reports_dir])
            self.geo_text.insert(END, f"📂 Opened: {reports_dir}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder: {e}")


def main():
    root = Tk()
    app = PawTkGui(root)
    root.mainloop()


if __name__ == '__main__':
    main()