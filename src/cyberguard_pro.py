#!/usr/bin/env python3
"""
CyberGuard Pro - Windows Security Assistant
Professional Desktop Application
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess, threading, json, urllib.request
import datetime, os, sys, socket, re, ssl, urllib.parse

# ============================================================
#  CONFIG
# ============================================================
API_URL      = "https://api.anthropic.com/v1/messages"
MODEL        = "claude-sonnet-4-6"
APP_VERSION  = "1.0"
KEY_FILE     = os.path.join(os.path.expanduser("~"), ".cyberguard_pro")

SYSTEM_PROMPT = (
    "You are CyberGuard Pro AI, an expert cybersecurity assistant for Windows systems. "
    "When users ask security tasks: "
    "1. Explain clearly what you will do. "
    "2. Give EXACT Windows PowerShell or CMD commands in code blocks. "
    "3. Explain each command. "
    "4. Explain how to read the results. "
    "5. Recommend fixes for any issues found. "
    "Format commands as: ```powershell\\ncommand\\n``` or ```cmd\\ncommand\\n```. "
    "Be specific, practical, and safety conscious. "
    "Warn before any system-changing commands. "
    "If the user writes in Urdu or Roman Urdu, reply in that language too."
)

# ============================================================
#  COLOUR PALETTE  (professional dark theme)
# ============================================================
BG      = "#0d1117"   # main background
BG2     = "#161b22"   # card / sidebar
BG3     = "#21262d"   # input / code bg
ACCENT  = "#00e676"   # primary green
ACCENT2 = "#1565c0"   # blue accent
TEXT    = "#e6edf3"   # main text
MUTED   = "#8b949e"   # secondary text
BORDER  = "#30363d"   # divider
WARN    = "#f78166"   # warning / orange
YELLOW  = "#e3b341"   # caution
PURPLE  = "#bc8cff"   # info

# ============================================================
#  WINDOWS QUICK COMMANDS
# ============================================================
WIN_CMDS = {
    "Open Ports":        ("cmd",        "netstat -ano"),
    "Active Connections":("cmd",        "netstat -an | findstr ESTABLISHED"),
    "Running Processes": ("powershell", "Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 | Format-Table Name,CPU,Id -AutoSize"),
    "Startup Programs":  ("powershell", "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command | Format-Table -AutoSize"),
    "All User Accounts": ("cmd",        "net user"),
    "Admin Accounts":    ("powershell", "Get-LocalGroupMember -Group Administrators | Format-Table Name,ObjectClass"),
    "Firewall Status":   ("powershell", "Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction"),
    "Firewall Rules":    ("powershell", "Get-NetFirewallRule | Where-Object Enabled -eq True | Select-Object DisplayName,Direction,Action | Select-Object -First 20 | Format-Table -AutoSize"),
    "Windows Updates":   ("powershell", "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | Format-Table HotFixID,Description,InstalledOn"),
    "Shared Folders":    ("cmd",        "net share"),
    "Disk Usage":        ("powershell", "Get-PSDrive -PSProvider FileSystem | Format-Table Name,Used,Free,Root"),
    "Recent Logins":     ("powershell", "Get-EventLog -LogName Security -InstanceId 4624 -Newest 10 | Format-Table TimeGenerated,Message -AutoSize"),
    "Failed Logins":     ("powershell", "Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 | Format-Table TimeGenerated,Message -AutoSize"),
    "Scheduled Tasks":   ("powershell", "Get-ScheduledTask | Where-Object State -eq Running | Select-Object TaskName,TaskPath | Format-Table -AutoSize"),
    "System Info":       ("cmd",        "systeminfo | findstr /C:OS /C:Host /C:Total"),
    "DNS Cache":         ("cmd",        "ipconfig /displaydns"),
    "ARP Table":         ("cmd",        "arp -a"),
    "Routing Table":     ("cmd",        "route print"),
    "Network Adapters":  ("powershell", "Get-NetAdapter | Format-Table Name,Status,LinkSpeed,MacAddress"),
}

QUICK_ACTIONS = [
    ("Full Security Scan",    ACCENT,  "Perform a complete Windows security audit. Check open ports, running processes, startup programs, user accounts, and firewall. Give all commands."),
    ("Network Analysis",      "#58a6ff","Analyze my Windows network security. Show open ports, active connections, suspicious traffic, and DNS cache. Give exact commands."),
    ("Threat Detection",      WARN,    "Check my Windows PC for malware, suspicious processes, unusual startup entries, and security threats. Give commands to find and remove them."),
    ("Firewall Hardening",    YELLOW,  "Check and harden my Windows Firewall. Show current rules, close dangerous ports, and apply best-practice security rules."),
    ("User Account Audit",    PURPLE,  "Audit all Windows user accounts. Find unauthorized accounts, check admin privileges, and review password policies."),
    ("Event Log Analysis",    "#79c0ff","Analyze Windows Security Event Logs for failed logins, suspicious activity, and attack patterns. Give exact commands."),
    ("Website Security Scan", ACCENT,  "I will enter a website URL. Help me scan it for security issues, open ports, SSL certificate problems, and vulnerabilities."),
    ("Patch & Update Check",  MUTED,   "Check my Windows for missing security patches and updates. Give commands to find and install them."),
]

# ============================================================
#  WEBSITE SCANNER  (runs without API key)
# ============================================================
def scan_website(url: str, callback):
    """Lightweight website security scanner, no external tools needed."""
    results = []

    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    host   = parsed.hostname or ""
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)

    results.append(f"Target : {url}")
    results.append(f"Host   : {host}")
    results.append(f"Port   : {port}")
    results.append("")

    # 1. DNS lookup
    results.append("[1/6] DNS Lookup")
    try:
        ip = socket.gethostbyname(host)
        results.append(f"  IP Address : {ip}")
    except Exception as e:
        results.append(f"  ERROR : {e}")
    results.append("")

    # 2. Port scan (common ports)
    results.append("[2/6] Common Port Scan")
    ports_to_check = {21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
                      80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS",
                      3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 8080:"HTTP-Alt"}
    open_ports  = []
    risky_ports = [21, 23, 3389, 3306, 5432]
    for p, svc in ports_to_check.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            r = s.connect_ex((host, p))
            s.close()
            if r == 0:
                risk = " [RISK - should not be public]" if p in risky_ports else ""
                results.append(f"  OPEN   {p:5d}  {svc}{risk}")
                open_ports.append(p)
        except Exception:
            pass
    if not open_ports:
        results.append("  No common ports open (good)")
    results.append("")

    # 3. SSL certificate
    results.append("[3/6] SSL / TLS Certificate")
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(5)
        conn.connect((host, 443))
        cert = conn.getpeercert()
        conn.close()
        exp_str = cert.get("notAfter","")
        results.append(f"  Status  : Valid")
        results.append(f"  Expires : {exp_str}")
        # Check expiry
        try:
            exp_dt = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days   = (exp_dt - datetime.datetime.utcnow()).days
            if days < 30:
                results.append(f"  WARNING : Expires in {days} days!")
            else:
                results.append(f"  Days left : {days}")
        except Exception:
            pass
    except ssl.SSLCertVerificationError as e:
        results.append(f"  FAIL : SSL certificate error - {e}")
    except Exception as e:
        results.append(f"  INFO : {e}")
    results.append("")

    # 4. HTTP headers
    results.append("[4/6] Security Headers")
    important_headers = {
        "Strict-Transport-Security": "HSTS",
        "X-Frame-Options":           "Clickjacking protection",
        "X-Content-Type-Options":    "MIME sniffing protection",
        "Content-Security-Policy":   "CSP",
        "X-XSS-Protection":          "XSS protection",
        "Referrer-Policy":           "Referrer policy",
        "Permissions-Policy":        "Permissions policy",
    }
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=8, context=ctx2) as resp:
            hdrs = dict(resp.getheaders())
            for h, desc in important_headers.items():
                val = hdrs.get(h) or hdrs.get(h.lower())
                if val:
                    results.append(f"  OK     {h}")
                else:
                    results.append(f"  MISSING  {h} ({desc})")
            srv = hdrs.get("Server") or hdrs.get("server")
            if srv:
                results.append(f"  INFO : Server header reveals: {srv}")
    except Exception as e:
        results.append(f"  Could not fetch headers: {e}")
    results.append("")

    # 5. Robots.txt
    results.append("[5/6] robots.txt Check")
    try:
        robots_url = f"{parsed.scheme}://{host}/robots.txt"
        req2 = urllib.request.Request(robots_url, headers={"User-Agent":"Mozilla/5.0"})
        ctx3 = ssl.create_default_context()
        ctx3.check_hostname = False
        ctx3.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req2, timeout=5, context=ctx3) as r:
            content = r.read().decode("utf-8", errors="ignore")
            lines   = [l for l in content.splitlines() if l.strip()][:10]
            results.append(f"  Found ({len(lines)} lines shown):")
            for ln in lines:
                results.append(f"    {ln}")
    except urllib.error.HTTPError as e:
        results.append(f"  Not found (HTTP {e.code})")
    except Exception as e:
        results.append(f"  {e}")
    results.append("")

    # 6. Summary
    results.append("[6/6] Security Summary")
    risky_open = [p for p in open_ports if p in risky_ports]
    if risky_open:
        results.append(f"  HIGH RISK  : Dangerous ports open: {risky_open}")
    if 80 in open_ports and 443 in open_ports:
        results.append("  INFO : Both HTTP and HTTPS open - ensure HTTP redirects to HTTPS")
    results.append("  Scan complete. Paste this output into the Chat tab for AI analysis.")

    callback("\n".join(results))

# ============================================================
#  MAIN APP
# ============================================================
class CyberGuardPro:
    def __init__(self, root):
        self.root    = root
        self.root.title("CyberGuard Pro  v" + APP_VERSION)
        self.root.configure(bg=BG)
        self.root.minsize(900, 600)

        try:
            self.root.state("zoomed")
        except Exception:
            self.root.geometry("1100x720")

        self.history    = []
        self.api_key    = self._load_key()
        self.loading    = False
        self.active_tab = "chat"

        self._build_ui()
        self._welcome()

    # ------------------------------------------------------------------
    #  PERSIST KEY
    # ------------------------------------------------------------------
    def _load_key(self):
        try:
            with open(KEY_FILE) as f:
                return f.read().strip()
        except Exception:
            return ""

    def _save_key_file(self, key):
        with open(KEY_FILE, "w") as f:
            f.write(key)

    # ------------------------------------------------------------------
    #  UI
    # ------------------------------------------------------------------
    def _build_ui(self):
        # Title bar row
        title_bar = tk.Frame(self.root, bg=BG2, height=52)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        logo_frame = tk.Frame(title_bar, bg=BG2)
        logo_frame.pack(side="left", padx=18, pady=8)

        canvas = tk.Canvas(logo_frame, width=30, height=30, bg=BG2,
                           highlightthickness=0)
        canvas.create_oval(2, 2, 28, 28, fill=ACCENT, outline="")
        canvas.create_oval(8, 8, 22, 22, fill=BG2,    outline="")
        canvas.pack(side="left", padx=(0, 8))

        tk.Label(logo_frame, text="CyberGuard Pro", bg=BG2,
                 fg=ACCENT, font=("Segoe UI", 13, "bold")).pack(side="left")
        tk.Label(logo_frame, text=f"  v{APP_VERSION}", bg=BG2,
                 fg=MUTED, font=("Segoe UI", 9)).pack(side="left")

        right = tk.Frame(title_bar, bg=BG2)
        right.pack(side="right", padx=18)
        self.threat_lbl = tk.Label(right, text="SECURE", bg=BG2,
                                   fg=ACCENT, font=("Segoe UI", 9, "bold"))
        self.threat_lbl.pack(side="right")
        tk.Label(right, text="System Status:  ", bg=BG2,
                 fg=MUTED, font=("Segoe UI", 9)).pack(side="right")

        # Tab navigation
        nav = tk.Frame(self.root, bg=BG, height=40)
        nav.pack(fill="x")
        nav.pack_propagate(False)

        self.tab_buttons = {}
        tabs = [
            ("chat",     "  Chat Assistant  "),
            ("tools",    "  Quick Tools  "),
            ("website",  "  Website Scanner  "),
            ("settings", "  Settings  "),
        ]
        for key, label in tabs:
            b = tk.Button(nav, text=label, bg=BG, fg=MUTED,
                          font=("Segoe UI", 10), relief="flat", bd=0,
                          padx=6, pady=8, cursor="hand2",
                          activebackground=BG2, activeforeground=ACCENT,
                          command=lambda k=key: self._show_tab(k))
            b.pack(side="left")
            self.tab_buttons[key] = b

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

        # Content area
        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(fill="both", expand=True)

        self.panes = {}
        self._build_chat_pane()
        self._build_tools_pane()
        self._build_website_pane()
        self._build_settings_pane()

        self._show_tab("chat")

    # ------------------------------------------------------------------
    #  CHAT PANE
    # ------------------------------------------------------------------
    def _build_chat_pane(self):
        pane = tk.Frame(self.content, bg=BG)
        self.panes["chat"] = pane

        # Quick action buttons
        qa_outer = tk.Frame(pane, bg=BG)
        qa_outer.pack(fill="x", padx=16, pady=10)
        tk.Label(qa_outer, text="Quick Actions", bg=BG, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 4))
        qa_grid = tk.Frame(qa_outer, bg=BG)
        qa_grid.pack(fill="x")
        for i, (label, color, prompt) in enumerate(QUICK_ACTIONS):
            col = i % 4
            row = i // 4
            b = tk.Button(qa_grid, text=label, bg=BG2, fg=color,
                          font=("Segoe UI", 9), relief="flat",
                          highlightbackground=BORDER, highlightthickness=1,
                          padx=10, pady=7, cursor="hand2",
                          command=lambda p=prompt: self._send(p))
            b.grid(row=row, column=col, padx=3, pady=2, sticky="ew")
            qa_grid.columnconfigure(col, weight=1)

        # Chat display
        chat_frame = tk.Frame(pane, bg=BG)
        chat_frame.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        self.chat_box = scrolledtext.ScrolledText(
            chat_frame, bg=BG3, fg=TEXT, font=("Consolas", 11),
            relief="flat", bd=0, wrap="word",
            insertbackground=ACCENT, padx=14, pady=12, state="disabled"
        )
        self.chat_box.pack(fill="both", expand=True)

        self.chat_box.tag_config("ai_name", foreground=ACCENT,
                                 font=("Segoe UI", 10, "bold"))
        self.chat_box.tag_config("user_name", foreground="#58a6ff",
                                 font=("Segoe UI", 10, "bold"))
        self.chat_box.tag_config("timestamp", foreground=MUTED,
                                 font=("Consolas", 9))
        self.chat_box.tag_config("body",   foreground=TEXT)
        self.chat_box.tag_config("code",   foreground="#e6edf3",
                                 background="#0d1117", font=("Consolas", 10),
                                 lmargin1=20, lmargin2=20, spacing1=2, spacing3=2)
        self.chat_box.tag_config("code_hdr", foreground=ACCENT,
                                 font=("Consolas", 9))

        # Thinking indicator
        self.think_frame = tk.Frame(pane, bg=BG)
        tk.Label(self.think_frame, text="CyberGuard AI is thinking...",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9, "italic")).pack(
                     side="left", padx=18, pady=2)

        # Input bar
        inp_bar = tk.Frame(pane, bg=BG2)
        inp_bar.pack(fill="x", padx=16, pady=8)

        self.chat_entry = tk.Entry(
            inp_bar, bg=BG3, fg=TEXT, font=("Segoe UI", 11),
            relief="flat", insertbackground=ACCENT,
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT
        )
        self.chat_entry.pack(side="left", fill="x", expand=True,
                             padx=(10, 8), pady=8, ipady=8)
        self.chat_entry.bind("<Return>", lambda e: self._send())
        self._set_placeholder(self.chat_entry,
                              "Ask anything... e.g. 'Check my open ports'")

        self.send_btn = tk.Button(
            inp_bar, text="Send", bg=ACCENT, fg=BG,
            font=("Segoe UI", 10, "bold"), relief="flat",
            padx=20, pady=8, cursor="hand2", command=self._send
        )
        self.send_btn.pack(side="right", padx=(0, 8), pady=8)

        self.clear_btn = tk.Button(
            inp_bar, text="Clear", bg=BG3, fg=MUTED,
            font=("Segoe UI", 9), relief="flat",
            padx=12, pady=8, cursor="hand2", command=self._clear_chat
        )
        self.clear_btn.pack(side="right", padx=(0, 4), pady=8)

    # ------------------------------------------------------------------
    #  TOOLS PANE
    # ------------------------------------------------------------------
    def _build_tools_pane(self):
        pane = tk.Frame(self.content, bg=BG)
        self.panes["tools"] = pane

        header = tk.Frame(pane, bg=BG)
        header.pack(fill="x", padx=16, pady=12)
        tk.Label(header, text="Quick Security Tools", bg=BG,
                 fg=TEXT, font=("Segoe UI", 13, "bold")).pack(side="left")
        tk.Label(header, text="  Click any button to run on your PC",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left",
                                                               pady=4)

        btn_frame = tk.Frame(pane, bg=BG)
        btn_frame.pack(fill="x", padx=16, pady=(0, 8))

        labels = list(WIN_CMDS.keys())
        cols   = 5
        for i, label in enumerate(labels):
            col = i % cols
            row = i // cols
            b = tk.Button(btn_frame, text=label, bg=BG2, fg=TEXT,
                          font=("Segoe UI", 9), relief="flat",
                          highlightbackground=BORDER, highlightthickness=1,
                          padx=8, pady=6, cursor="hand2",
                          command=lambda l=label: self._run_win(l))
            b.grid(row=row, column=col, padx=3, pady=2, sticky="ew")
            btn_frame.columnconfigure(col, weight=1)

        out_header = tk.Frame(pane, bg=BG)
        out_header.pack(fill="x", padx=16, pady=(4, 0))
        tk.Label(out_header, text="Output", bg=BG,
                 fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Button(out_header, text="Copy Output", bg=BG2, fg=MUTED,
                  font=("Segoe UI", 8), relief="flat", padx=8, pady=2,
                  cursor="hand2", command=self._copy_tool_out).pack(
                      side="right")
        tk.Button(out_header, text="Analyze in Chat", bg=ACCENT, fg=BG,
                  font=("Segoe UI", 8, "bold"), relief="flat", padx=8, pady=2,
                  cursor="hand2", command=self._analyze_in_chat).pack(
                      side="right", padx=4)

        self.tool_out = scrolledtext.ScrolledText(
            pane, bg=BG3, fg="#e6edf3", font=("Consolas", 10),
            relief="flat", bd=0, padx=14, pady=12, state="disabled"
        )
        self.tool_out.pack(fill="both", expand=True, padx=16, pady=(4, 8))

        tk.Label(pane,
                 text="Tip: Click 'Analyze in Chat' to send the output to AI for analysis",
                 bg=BG, fg=YELLOW, font=("Segoe UI", 9)).pack(
                     anchor="w", padx=16, pady=(0, 8))

    # ------------------------------------------------------------------
    #  WEBSITE SCANNER PANE
    # ------------------------------------------------------------------
    def _build_website_pane(self):
        pane = tk.Frame(self.content, bg=BG)
        self.panes["website"] = pane

        # Header
        hdr = tk.Frame(pane, bg=BG)
        hdr.pack(fill="x", padx=16, pady=12)
        tk.Label(hdr, text="Website Security Scanner", bg=BG,
                 fg=TEXT, font=("Segoe UI", 13, "bold")).pack(side="left")

        # URL input card
        card = tk.Frame(pane, bg=BG2)
        card.pack(fill="x", padx=16, pady=(0, 8))

        tk.Label(card, text="Enter Website URL", bg=BG2,
                 fg=MUTED, font=("Segoe UI", 9, "bold")).pack(
                     anchor="w", padx=14, pady=(12, 2))

        url_row = tk.Frame(card, bg=BG2)
        url_row.pack(fill="x", padx=14, pady=(0, 12))

        self.url_entry = tk.Entry(
            url_row, bg=BG3, fg=TEXT, font=("Segoe UI", 11),
            relief="flat", insertbackground=ACCENT,
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT
        )
        self.url_entry.pack(side="left", fill="x", expand=True,
                            ipady=8, padx=(0, 8))
        self._set_placeholder(self.url_entry, "example.com or https://example.com")
        self.url_entry.bind("<Return>", lambda e: self._start_webscan())

        self.scan_btn = tk.Button(
            url_row, text="Scan", bg=ACCENT, fg=BG,
            font=("Segoe UI", 10, "bold"), relief="flat",
            padx=20, pady=8, cursor="hand2",
            command=self._start_webscan
        )
        self.scan_btn.pack(side="left")

        # What gets checked
        info_frame = tk.Frame(pane, bg=BG)
        info_frame.pack(fill="x", padx=16, pady=(0, 6))
        checks = [
            ("DNS Lookup", ACCENT),
            ("Port Scan", "#58a6ff"),
            ("SSL Certificate", YELLOW),
            ("Security Headers", PURPLE),
            ("robots.txt", MUTED),
        ]
        for label, color in checks:
            tk.Label(info_frame, text=f"  {label}", bg=BG, fg=color,
                     font=("Segoe UI", 9)).pack(side="left")

        # Output
        out_hdr = tk.Frame(pane, bg=BG)
        out_hdr.pack(fill="x", padx=16, pady=(4, 0))
        tk.Label(out_hdr, text="Scan Results", bg=BG,
                 fg=MUTED, font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Button(out_hdr, text="Analyze with AI", bg=ACCENT, fg=BG,
                  font=("Segoe UI", 8, "bold"), relief="flat",
                  padx=8, pady=2, cursor="hand2",
                  command=self._analyze_web_in_chat).pack(side="right")
        tk.Button(out_hdr, text="Copy", bg=BG2, fg=MUTED,
                  font=("Segoe UI", 8), relief="flat", padx=8, pady=2,
                  cursor="hand2",
                  command=self._copy_web_out).pack(side="right", padx=4)

        self.web_out = scrolledtext.ScrolledText(
            pane, bg=BG3, fg="#e6edf3", font=("Consolas", 10),
            relief="flat", bd=0, padx=14, pady=12, state="disabled"
        )
        self.web_out.pack(fill="both", expand=True, padx=16, pady=(4, 8))

        self.web_status = tk.Label(
            pane, text="Ready to scan", bg=BG,
            fg=MUTED, font=("Segoe UI", 9)
        )
        self.web_status.pack(anchor="w", padx=16, pady=(0, 8))

    # ------------------------------------------------------------------
    #  SETTINGS PANE
    # ------------------------------------------------------------------
    def _build_settings_pane(self):
        pane = tk.Frame(self.content, bg=BG)
        self.panes["settings"] = pane

        tk.Label(pane, text="Settings", bg=BG, fg=TEXT,
                 font=("Segoe UI", 14, "bold")).pack(
                     anchor="w", padx=20, pady=(20, 2))
        tk.Label(pane,
                 text="Configure your API key to enable the AI chatbot",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(
                     anchor="w", padx=20)

        # API key card
        card = tk.Frame(pane, bg=BG2)
        card.pack(fill="x", padx=20, pady=14)

        tk.Label(card, text="Anthropic API Key", bg=BG2, fg=TEXT,
                 font=("Segoe UI", 11, "bold")).pack(
                     anchor="w", padx=16, pady=(14, 2))
        tk.Label(card, text="Required for the AI chatbot. Free account at console.anthropic.com",
                 bg=BG2, fg=MUTED, font=("Segoe UI", 9)).pack(
                     anchor="w", padx=16)

        key_row = tk.Frame(card, bg=BG2)
        key_row.pack(fill="x", padx=16, pady=10)

        self.key_entry = tk.Entry(
            key_row, bg=BG3, fg=TEXT, font=("Consolas", 11),
            relief="flat", insertbackground=ACCENT,
            show="*", width=55,
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT
        )
        self.key_entry.pack(side="left", fill="x", expand=True,
                            ipady=7, padx=(0, 10))
        if self.api_key:
            self.key_entry.insert(0, self.api_key)

        self.show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(key_row, text="Show", bg=BG2, fg=MUTED,
                       selectcolor=BG3, activebackground=BG2,
                       variable=self.show_var,
                       command=self._toggle_show).pack(side="left")

        btn_row = tk.Frame(card, bg=BG2)
        btn_row.pack(fill="x", padx=16, pady=(0, 14))
        tk.Button(btn_row, text="Save Key", bg=ACCENT, fg=BG,
                  font=("Segoe UI", 10, "bold"), relief="flat",
                  padx=18, pady=7, cursor="hand2",
                  command=self._save_key).pack(side="left")
        tk.Button(btn_row, text="Clear Key", bg=BG3, fg=MUTED,
                  font=("Segoe UI", 9), relief="flat",
                  padx=12, pady=7, cursor="hand2",
                  command=self._clear_key).pack(side="left", padx=8)

        self.key_status = tk.Label(btn_row, bg=BG2,
                                   fg=ACCENT if self.api_key else MUTED,
                                   font=("Segoe UI", 9),
                                   text="Key loaded" if self.api_key else "No key saved")
        self.key_status.pack(side="left", padx=8)

        # How to get key
        guide = tk.Frame(pane, bg=BG2)
        guide.pack(fill="x", padx=20, pady=(0, 14))
        tk.Label(guide, text="How to Get a Free API Key", bg=BG2, fg=TEXT,
                 font=("Segoe UI", 10, "bold")).pack(
                     anchor="w", padx=16, pady=(12, 6))
        steps = [
            "1.  Open your browser and go to  console.anthropic.com",
            "2.  Click Sign Up and create a free account",
            "3.  In the dashboard click  API Keys  in the left menu",
            "4.  Click  Create Key,  give it a name, then click Copy",
            "5.  Paste the key in the box above and click Save Key",
        ]
        for s in steps:
            tk.Label(guide, text=s, bg=BG2, fg=TEXT,
                     font=("Segoe UI", 10), anchor="w").pack(
                         fill="x", padx=16, pady=1)
        tk.Label(guide, bg=BG2, height=1).pack()

        tk.Label(pane,
                 text="Your API key is saved locally on this PC only. Never share it with anyone.",
                 bg=BG, fg=WARN, font=("Segoe UI", 9)).pack(
                     anchor="w", padx=20, pady=4)

    # ------------------------------------------------------------------
    #  TAB SWITCHING
    # ------------------------------------------------------------------
    def _show_tab(self, name):
        for k, f in self.panes.items():
            f.pack_forget()
        self.panes[name].pack(fill="both", expand=True)
        self.active_tab = name
        for k, b in self.tab_buttons.items():
            active = k == name
            b.config(
                fg=ACCENT if active else MUTED,
                bg=BG2    if active else BG,
                font=("Segoe UI", 10, "bold") if active else ("Segoe UI", 10)
            )

    # ------------------------------------------------------------------
    #  CHAT HELPERS
    # ------------------------------------------------------------------
    def _welcome(self):
        self._chat_write("ai_name",    "CyberGuard Pro AI\n")
        self._chat_write("timestamp",  datetime.datetime.now().strftime("%H:%M:%S") + "\n")
        self._chat_write("body",
            "Welcome! I'm your personal Windows security assistant.\n\n"
            "I can help you:\n"
            "  - Scan your Windows PC for security issues\n"
            "  - Analyse open ports and network connections\n"
            "  - Detect malware and suspicious processes\n"
            "  - Harden your Windows Firewall\n"
            "  - Audit user accounts and event logs\n"
            "  - Scan websites for security vulnerabilities\n\n"
            "Use the Quick Action buttons above, or just ask me anything.\n"
        )
        if not self.api_key:
            self._chat_write("body",
                "No API key found. Go to the Settings tab to add your free key.\n")
        self.chat_box.see("end")

    def _chat_write(self, tag, text):
        self.chat_box.config(state="normal")
        self.chat_box.insert("end", text, tag)
        self.chat_box.config(state="disabled")

    def _format_and_insert(self, text):
        """Insert assistant message with code block highlighting."""
        self.chat_box.config(state="normal")
        parts = re.split(r"(```(?:\w+)?\n[\s\S]*?```)", text)
        for part in parts:
            if part.startswith("```"):
                lines = part.split("\n")
                lang  = lines[0].replace("```", "").strip() or "cmd"
                code  = "\n".join(lines[1:]).rstrip("`").strip()
                self.chat_box.insert("end",
                    f"\n  [ {lang.upper()} Command ]\n", "code_hdr")
                self.chat_box.insert("end", code + "\n\n", "code")
            else:
                clean = part.replace("**", "")
                self.chat_box.insert("end", clean, "body")
        self.chat_box.config(state="disabled")
        self.chat_box.see("end")

    def _set_loading(self, val):
        self.loading = val
        self.send_btn.config(
            state="disabled" if val else "normal",
            text="Sending..." if val else "Send"
        )
        if val:
            self.think_frame.pack(fill="x", padx=16, before=self.chat_box)
        else:
            self.think_frame.pack_forget()

    def _clear_chat(self):
        self.chat_box.config(state="normal")
        self.chat_box.delete("1.0", "end")
        self.chat_box.config(state="disabled")
        self.history.clear()
        self._welcome()

    # ------------------------------------------------------------------
    #  SEND MESSAGE
    # ------------------------------------------------------------------
    def _send(self, text=None):
        if self.loading:
            return
        if text is None:
            text = self.chat_entry.get().strip()
            if not text or text == self._ph_text(self.chat_entry):
                return
            self.chat_entry.delete(0, "end")

        if not self.api_key:
            messagebox.showwarning(
                "API Key Required",
                "Please add your Anthropic API key in the Settings tab.\n\n"
                "It is free at console.anthropic.com"
            )
            self._show_tab("settings")
            return

        # Display user message
        self.chat_box.config(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_box.insert("end", "\nYou  ", "user_name")
        self.chat_box.insert("end", f"[{ts}]\n", "timestamp")
        self.chat_box.insert("end", text + "\n\n", "body")
        self.chat_box.config(state="disabled")
        self.chat_box.see("end")

        self.history.append({"role": "user", "content": text})
        self._set_loading(True)
        threading.Thread(target=self._api_call, daemon=True).start()

    def _api_call(self):
        try:
            payload = json.dumps({
                "model":      MODEL,
                "max_tokens": 1000,
                "system":     SYSTEM_PROMPT,
                "messages":   self.history,
            }).encode()
            req = urllib.request.Request(API_URL, data=payload, method="POST")
            req.add_header("Content-Type",      "application/json")
            req.add_header("x-api-key",         self.api_key)
            req.add_header("anthropic-version", "2023-06-01")
            with urllib.request.urlopen(req, timeout=60) as r:
                data  = json.loads(r.read())
                reply = "".join(b.get("text", "")
                                for b in data.get("content", []))
            self.history.append({"role": "assistant", "content": reply})
            self.root.after(0, lambda: self._on_reply(reply))
        except Exception as e:
            err = f"Connection error: {e}\n\nCheck your internet connection and API key."
            self.root.after(0, lambda: self._on_reply(err))

    def _on_reply(self, text):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_box.config(state="normal")
        self.chat_box.insert("end", "CyberGuard AI  ", "ai_name")
        self.chat_box.insert("end", f"[{ts}]\n", "timestamp")
        self.chat_box.config(state="disabled")
        self._format_and_insert(text)
        self._set_loading(False)

        lo = text.lower()
        if any(w in lo for w in ["critical", "rootkit", "malware", "ransomware"]):
            self.threat_lbl.config(text="AT RISK", fg=WARN)
        elif any(w in lo for w in ["warning", "suspicious", "vulnerability", "risk"]):
            self.threat_lbl.config(text="CAUTION", fg=YELLOW)
        else:
            self.threat_lbl.config(text="SECURE",  fg=ACCENT)

    # ------------------------------------------------------------------
    #  QUICK TOOLS
    # ------------------------------------------------------------------
    def _run_win(self, label):
        shell, cmd = WIN_CMDS[label]
        self.tool_out.config(state="normal")
        self.tool_out.delete("1.0", "end")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.tool_out.insert("end", f"[{ts}]  {label}\nCommand: {cmd}\n")
        self.tool_out.insert("end", "-" * 60 + "\n")
        self.tool_out.insert("end", "Running...\n")
        self.tool_out.config(state="disabled")

        def run():
            try:
                if shell == "powershell":
                    result = subprocess.run(
                        ["powershell", "-NoProfile", "-Command", cmd],
                        capture_output=True, text=True, timeout=30,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                else:
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True,
                        text=True, timeout=30,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                out = result.stdout or result.stderr or "(No output returned)"
            except FileNotFoundError:
                out = "PowerShell not found. Try running as Administrator."
            except Exception as e:
                out = f"Error: {e}"
            self.root.after(0, lambda: self._show_tool_out(label, cmd, out))

        threading.Thread(target=run, daemon=True).start()

    def _show_tool_out(self, label, cmd, out):
        self.tool_out.config(state="normal")
        self.tool_out.delete("1.0", "end")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.tool_out.insert("end", f"[{ts}]  {label}\nCommand: {cmd}\n")
        self.tool_out.insert("end", "-" * 60 + "\n")
        self.tool_out.insert("end", out)
        self.tool_out.config(state="disabled")

    def _copy_tool_out(self):
        text = self.tool_out.get("1.0", "end")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _analyze_in_chat(self):
        text = self.tool_out.get("1.0", "end").strip()
        if not text:
            return
        self._show_tab("chat")
        self._send(f"Analyze this Windows security output and tell me if there are any threats or issues:\n\n{text[:2000]}")

    # ------------------------------------------------------------------
    #  WEBSITE SCANNER
    # ------------------------------------------------------------------
    def _start_webscan(self):
        url = self.url_entry.get().strip()
        ph  = self._ph_text(self.url_entry)
        if not url or url == ph:
            messagebox.showwarning("No URL", "Please enter a website URL first.")
            return

        self.scan_btn.config(state="disabled", text="Scanning...")
        self.web_status.config(text="Scanning... please wait", fg=YELLOW)
        self.web_out.config(state="normal")
        self.web_out.delete("1.0", "end")
        self.web_out.insert("end", f"Starting scan for: {url}\n\n")
        self.web_out.config(state="disabled")

        def done(result):
            self.web_out.config(state="normal")
            self.web_out.delete("1.0", "end")
            self.web_out.insert("end", result)
            self.web_out.config(state="disabled")
            self.scan_btn.config(state="normal", text="Scan")
            self.web_status.config(text="Scan complete", fg=ACCENT)

        threading.Thread(target=scan_website, args=(url, lambda r: self.root.after(0, lambda: done(r))), daemon=True).start()

    def _copy_web_out(self):
        text = self.web_out.get("1.0", "end")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _analyze_web_in_chat(self):
        text = self.web_out.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("No Results", "Run a website scan first.")
            return
        self._show_tab("chat")
        self._send(f"Analyze this website security scan report and tell me the risks and how to fix them:\n\n{text[:2500]}")

    # ------------------------------------------------------------------
    #  SETTINGS ACTIONS
    # ------------------------------------------------------------------
    def _toggle_show(self):
        self.key_entry.config(show="" if self.show_var.get() else "*")

    def _save_key(self):
        k = self.key_entry.get().strip()
        if not k:
            messagebox.showwarning("Empty", "Please paste your API key first.")
            return
        self.api_key = k
        self._save_key_file(k)
        self.key_status.config(text="Key saved", fg=ACCENT)
        messagebox.showinfo("Saved", "API key saved successfully!\nYou can now use the chatbot.")
        self._show_tab("chat")

    def _clear_key(self):
        if messagebox.askyesno("Clear Key", "Remove the saved API key?"):
            self.api_key = ""
            self.key_entry.delete(0, "end")
            self.key_status.config(text="No key saved", fg=MUTED)
            try:
                os.remove(KEY_FILE)
            except Exception:
                pass

    # ------------------------------------------------------------------
    #  PLACEHOLDER HELPER
    # ------------------------------------------------------------------
    _placeholders = {}

    def _ph_text(self, widget):
        return self._placeholders.get(widget, "")

    def _set_placeholder(self, widget, text):
        self._placeholders[widget] = text
        widget.insert(0, text)
        widget.config(fg=MUTED)

        def on_focus_in(_event):
            if widget.get() == self._placeholders.get(widget, ""):
                widget.delete(0, "end")
                widget.config(fg=TEXT)

        def on_focus_out(_event):
            if not widget.get():
                widget.insert(0, self._placeholders.get(widget, ""))
                widget.config(fg=MUTED)

        widget.bind("<FocusIn>",  on_focus_in)
        widget.bind("<FocusOut>", on_focus_out)


# ============================================================
#  ENTRY POINT
# ============================================================
if __name__ == "__main__":
    root = tk.Tk()
    app  = CyberGuardPro(root)
    root.mainloop()
