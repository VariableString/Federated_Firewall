# gui_app.py
# GUI launcher for Federated Firewall that runs:
# sudo env "PATH=$PATH" python3 src/main_simple.py --debug --log-level DEBUG
# and parses DEBUG logs to populate the dashboard.

import os
import sys
import subprocess
import threading
import queue
import signal
import re
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from typing import Optional

# ---------------------------
# Regex Parsers
# ---------------------------
RE_ENHANCED_LEARNING_PROG = re.compile(
    r"Enhanced Learning Progress:\s*Accuracy=([\d\.]+),\s*Packets=(\d+),\s*Threats=(\d+),",
    re.IGNORECASE,
)
RE_ENHANCED_STATUS_LINE = re.compile(
    r"Metrics:\s*Avg Accuracy=([\d\.]+),\s*Packets=(\d+),\s*Fed Rounds=(\d+)",
    re.IGNORECASE,
)
RE_ACTIVE_CLIENTS = re.compile(r"Clients:\s*(\d+)\s*active", re.IGNORECASE)
RE_SYSTEM_STATUS_ACTIVE = re.compile(r"Active Clients:\s*(\d+)/\d+", re.IGNORECASE)
RE_SYSTEM_STATUS_AVGACC = re.compile(r"Average Accuracy:\s*([\d\.]+)", re.IGNORECASE)
RE_SYSTEM_STATUS_PACKETS = re.compile(r"Total Packets:\s*(\d+)", re.IGNORECASE)
RE_SYSTEM_STATUS_THREATS = re.compile(r"Threats Detected:\s*(\d+)", re.IGNORECASE)
RE_SYSTEM_STATUS_ROUNDS = re.compile(r"Federated Rounds:\s*(\d+)", re.IGNORECASE)

RE_CLIENT_HEADER = re.compile(r"(h\d+)\s+Enhanced Status\s*\[(\w+)\]", re.IGNORECASE)
RE_CLIENT_ROUND_ACC = re.compile(r"Round:\s*(\d+),\s*Accuracy:\s*([\d\.]+)", re.IGNORECASE)
RE_CLIENT_PACKETS_THREATS = re.compile(r"Packets:\s*(\d+),\s*Threats[:=]\s*(\d+)", re.IGNORECASE)
RE_TRAINING_PROGRESS = re.compile(r"(h\d+)\s*Training Progress.*Round\s*(\d+)", re.IGNORECASE)

RE_HIGH_THREAT = re.compile(
    r"(h\d+).*HIGH THREAT.*Confidence:\s*([\d\.]+).*Uncertainty:\s*([\d\.]+).*Action:\s*(\w+)",
    re.IGNORECASE,
)
RE_HIGH_THREAT_FALLBACK = re.compile(
    r"(h\d+).*HIGH THREAT.*Confidence:\s*([\d\.]+).*Action:\s*(\w+)", re.IGNORECASE
)

# Phase transitions
RE_GLOBAL_PHASE = re.compile(r"ENHANCED PHASE TRANSITION:\s*(\w+)\s*->\s*(\w+)", re.IGNORECASE)
RE_PHASE_TRANSITION = re.compile(
    r"(h\d+):\s*Enhanced phase transition\s+(\w+)\s*->\s*(\w+)", re.IGNORECASE
)
RE_CLIENT_PHASE_SIMPLE = re.compile(r"(h\d+).*Phase:\s*(\w+)", re.IGNORECASE)

# ---------------------------
# GUI Application
# ---------------------------


def _host_sort_key(host: str):
    """Natural sort key for host names like h1, h2, h10."""
    if not host:
        return host
    m = re.match(r"h0*(\d+)$", host)
    if m:
        return int(m.group(1))
    try:
        return int(re.sub(r"\D", "", host))
    except Exception:
        return host


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Federated Firewall Dashboard")
        self.geometry("1280x820")
        self.configure(bg="#0b1220")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # process + reader thread state
        self.proc: Optional[subprocess.Popen] = None
        self.output_queue: "queue.Queue[str]" = queue.Queue()
        self.reader_stop = threading.Event()
        self.reader_thread_handle: Optional[threading.Thread] = None

        # internal metrics state
        self.clients_connected: int = 0
        self.global_accuracy: Optional[float] = None
        self.packets_total: Optional[int] = None
        self.threats_total: Optional[int] = None
        self.training_round: int = 0
        self.client_metrics: dict = {}  # h1 -> metrics
        self._recent_host: Optional[str] = None
        self.current_phase: Optional[str] = None

        # build UI
        self._build_ui()

        # start periodic drain loop
        self.after(200, self._drain_output_queue)

    # ---------------- UI builders ----------------
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        bg = "#0b1220"
        sidebar_bg = "#071023"
        card_bg = "#0f1724"
        panel_bg = "#0b1220"
        fg = "#e6eef8"
        accent = "#60a5fa"

        style.configure("Sidebar.TFrame", background=sidebar_bg)
        style.configure("Main.TFrame", background=panel_bg)
        style.configure("Card.TFrame", background=card_bg, relief="flat")
        style.configure("Title.TLabel", background=bg, foreground=fg, font=("Segoe UI Semibold", 18))
        style.configure("Metric.TLabel", background=card_bg, foreground=fg, font=("Segoe UI", 11))
        style.configure("MetricBig.TLabel", background=card_bg, foreground=accent, font=("Segoe UI Semibold", 28))
        style.configure("Section.TLabel", background=panel_bg, foreground=fg, font=("Segoe UI Semibold", 14))
        style.configure("Accent.TButton", background=accent, foreground=bg, font=("Segoe UI Semibold", 11), padding=8)

        # Sidebar
        sidebar = ttk.Frame(self, style="Sidebar.TFrame", padding=(18, 18))
        sidebar.pack(side="left", fill="y")

        ttk.Label(sidebar, text="Federated\nFirewall V1", foreground=fg,
                  background=sidebar_bg, font=("Segoe UI Semibold", 20)).pack(anchor="w", pady=(0, 12))

        self.start_btn = ttk.Button(sidebar, text="▶ Start System", command=self.start_system, style="Accent.TButton")
        self.start_btn.pack(fill="x", pady=(6, 8))

        self.stop_btn = ttk.Button(sidebar, text="⏹ Stop System", command=self.stop_system, style="Accent.TButton", state="disabled")
        self.stop_btn.pack(fill="x")

        ttk.Separator(sidebar, orient="horizontal").pack(fill="x", pady=12)
        ttk.Button(sidebar, text="Clear Logs", command=self._clear_logs).pack(fill="x", pady=6)

        # Main area
        main = ttk.Frame(self, style="Main.TFrame", padding=(16, 16))
        main.pack(side="right", fill="both", expand=True)

        self.global_title = ttk.Label(main, text="🌐 Global Dashboard", style="Title.TLabel")
        self.global_title.pack(anchor="w")

        cards = ttk.Frame(main, style="Main.TFrame")
        cards.pack(fill="x", pady=(12, 8))

        self.card_clients = self._metric_card(cards, "Clients Connected", "0")
        self.card_clients.pack(side="left", padx=8, expand=True, fill="x")

        self.card_accuracy = self._metric_card(cards, "Global Accuracy", "—")
        self.card_accuracy.pack(side="left", padx=8, expand=True, fill="x")

        self.card_packets = self._metric_card(cards, "Total Packets", "—")
        self.card_packets.pack(side="left", padx=8, expand=True, fill="x")

        self.card_threats = self._metric_card(cards, "Total Threats", "—")
        self.card_threats.pack(side="left", padx=8, expand=True, fill="x")

        self.card_round = self._metric_card(cards, "Federated Rounds", "0")
        self.card_round.pack(side="left", padx=8, expand=True, fill="x")

        lower = ttk.Frame(main, style="Main.TFrame")
        lower.pack(fill="both", expand=True, pady=(10, 0))

        left_panel = ttk.Frame(lower, style="Card.TFrame", padding=10)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 8))

        right_panel = ttk.Frame(lower, style="Card.TFrame", padding=10)
        right_panel.pack(side="left", fill="both", expand=True, padx=(8, 0))

        ttk.Label(left_panel, text="⚠️ Recent Alerts", style="Section.TLabel").pack(anchor="w")
        self.alerts_tree = ttk.Treeview(left_panel, columns=("time", "host", "sev", "details"), show="headings", height=12)
        self.alerts_tree.heading("time", text="Time")
        self.alerts_tree.heading("host", text="Host")
        self.alerts_tree.heading("sev", text="Severity")
        self.alerts_tree.heading("details", text="Details")
        self.alerts_tree.column("time", width=110, anchor="w")
        self.alerts_tree.column("host", width=80, anchor="w")
        self.alerts_tree.column("sev", width=80, anchor="center")
        self.alerts_tree.column("details", anchor="w")
        self.alerts_tree.pack(fill="both", expand=True, pady=(8, 0))
        self.alerts_tree.tag_configure("HIGH", foreground="#ff6b6b")
        self.alerts_tree.tag_configure("MEDIUM", foreground="#f59e0b")
        self.alerts_tree.tag_configure("LOW", foreground="#10b981")

        ttk.Label(right_panel, text="◉ Client Hosts", style="Section.TLabel").pack(anchor="w")
        self.clients_tree = ttk.Treeview(
            right_panel,
            columns=("host", "round", "accuracy", "packets", "threats", "phase"),
            show="headings",
            height=12,
        )
        for col, w in (("host", 80), ("round", 80), ("accuracy", 100), ("packets", 100), ("threats", 100), ("phase", 100)):
            self.clients_tree.heading(col, text=col.title())
            self.clients_tree.column(col, width=w, anchor="w")
        self.clients_tree.pack(fill="both", expand=True, pady=(8, 0))

        ttk.Label(main, text="🧾 System Logs", style="Section.TLabel").pack(anchor="w", pady=(12, 6))
        logs_frame = ttk.Frame(main, style="Card.TFrame", padding=8)
        logs_frame.pack(fill="both", expand=True)
        self.logs_text = tk.Text(logs_frame, bg="#071827", fg="#dbeafe", height=12, wrap="none", font=("Consolas", 10))
        self.logs_text.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(logs_frame, orient="vertical", command=self.logs_text.yview)
        sb.pack(side="right", fill="y")
        self.logs_text.configure(yscrollcommand=sb.set)

    def _metric_card(self, parent, label, value):
        frame = ttk.Frame(parent, style="Card.TFrame", padding=12)
        ttk.Label(frame, text=label, style="Metric.TLabel").pack(anchor="w")
        big = ttk.Label(frame, text=str(value), style="MetricBig.TLabel")
        big.pack(anchor="w", pady=(6, 0))
        return frame

    # ---------------------------
    # Process control
    # ---------------------------
    def start_system(self):
        if self.proc:
            messagebox.showinfo("Info", "System already running.")
            return
        self._flush_state()  # reset UI before start

        cmd = [
            "sudo", "env", f"PATH={os.environ.get('PATH','')}",
            sys.executable, "src/main_simple.py", "--debug", "--log-level", "DEBUG"
        ]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except Exception as e:
            messagebox.showerror("Start Failed", f"Failed to start main_simple.py:\n{e}")
            self.proc = None
            return

        self._append_log("Started main_simple.py")
        self.reader_stop.clear()
        self.reader_thread_handle = threading.Thread(target=self._reader_thread, daemon=True)
        self.reader_thread_handle.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def stop_system(self):
        if not self.proc:
            self._flush_state()
            return
        self._append_log("Stopping system...")
        try:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self._append_log("SIGINT timeout, terminating...")
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    self._append_log("Terminate timeout, killing...")
                    self.proc.kill()
        except Exception as e:
            self._append_log(f"Error stopping process: {e}")

        self.reader_stop.set()
        self._clear_queue()
        self.proc = None
        self._flush_state()  # does NOT clear logs
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    # ---------------------------
    # Reader thread + queue
    # ---------------------------
    def _reader_thread(self):
        try:
            if not self.proc or self.proc.stdout is None:
                return
            for raw_line in self.proc.stdout:
                if self.reader_stop.is_set():
                    break
                line = raw_line.rstrip("\n")
                self.output_queue.put(line)
        except Exception as e:
            self.output_queue.put(f"[READER ERROR] {e}")
        finally:
            self.output_queue.put("[PROCESS_ENDED]")

    def _clear_queue(self):
        try:
            while True:
                self.output_queue.get_nowait()
        except queue.Empty:
            return

    def _drain_output_queue(self):
        drained = False
        while True:
            try:
                line = self.output_queue.get_nowait()
            except queue.Empty:
                break
            drained = True
            if line == "[PROCESS_ENDED]":
                self._append_log("Process ended.")
                self.reader_stop.set()
                self.proc = None
                self.start_btn.configure(state="normal")
                self.stop_btn.configure(state="disabled")
                continue
            self._append_log(line)
            try:
                self._parse_log_line(line)
            except Exception as e:
                self._append_log(f"[PARSE ERROR] {e}")
        if drained:
            self._refresh_dashboard()
        self.after(200, self._drain_output_queue)

    # ---------------------------
    # Parsing logic
    # ---------------------------
    def _parse_log_line(self, line: str):
        m = RE_GLOBAL_PHASE.search(line)
        if m:
            self.current_phase = m.group(2).capitalize()
            for host in self.client_metrics.keys():
                self.client_metrics[host]["phase"] = self.current_phase
            return

        m = RE_PHASE_TRANSITION.search(line)
        if m:
            host = m.group(1).lower()
            to_phase = m.group(3).capitalize()
            self.client_metrics.setdefault(host, {})["phase"] = to_phase
            self._recent_host = host
            return

        m = RE_CLIENT_PHASE_SIMPLE.search(line)
        if m:
            host = m.group(1).lower()
            phase = m.group(2).capitalize()
            self.client_metrics.setdefault(host, {})["phase"] = phase
            self._recent_host = host
            return

        m = RE_ENHANCED_LEARNING_PROG.search(line)
        if m:
            try:
                self.global_accuracy = float(m.group(1))
                self.packets_total = int(m.group(2))
                self.threats_total = int(m.group(3))
            except Exception:
                pass
            return

        m = RE_ENHANCED_STATUS_LINE.search(line)
        if m:
            try:
                self.global_accuracy = float(m.group(1))
                self.packets_total = int(m.group(2))
                self.training_round = int(m.group(3))
            except Exception:
                pass
            return

        m = RE_ACTIVE_CLIENTS.search(line)
        if m:
            try:
                self.clients_connected = int(m.group(1))
            except Exception:
                pass
            return

        m = RE_SYSTEM_STATUS_ACTIVE.search(line)
        if m:
            try:
                self.clients_connected = int(m.group(1))
            except Exception:
                pass
        m = RE_SYSTEM_STATUS_AVGACC.search(line)
        if m:
            try:
                self.global_accuracy = float(m.group(1))
            except Exception:
                pass
        m = RE_SYSTEM_STATUS_PACKETS.search(line)
        if m:
            try:
                self.packets_total = int(m.group(1))
            except Exception:
                pass
        m = RE_SYSTEM_STATUS_THREATS.search(line)
        if m:
            try:
                self.threats_total = int(m.group(1))
            except Exception:
                pass
        m = RE_SYSTEM_STATUS_ROUNDS.search(line)
        if m:
            try:
                self.training_round = int(m.group(1))
            except Exception:
                pass

        m = RE_CLIENT_HEADER.search(line)
        if m:
            host = m.group(1).lower()
            self._recent_host = host
            self.client_metrics.setdefault(host, {})
            return

        m = RE_CLIENT_ROUND_ACC.search(line)
        if m and self._recent_host:
            try:
                self.client_metrics.setdefault(self._recent_host, {})["round"] = int(m.group(1))
                self.client_metrics[self._recent_host]["accuracy"] = float(m.group(2))
            except Exception:
                pass
            return

        m = RE_CLIENT_PACKETS_THREATS.search(line)
        if m and self._recent_host:
            try:
                self.client_metrics.setdefault(self._recent_host, {})["packets"] = int(m.group(1))
                self.client_metrics[self._recent_host]["threats"] = int(m.group(2))
            except Exception:
                pass
            return

        m = RE_TRAINING_PROGRESS.search(line)
        if m:
            host = m.group(1).lower()
            try:
                self.client_metrics.setdefault(host, {})["round"] = int(m.group(2))
            except Exception:
                pass
            self._recent_host = host
            return

        m = RE_HIGH_THREAT.search(line)
        if m:
            try:
                host = m.group(1).lower()
                conf = float(m.group(2))
                unc = float(m.group(3))
                action = m.group(4)
                self._push_alert(host, "HIGH", f"Conf={conf:.3f}, Unc={unc:.3f}, Action={action}")
            except Exception:
                pass
            return
        m = RE_HIGH_THREAT_FALLBACK.search(line)
        if m:
            try:
                host = m.group(1).lower()
                conf = float(m.group(2))
                action = m.group(3)
                self._push_alert(host, "HIGH", f"Conf={conf:.3f}, Action={action}")
            except Exception:
                pass
            return

        host_hit = re.search(r"\b(h\d+)\b[:\s]", line, re.IGNORECASE)
        if host_hit:
            self._recent_host = host_hit.group(1).lower()

    # ---------------------------
    # Alerts / UI updates
    # ---------------------------
    def _push_alert(self, host: str, severity: str, details: str):
        ts = datetime.now().strftime("%H:%M:%S")
        children = self.alerts_tree.get_children()
        if len(children) > 500:
            for iid in children[:10]:
                self.alerts_tree.delete(iid)
        self.alerts_tree.insert("", "end", values=(str(ts), str(host), str(severity), str(details)), tags=(severity,))

    def _refresh_dashboard(self):
        phase_text = None
        if self._recent_host and self._recent_host in self.client_metrics:
            phase_text = self.client_metrics[self._recent_host].get("phase")
        if not phase_text:
            hosts_sorted = sorted(self.client_metrics.keys(), key=_host_sort_key)
            for host in reversed(hosts_sorted):
                phase_text = self.client_metrics[host].get("phase")
                if phase_text:
                    break
        if not phase_text:
            phase_text = self.current_phase
        if phase_text:
            self.global_title.configure(text=f"🌐 Global Dashboard ({phase_text})")
        else:
            self.global_title.configure(text="🌐 Global Dashboard")

        self._set_card_value(self.card_clients, str(self.clients_connected))
        if isinstance(self.global_accuracy, (int, float)):
            self._set_card_value(self.card_accuracy, f"{self.global_accuracy*100:.1f}%")
        else:
            self._set_card_value(self.card_accuracy, "—")
        self._set_card_value(self.card_packets, str(self.packets_total) if self.packets_total is not None else "—")
        self._set_card_value(self.card_threats, str(self.threats_total) if self.threats_total is not None else "—")
        self._set_card_value(self.card_round, str(self.training_round))

        for iid in self.clients_tree.get_children():
            self.clients_tree.delete(iid)
        hosts = [h for h in self.client_metrics.keys() if isinstance(h, str)]
        try:
            hosts_sorted = sorted(hosts, key=_host_sort_key)
        except Exception:
            hosts_sorted = sorted(hosts)
        for host in hosts_sorted:
            m = self.client_metrics.get(host, {}) or {}
            acc = m.get("accuracy")
            acc_txt = f"{acc*100:.1f}%" if isinstance(acc, float) else "—"
            self.clients_tree.insert("", "end", values=(
                host,
                m.get("round", "—"),
                acc_txt,
                m.get("packets", "—"),
                m.get("threats", "—"),
                m.get("phase", "—"),
            ))

    def _set_card_value(self, card_frame, value):
        try:
            lbl = card_frame.winfo_children()[1]
            lbl.configure(text=str(value))
        except Exception:
            pass

    # ---------------------------
    # Utilities
    # ---------------------------
    def _append_log(self, line: str):
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.logs_text.insert("end", f"[{ts}] {line}\n")
            self.logs_text.see("end")
        except Exception:
            pass

    def _clear_logs(self):
        try:
            self.logs_text.delete("1.0", "end")
        except Exception:
            pass

    def _flush_state(self):
        self.clients_connected = 0
        self.global_accuracy = None
        self.packets_total = None
        self.threats_total = None
        self.training_round = 0
        self.client_metrics.clear()
        self._recent_host = None
        self.current_phase = None
        self._clear_queue()
        for tree in (self.alerts_tree, self.clients_tree):
            try:
                for iid in tree.get_children():
                    tree.delete(iid)
            except Exception:
                pass
        try:
            self.global_title.configure(text="🌐 Global Dashboard")
        except Exception:
            pass
        self._set_card_value(self.card_clients, "0")
        self._set_card_value(self.card_accuracy, "—")
        self._set_card_value(self.card_packets, "—")
        self._set_card_value(self.card_threats, "—")
        self._set_card_value(self.card_round, "0")

    def _on_close(self):
        if self.proc:
            if not messagebox.askyesno("Exit", "System is running. Stop and exit?"):
                return
            self.stop_system()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
