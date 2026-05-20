from __future__ import annotations

import os
import pickle
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from http.server import HTTPServer

# Ensure project root on sys.path
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from apps.cli.csp_server import Handler, CSPState
from apps.cli.user_management import ensure_user_db


class ServerApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("ST-VLS CSP Control Center")
        self.root.geometry("980x660")
        self.root.minsize(900, 620)

        default_aui = os.path.join(PROJ_ROOT, "apps", "cli", "aui.pkl")
        default_user_db = os.path.join(PROJ_ROOT, "apps", "cli", "users_db.json")
        self.aui_path_var = tk.StringVar(value=default_aui)
        self.user_db_var = tk.StringVar(value=default_user_db)
        self.ports_var = tk.StringVar(value="8001,8002,8003")
        self.status_var = tk.StringVar(value="Servers stopped")

        self._configure_style()
        self._build_layout()

        self.servers: list[HTTPServer] = []
        self.threads: list[threading.Thread] = []
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self.root.configure(bg="#eef4fb")
        style.configure("Root.TFrame", background="#eef4fb")
        style.configure("Card.TLabelframe", background="#ffffff", borderwidth=1, relief="solid")
        style.configure("Card.TLabelframe.Label", background="#ffffff", foreground="#173f5f", font=("Segoe UI Semibold", 10))
        style.configure("Title.TLabel", background="#eef4fb", foreground="#0f2740", font=("Segoe UI Semibold", 16))
        style.configure("Sub.TLabel", background="#eef4fb", foreground="#52708f", font=("Segoe UI", 9))
        style.configure("Status.TLabel", background="#eef4fb", foreground="#133b5c", font=("Segoe UI", 10, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 10))
        style.configure("TButton", font=("Segoe UI", 9))
        style.configure("TLabel", font=("Segoe UI", 9))
        style.configure("TEntry", font=("Consolas", 10))

    def _build_layout(self) -> None:
        root_frame = ttk.Frame(self.root, style="Root.TFrame", padding=14)
        root_frame.pack(fill=tk.BOTH, expand=True)
        root_frame.columnconfigure(0, weight=1)
        root_frame.rowconfigure(4, weight=1)

        ttk.Label(root_frame, text="ST-VLS CSP Control Center", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            root_frame,
            text="Manage CSP nodes with RBAC-enabled runtime",
            style="Sub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(0, 8))

        card = ttk.LabelFrame(root_frame, text="Server Configuration", style="Card.TLabelframe", padding=(10, 8))
        card.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="AUI path:").grid(row=0, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Entry(card, textvariable=self.aui_path_var).grid(row=0, column=1, sticky="ew", padx=(0, 6), pady=6)
        ttk.Button(card, text="Browse", command=lambda: self._browse(self.aui_path_var)).grid(row=0, column=2, padx=(0, 8), pady=6)

        ttk.Label(card, text="User DB path:").grid(row=1, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Entry(card, textvariable=self.user_db_var).grid(row=1, column=1, sticky="ew", padx=(0, 6), pady=6)
        ttk.Button(card, text="Browse", command=lambda: self._browse(self.user_db_var)).grid(row=1, column=2, padx=(0, 8), pady=6)

        ttk.Label(card, text="Ports (comma separated):").grid(row=2, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Entry(card, textvariable=self.ports_var).grid(row=2, column=1, sticky="ew", padx=(0, 6), pady=6)
        ttk.Label(card, text="Default users: admin/alice/bob", foreground="#58748f").grid(row=2, column=2, sticky="w", padx=(0, 8), pady=6)

        inline_actions = ttk.Frame(card)
        inline_actions.grid(row=3, column=1, columnspan=2, sticky="w", padx=(0, 8), pady=(0, 8))
        ttk.Button(
            inline_actions,
            text="Open Ports / 开启CSP端口",
            style="Accent.TButton",
            command=self.start_servers,
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            inline_actions,
            text="Close Ports / 关闭CSP端口",
            command=self.stop_servers,
        ).pack(side=tk.LEFT, padx=6)

        actions = ttk.Frame(root_frame, style="Root.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(actions, textvariable=self.status_var, style="Status.TLabel").pack(side=tk.RIGHT, padx=4)

        log_card = ttk.LabelFrame(root_frame, text="Server Logs", style="Card.TLabelframe", padding=(8, 8))
        log_card.grid(row=4, column=0, sticky="nsew")
        log_card.columnconfigure(0, weight=1)
        log_card.rowconfigure(0, weight=1)

        self.log_box = tk.Text(
            log_card,
            bg="#fbfdff",
            fg="#12263a",
            insertbackground="#12263a",
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=8,
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self.log_box.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(log_card, orient="vertical", command=self.log_box.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_box.configure(yscrollcommand=scroll.set)

    def _browse(self, var: tk.StringVar) -> None:
        path = filedialog.askopenfilename(initialdir=PROJ_ROOT)
        if path:
            var.set(path)

    def append_log(self, text: str) -> None:
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def start_servers(self) -> None:
        if self.servers:
            messagebox.showinfo("Info", "Servers are already running.")
            return
        try:
            with open(self.aui_path_var.get().strip(), "rb") as f:
                aui = pickle.load(f)
            CSPState.aui = aui
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to load AUI: {exc}")
            return

        user_db_path = self.user_db_var.get().strip()
        if not user_db_path:
            messagebox.showwarning("Warning", "User DB path is required.")
            return
        try:
            ensure_user_db(user_db_path)
            CSPState.user_db_path = user_db_path
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to init user DB: {exc}")
            return

        ports = []
        for item in self.ports_var.get().split(","):
            item = item.strip()
            if not item:
                continue
            try:
                ports.append(int(item))
            except ValueError:
                messagebox.showerror("Error", f"Invalid port: {item}")
                return
        if not ports:
            messagebox.showwarning("Warning", "Provide at least one port.")
            return

        started = []
        try:
            for port in ports:
                server = HTTPServer(("0.0.0.0", port), Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self.servers.append(server)
                self.threads.append(thread)
                started.append(port)
                self.append_log(f"Started CSP server on port {port} (UserDB={user_db_path})")
        except Exception as exc:
            self.append_log(f"Failed to start server: {exc}")
            messagebox.showerror("Error", f"Failed to start server: {exc}")
            self.stop_servers()
            return
        self.status_var.set(f"Servers running on: {', '.join(str(p) for p in started)}")

    def stop_servers(self) -> None:
        for server in self.servers:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        if self.servers:
            self.append_log("Servers stopped")
        self.servers.clear()
        self.threads.clear()
        self.status_var.set("Servers stopped")

    def on_close(self) -> None:
        self.stop_servers()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    app = ServerApp()
    app.run()


if __name__ == "__main__":
    main()
