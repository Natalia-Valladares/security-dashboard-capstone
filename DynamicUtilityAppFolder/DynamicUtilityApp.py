import os
import importlib.util
import tkinter as tk
from tkinter import ttk

# ---------------- Colors ----------------
BG_BLACK = "#000000"
CREAM = "#FFF8E1"
DARK_GREEN = "#0b5d3b"
PANEL_BG = "#0f0f0f"

class DynamicUtilityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dynamic Utility App")
        self.state("zoomed")
        self.configure(bg=BG_BLACK)

        self._setup_styles()
        self._create_sidebar()
        self._create_main_panel()
        self.build_dynamic_sidebar()

    # ---------------- Styles ----------------
    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(
            "Treeview",
            background=BG_BLACK,
            foreground=CREAM,
            fieldbackground=BG_BLACK,
            rowheight=28,
            font=("Segoe UI", 10),
        )
        s.configure(
            "Treeview.Heading",
            background=DARK_GREEN,
            foreground=CREAM,
            font=("Segoe UI", 10, "bold"),
        )
        s.map(
            "Treeview",
            background=[("selected", "#1a7b50")],
            foreground=[("selected", "white")],
        )

    # ---------------- Sidebar ----------------
    def _create_sidebar(self):
        self.sidebar = tk.Frame(self, bg=PANEL_BG, width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        tk.Label(
            self.sidebar,
            text="Menu",
            font=("Segoe UI", 14, "bold"),
            bg=PANEL_BG,
            fg=CREAM,
        ).pack(pady=(16, 8))

    # ---------------- Main Panel ----------------
    def _create_main_panel(self):
        self.main_frame = tk.Frame(self, bg=BG_BLACK)
        self.main_frame.pack(side="left", fill="both", expand=True, padx=8, pady=8)

        self.title_label = tk.Label(
            self.main_frame,
            text="",
            font=("Segoe UI", 18, "bold"),
            bg=BG_BLACK,
            fg=CREAM,
            anchor="w",
        )
        self.title_label.pack(fill="x", pady=(0, 5))

        table_frame = tk.Frame(self.main_frame, bg=BG_BLACK)
        table_frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(table_frame, columns=(), show="headings")
        self.tree.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

    # ---------------- Scan Functions Folder ----------------
    def scan_py_files(self, folder):
        """
        Scan the Functions folder for .py files and extract:
        - #title: 'Module Title'
        - #btn: 'Button Name'
        Returns:
            { title: [(button_name, file_path), ...], ... }
        """
        data = {}
        if not os.path.exists(folder):
            print(f"[DEBUG] Folder does not exist: {folder}")
            return data

        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    title = None
                    btns = []
                    with open(full_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("#title:"):
                                title = line.split(":", 1)[1].strip().strip("'\"")
                            elif line.startswith("#btn:"):
                                btn_name = line.split(":", 1)[1].strip().strip("'\"")
                                btns.append((btn_name, full_path))
                    if title and btns:
                        if title in data:
                            data[title].extend(btns)
                        else:
                            data[title] = btns
        return data

    # ---------------- Load Module ----------------
    def load_module_class(self, file_path):
        """
        Dynamically load a utility class from a module file.

        Priority:
        1. Class named '<Something>Utility' (e.g., SecurityDashboardUtility)
        2. Any user-defined class from this module
        """
        spec = importlib.util.spec_from_file_location(os.path.basename(file_path), file_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        cls = None

        # 1) Prefer classes whose names end with 'Utility'
        for name, obj in vars(mod).items():
            if isinstance(obj, type) and name.endswith("Utility"):
                cls = obj
                break

        # 2) Fallback: any class defined in this module (not imported)
        if cls is None:
            for name, obj in vars(mod).items():
                if isinstance(obj, type) and obj.__module__ == mod.__name__:
                    cls = obj
                    break

        if cls is None:
            raise Exception(f"No suitable class found in {file_path}")

        # Instantiate class (handle both normal and no-arg classes)
        try:
            instance = cls()
        except TypeError:
            instance = cls

        print(f"[DEBUG] Loaded class {cls.__name__} from {file_path}")
        return instance


    # ---------------- Call Function ----------------
    def call_module_function(self, module_instance, btn_name):
        """
        Convert button text into function name:
            'Security Findings' -> get_security_findings
        and call it on the module instance.
        """
        func_name = "get_" + btn_name.lower().replace(" ", "_")
        if hasattr(module_instance, func_name):
            columns, rows = getattr(module_instance, func_name)()
            self.populate_tree(columns, rows)
            self.title_label.config(text=btn_name)
        else:
            self.title_label.config(text=f"{btn_name} (function not found)")
            self.populate_tree(["Message"], [("⚠️ Function not implemented.",)])

    # ---------------- Populate Treeview ----------------
    def populate_tree(self, cols, rows):
        tree = self.tree
        tree.delete(*tree.get_children())
        tree["columns"] = cols
        tree["show"] = "headings"

        for c in cols:
            tree.heading(c, text=c, anchor="center")
            tree.column(c, width=150, anchor="center")

        # Empty data case
        if not rows:
            tree["columns"] = ("Message",)
            tree.heading("Message", text="")
            tree.column("Message", anchor="center", width=800)
            tree.insert("", "end", values=("⚠️ No data found.",))
            return

        for i, r in enumerate(rows):
            tag = "evenrow" if i % 2 == 0 else "oddrow"

            # Device Health status coloring
            if cols == ("Device ID", "Device Name", "Status", "Last Checked"):
                status = str(r[2]).strip().lower()  # third column is Status
                if status == "critical":
                    tag = "status_critical"
                elif status == "warning":
                    tag = "status_warning"
                elif status == "good":
                    tag = "status_good"
                else:
                    # Fallback heuristics for legacy/raw values
                    if any(
                        tok in status
                        for tok in (
                            "battery",
                            "offline",
                            "no data",
                            "deleted",
                            "out of service",
                            "dead",
                            "critical",
                        )
                    ):
                        tag = "status_warning"

            tree.insert("", "end", values=r, tags=(tag,))

        # Configure row tag styles (parity + status)
        tree.tag_configure("evenrow", background="#000000", foreground=CREAM)
        tree.tag_configure("oddrow", background="#0f3021", foreground=CREAM)
        tree.tag_configure("status_critical", background="#661111", foreground=CREAM)
        tree.tag_configure("status_warning", background="#7a4e00", foreground=CREAM)
        tree.tag_configure("status_good", background=DARK_GREEN, foreground=CREAM)

    # ---------------- Build Dynamic Sidebar ----------------
    def build_dynamic_sidebar(self):
        """
        Scan Functions/ for modules, build the left-hand sidebar:
        - Each #title: becomes a top-level button.
        - Each #btn: under that file becomes a dropdown button.
        """
        folder = os.path.join(os.path.dirname(__file__), "Functions")
        print("[DEBUG] Scanning Functions folder:", folder)
        data = self.scan_py_files(folder)


        for title, btn_list in data.items():
            print("[DEBUG] Found title:", title)
            for btn_name, module_file in btn_list:
                print("    [DEBUG] Button:", btn_name, "from file:", module_file)

            # Container for title button + dropdown
            container = tk.Frame(self.sidebar, bg=PANEL_BG)
            container.pack(fill="x")

            # Main button (title)
            main_btn = tk.Button(
                container,
                text=f"{title} ▸",
                bg=DARK_GREEN,
                fg=CREAM,
                relief="flat",
                anchor="w",
            )
            main_btn.pack(fill="x", padx=12, pady=6)

            # Frame for dropdown buttons
            frame = tk.Frame(container, bg=PANEL_BG)
            frame.pack(fill="x", padx=12, pady=0)
            frame.pack_forget()  # initially hidden

            # Toggle function for dropdown
            def toggle(f=frame, b=main_btn, t=title):
                if f.winfo_ismapped():
                    f.pack_forget()
                    b.config(text=f"{t} ▸")
                else:
                    f.pack(fill="x", padx=12)
                    b.config(text=f"{t} ▾")

            main_btn.config(command=toggle)

            # Add buttons under the dropdown
            for btn_name, module_file in btn_list:
                mod_instance = self.load_module_class(module_file)
                tk.Button(
                    frame,
                    text=btn_name,
                    bg=PANEL_BG,
                    fg=CREAM,
                    relief="flat",
                    anchor="w",
                    padx=12,
                    command=lambda m=mod_instance, b=btn_name: self.call_module_function(m, b),
                ).pack(fill="x", pady=2)

# ---------------- Run App ----------------
if __name__ == "__main__":
    app = DynamicUtilityApp()
    app.mainloop()
