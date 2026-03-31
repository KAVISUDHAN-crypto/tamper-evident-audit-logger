# gui.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tamper_log import add_log_entry, verify_log_chain
from log_store import create_db
import sqlite3


DB_PATH = "audit_log.db"


class TamperLogUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Tamper‑Evident Audit Logger")
        self.root.geometry("900x600")
        self.root.minsize(700, 400)

        # Create DB if not exists
        create_db(DB_PATH)

        self.setup_widgets()
        self.load_entries()

    def setup_widgets(self):
        # --- Header ---
        header = tk.Frame(self.root, bg="#005f73")
        header.pack(fill="x", pady=(0, 10))

        tk.Label(
            header,
            text="Tamper‑Evident Audit Logger",
            bg="#005f73",
            fg="white",
            font=("Segoe UI", 14, "bold"),
            padx=10,
            pady=5,
        ).pack()

        # --- Form frame ---
        form_frame = tk.Frame(self.root, padx=10, pady=5)
        form_frame.pack(fill="x", pady=(0, 10))

        tk.Label(form_frame, text="Event Type:", font=("Segoe UI", 10)).grid(row=0, column=0, padx=5, sticky="w")
        self.event_type_var = tk.StringVar(value="USER_ACTIVITY")
        ttk.Combobox(
            form_frame,
            textvariable=self.event_type_var,
            values=["LOGIN_ATTEMPT", "TRANSACTION", "USER_ACTIVITY"],
            state="readonly",
            width=30,
        ).grid(row=0, column=1, padx=5, sticky="w")

        tk.Label(form_frame, text="Description:", font=("Segoe UI", 10)).grid(row=0, column=2, padx=5, sticky="w")
        self.desc_var = tk.StringVar()
        tk.Entry(
            form_frame,
            textvariable=self.desc_var,
            width=40,
            font=("Segoe UI", 10),
        ).grid(row=0, column=3, padx=5, sticky="we")

        self.desc_var.set("Enter description here...")

        tk.Button(
            form_frame,
            text="Add Log Entry",
            command=self.add_entry,
            bg="#028090",
            fg="white",
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=4, padx=10, ipadx=5)

        form_frame.columnconfigure(3, weight=1)

        # --- Buttons ---
        btn_frame = tk.Frame(self.root, padx=10, pady=5)
        btn_frame.pack(fill="x")

        tk.Button(
            btn_frame,
            text="Verify Integrity",
            command=self.do_verify,
            bg="#8B0000",
            fg="white",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=5)

        tk.Button(
            btn_frame,
            text="Refresh List",
            command=self.load_entries,
            bg="#0077B6",
            fg="white",
            font=("Segoe UI", 10),
        ).pack(side="left", padx=5)

        # --- Treeview (log table) ---
        tree_frame = tk.Frame(self.root, padx=10, pady=5)
        tree_frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("id", "timestamp", "event_type", "description", "this_hash"),
            show="headings",
            height=15,
        )
        self.tree.pack(side="left", fill="both", expand=True)

        for col, text, w in [
            ("id", "ID", 40),
            ("timestamp", "Timestamp", 150),
            ("event_type", "Event", 120),
            ("description", "Description", 250),
            ("this_hash", "Hash (short)", 150),
        ]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w, anchor="w")

        # Scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=vsb.set)

        # --- Status text box ---
        status_frame = tk.Frame(self.root, padx=10, pady=5)
        status_frame.pack(fill="x")

        tk.Label(
            status_frame,
            text="Integrity Status:",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")

        self.status_text = scrolledtext.ScrolledText(
            status_frame,
            height=6,
            font=("Segoe UI", 9),
            wrap="word",
        )
        self.status_text.pack(fill="x", expand=True, pady=(5, 0))

    def run_query(self, query, params=()):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
        return rows

    def load_entries(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        rows = self.run_query(
            "SELECT id, timestamp, event_type, description, this_hash FROM log_entries ORDER BY id"
        )
        for row in rows:
            id_, ts, etype, desc, hash_ = row
            self.tree.insert(
                "",
                "end",
                values=(id_, ts, etype, desc, hash_[:12]),
            )

    def add_entry(self):
        etype = self.event_type_var.get()
        desc = self.desc_var.get().strip()

        if not desc or desc == "Enter description here...":
            messagebox.showwarning("Input Error", "Please enter a valid description.")
            return

        try:
            add_log_entry(DB_PATH, etype, desc)
            self.desc_var.set("")
            self.load_entries()
            messagebox.showinfo("Success", "Log entry added.")
        except Exception as e:
            messagebox.showerror("Error", "Failed to add log entry: " + str(e))

    def do_verify(self):
        ok, bad_ids = verify_log_chain(DB_PATH)
        self.status_text.delete(1.0, tk.END)

        if ok:
            self.status_text.insert(
                tk.END,
                "✓ Log chain integrity verified; no tampering detected.\n",
                "ok",
            )
        else:
            self.status_text.insert(
                tk.END,
                f"✗ Tampering detected around IDs: {sorted(bad_ids)}",
            )

        # Highlight tampered entries in the tree
        self.highlight_tampered(bad_ids)

    def highlight_tampered(self, bad_ids):
        # Clean old tags
        self.tree.tag_configure("ok", background="white")
        self.tree.tag_configure("tampered", background="#ffaaaa")

        # Highlight bad IDs
        for child in self.tree.get_children():
            value = self.tree.item(child)["values"]
            if value and value[0] in bad_ids:
                self.tree.item(child, tags=("tampered",))
            else:
                self.tree.item(child, tags=("ok",))


if __name__ == "__main__":
    root = tk.Tk()
    app = TamperLogUI(root)
    root.mainloop()
