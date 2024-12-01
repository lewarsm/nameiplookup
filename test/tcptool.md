```

import subprocess
import dns.resolver
from datetime import datetime
import tkinter as tk
from tkinter import ttk

class CustomTable:
    def __init__(self, parent, columns, row, column, columnspan=1, title=None):
        if title:
            ttk.Label(parent, text=title, font=("Helvetica", 10, "bold")).grid(row=row-1, column=column, columnspan=columnspan, pady=5, sticky="w")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings")
        self.tree.grid(row=row, column=column, columnspan=columnspan, sticky="nsew")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, stretch=tk.YES, anchor="center")
        self.tree.bind("<Double-1>", self.delete_row)
        scrollbar_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_y.grid(row=row, column=column + columnspan, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar_y.set)
        scrollbar_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.tree.xview)
        scrollbar_x.grid(row=row + 1, column=column, columnspan=columnspan, sticky="ew")
        self.tree.configure(xscrollcommand=scrollbar_x.set)

    def insert_row(self, values):
        self.tree.insert("", "end", values=values)

    def clear_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def get_value(self, column):
        for row in self.tree.get_children():
            return self.tree.item(row)["values"][self.tree["columns"].index(column)]

    def delete_row(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            self.tree.delete(selected_item[0])

class CustomWindow:
    def __init__(self, title, width, height, theme):
        self.window = tk.Toplevel()
        self.window.title(title)
        self.window.geometry(f"{width}x{height}")
        self.apply_theme(theme)
        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

    def apply_theme(self, theme):
        style = ttk.Style()
        style.theme_use(theme)

def create_labeled_entry(parent, label_text, row, column, width=30):
    label = ttk.Label(parent, text=label_text)
    label.grid(row=row, column=column, padx=5, pady=5, sticky="w")
    entry = ttk.Entry(parent, width=width)
    entry.grid(row=row, column=column + 1, padx=5, pady=5, sticky="w")
    return entry

def create_scrollable_text(parent, rows, columns, theme, row, column, columnspan=1):
    frame = ttk.Frame(parent)
    frame.grid(row=row, column=column, columnspan=columnspan, sticky="nsew")
    text = tk.Text(frame, wrap=tk.WORD, height=rows, width=columns)
    text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
    text.configure(yscrollcommand=scrollbar_y.set)
    scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text.xview)
    scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
    text.configure(xscrollcommand=scrollbar_x.set)
    return text

def open_tcp_tools_window(theme):
    tcp_tools_window = CustomWindow("TCP Tools", 800, 600, theme)
    frame = tcp_tools_window.frame

    host_entry = create_labeled_entry(frame, "Host:", 0, 0)

    tool_selection = ttk.Combobox(frame, values=["Ping", "Dig", "Traceroute"], state="readonly")
    tool_selection.grid(row=1, column=0, padx=5, pady=5)
    tool_selection.set("Ping")

    result_text = create_scrollable_text(frame, 20, 60, theme, 3, 0, 2)

    def run_tool():
        host = host_entry.get().strip()
        tool = tool_selection.get()
        if host:
            try:
                result_text.delete(1.0, tk.END)
                if tool == "Ping":
                    response = subprocess.run(["ping", "-c", "4", host], capture_output=True, text=True)
                elif tool == "Dig":
                    response = subprocess.run(["dig", host], capture_output=True, text=True)
                elif tool == "Traceroute":
                    response = subprocess.run(["traceroute", host], capture_output=True, text=True)
                else:
                    result_text.insert(tk.END, "Unknown tool selected.")
                    return
                result_text.insert(tk.END, response.stdout)
            except Exception as e:
                result_text.insert(tk.END, f"Error running {tool}: {e}")

    ttk.Button(frame, text="Run", command=run_tool).grid(row=2, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Close", command=tcp_tools_window.window.destroy).grid(row=4, column=1, padx=5, pady=5, sticky="e")

def backup_data(nslookup_instance, httprequest_instance):
    try:
        data = {
            "nslookup": nslookup_instance.load_domains(),
            "httprequest": httprequest_instance.load_urls(),
            "theme": ttk.Style().theme_use()
        }
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"backup_{timestamp}.json"
        with open(filename, "w") as file:
            json.dump(data, file)
        print(f"Backup created: {filename}")
    except Exception as e:
        print(f"Error creating backup: {e}")

def restore_data():
    filename = filedialog.askopenfilename(title="Select Backup File", filetypes=[("JSON files", "*.json")])
    if filename:
        try:
            with open(filename, "r") as file:
                data = json.load(file)
            with open("nslookup.json", "w") as ns_file:
                json.dump(data.get("nslookup", []), ns_file)
            with open("urls.json", "w") as http_file:
                json.dump(data.get("httprequest", []), http_file)
            ttk.Style().theme_use(data.get("theme", "clam"))
            print(f"Data restored from {filename}")
        except Exception as e:
            print(f"Error restoring data: {e}")

def create_main_window():
    root = tk.Tk()
    root.title("Multi-Tool Application")
    root.geometry("800x600")

    toolbar_frame = ttk.Frame(root, padding="5")
    toolbar_frame.pack(fill=tk.X)

    nslookup_instance = NSLookup(root, None)
    httprequest_instance = HTTPRequest(root, None)

    ttk.Button(toolbar_frame, text="Backup Data", command=lambda: backup_data(nslookup_instance, httprequest_instance)).pack(side=tk.LEFT, padx=5, pady=5)
    ttk.Button(toolbar_frame, text="Restore Data", command=restore_data).pack(side=tk.LEFT, padx=5, pady=5)

    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    sidebar_frame = ttk.Frame(main_frame, padding="5")
    sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

    tools_frame = ttk.Frame(main_frame, padding="10")
    tools_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # Add the sidebar label
    ttk.Label(sidebar_frame, text="Diagnostic Tools", font=("Helvetica", 14, "bold")).pack(pady=(0, 10))

    # Add TCP Tools button to the sidebar
    ttk.Button(sidebar_frame, text="TCP Tools", command=lambda: open_tcp_tools_window("clam")).pack(pady=5)

    # Add JWKS Check Tool button to the sidebar
    ttk.Button(sidebar_frame, text="JWKS Check Tool", command=lambda: open_jwks_check_window("clam")).pack(pady=5)

    # Existing setup
    ttk.Label(tools_frame, text="Choose a tool:", font=("Helvetica", 16)).pack(pady=10)

    ttk.Button(tools_frame, text="OAuth Debugger", command=lambda: open_oidc_window("clam")).pack(pady=5)
    ttk.Button(tools_frame, text="NSLookup Tool", command=lambda: nslookup_instance.expand()).pack(pady=5)
    ttk.Button(tools_frame, text="HTTPRequest Tool", command=lambda: httprequest_instance.expand()).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_main_window()

```
