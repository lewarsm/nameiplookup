```
import tkinter as tk
from tkinter import ttk
import json
import os
import re
import requests
from datetime import datetime
import dns.resolver

# Custom theme configurations
NORD_STYLES = {
    "standard": {
        "background": "#2E3440",
        "foreground": "#D8DEE9",
        "highlight": "#88C0D0",
        "error": "#BF616A",
        "header": "#4C566A",
        "row_odd": "#3B4252",
        "row_even": "#434C5E",
        "button": "#5E81AC",
        "invert_button": "#BF616A"
    }
}

hanger_mappings = {
    'prod0': 'hanger0'
}

def open_saml_window(theme):
    saml_window = CustomWindow("SAML Decoder", 800, 600, theme)
    frame = saml_window.frame

    saml_entry = create_labeled_entry(frame, "SAML Token:", 0, 0, width=80)

    result_text = create_scrollable_text(frame, 20, 60, theme, 2, 0, 2)

    def decode_saml():
        saml_token = saml_entry.get().strip()
        if not saml_token:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a SAML token.")
            return

        try:
            # Decode the SAML token
            saml_decoded = base64.b64decode(saml_token).decode('utf-8')
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"SAML Token:\n{saml_decoded}\n\n")
        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Error decoding SAML token: {e}")

    ttk.Button(frame, text="Decode SAML", command=decode_saml).grid(row=1, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Close", command=saml_window.window.destroy).grid(row=3, column=1, padx=5, pady=5, sticky="e")

class CustomWindow:
    def __init__(self, title, width, height, theme):
        self.window = tk.Toplevel()
        self.window.title(title)
        self.window.geometry(f"{width}x{height}")
        self.theme = theme
        self.apply_theme()

        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

class CustomTable:
    def __init__(self, parent, columns, row, col, columnspan=1, title=None):
        if title:
            ttk.Label(parent, text=title, font=("Helvetica", 10, "bold")).grid(row=row, column=col, columnspan=columnspan, pady=5, sticky="w")
        self.frame = ttk.Frame(parent)
        self.frame.grid(row=row, column=col, columnspan=columnspan, padx=5, pady=5, sticky="nsew")

        self.table = ttk.Treeview(self.frame, columns=columns, show="headings")
        for col in columns:
            self.table.heading(col, text=col)
            self.table.column(col, anchor=tk.W, width=150)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.table.yview)
        self.scrollbar_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL, command=self.table.xview)
        self.table.configure(yscroll=self.scrollbar_y.set, xscroll=self.scrollbar_x.set)
        self.scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.table.bind("<Double-1>", self.delete_row)
        self.frame.rowconfigure(0, weight=1)
        self.frame.columnconfigure(0, weight=1)

    def delete_row(self, event):
        selected_item = self.table.selection()[0]
        self.table.delete(selected_item)

    def clear_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

    def insert_row(self, values):
        if all(v == "" for v in values):
            return
        self.table.insert("", "end", values=values)

class HTTPRequest:
    def __init__(self, master, style):
        self.master = master
        self.style = style
        self.is_collapsed = False
        self.setup_ui()
        self.ignore_ssl_verification = False

        self.urls = self.load_urls()
        self.update_http_table()

    def setup_ui(self):
        self.frame = ttk.LabelFrame(self.master, text="HTTPRequest", padding="10")
        self.frame.grid(row=2, column=0, sticky="nsew")

        self.table_title_frame = ttk.Frame(self.frame)
        self.table_title_frame.grid(row=0, column=0, columnspan=6, sticky="ew")
        ttk.Label(self.table_title_frame, text="HTTPRequest").pack(side=tk.LEFT)

        self.collapse_btn = ttk.Button(self.table_title_frame, text="Collapse", command=self.toggle_collapse, style="Invert.TButton")
        self.collapse_btn.pack(side=tk.RIGHT, padx=5)

        self.refresh_btn = ttk.Button(self.frame, text="Refresh", command=self.update_http_table)
        self.refresh_btn.grid(row=1, column=3, padx=5, pady=5)

        self.table = CustomTable(self.frame, ("URL", "Status Code", "Status Text", "Timestamp"), 2, 0, 6)
        
        self.frame.rowconfigure(2, weight=1)
        self.frame.columnconfigure(0, weight=1)

    def load_urls(self):
        if not os.path.exists("urls.json"):
            initial_data = [{"url" : "sso.com/pf/heartbeat.ping", "regex" : "ok" }]
            with open("urls.json", "w") as file:
                json.dump(initial_data, file)
        with open("urls.json", "r") as file:
            return json.load(file)

    def save_urls(self):
        with open("urls.json", "w") as file:
            json.dump(self.urls, file)

    def add_url(self):
        url = self.url_entry.get().strip()
        regex = self.regex_entry.get().strip()
        if url:
            self.urls.append({"url": url, "regex": regex})
            self.save_urls()
            self.update_http_table()

    def reset_urls(self):
        self.urls = [{"url" : "sso.com/pf/heartbeat.ping", "regex" : "ok" }]
        self.save_urls()
        self.update_http_table()

    def update_http_table(self):
        self.table.clear_table()
        for index, item in enumerate(self.urls):
            url = item.get("url")
            regex = item.get("regex")
            try:
                response = requests.get(f'https://{url}', verify=not self.ignore_ssl_verification)
                status_text = response.text
                if regex and re.search(regex, status_text):
                    status_text = "OK"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.table.insert_row((url, response.status_code, status_text, timestamp))
            except Exception as e:
                self.table.insert_row((url, "Error", str(e), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        self.master.after(600000, self.update_http_table)

class NSLookup:
    def __init__(self, master, style):
        self.master = master
        self.style = style
        self.is_collapsed = False
        self.setup_ui()
        self.domains = self.load_domains()
        self.update_nslookup_table()

    def setup_ui(self):
        self.frame = ttk.LabelFrame(self.master, text="NSLookup", padding="10")
        self.frame.grid(row=1, column=0, sticky="nsew")

        self.table_title_frame = ttk.Frame(self.frame)
        self.table_title_frame.grid(row=0, column=0, columnspan=4, sticky="ew")
        ttk.Label(self.table_title_frame, text="NSLookup").pack(side=tk.LEFT)

        self.collapse_btn = ttk.Button(self.table_title_frame, text="Collapse", command=self.toggle_collapse, style="Invert.TButton")
        self.collapse_btn.pack(side=tk.RIGHT, padx=5)

        self.domain_entry = ttk.Entry(self.frame, width=50)
        self.domain_entry.grid(row=1, column=0, padx=5, pady=5)
        
        self.add_domain_btn = ttk.Button(self.frame, text="Add Domain", command=self.add_domain)
        self.add_domain_btn.grid(row=1, column=1, padx=5, pady=5)

        self.refresh_btn = ttk.Button(self.frame, text="Refresh", command=self.update_nslookup_table)
        self.refresh_btn.grid(row=1, column=2, padx=5, pady=5)

        self.reset_btn = ttk.Button(self.frame, text="Reset Domains", command=self.reset_domains)
        self.reset_btn.grid(row=1, column=3, padx=5, pady=5)
                
        self.table = CustomTable(self.frame, ("Domain", "Name", "IP Address", "Hanger", "Timestamp"), 2, 0, 4)
        
        self.frame.rowconfigure(2, weight=1)
        self.frame.columnconfigure(0, weight=1)

    def toggle_collapse(self):
        if self.is_collapsed:
            self.table.frame.grid()
            self.domain_entry.grid()
            self.add_domain_btn.grid()
            self.refresh_btn.grid()
            self.reset_btn.grid()
            self.collapse_btn.config(text="Collapse")
        else:
            self.table.frame.grid_remove()
            self.domain_entry.grid_remove()
            self.add_domain_btn.grid_remove()
            self.refresh_btn.grid_remove()
            self.reset_btn.grid_remove()
            self.collapse_btn.config(text="Expand")
        self.is_collapsed = not self.is_collapsed

    def expand(self):
        if self.is_collapsed:
            self.toggle_collapse()
    
    def load_domains(self):
        try:
            with open("domains.json", "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return ["sso.fed.prod.aws.swalife.com", "sso.fed.prod.aws.swacorp.com", "sso.fed.qa.aws.swalife.com", "sso.fed.qa.aws.swacorp.com", "sso.fed.dev.aws.swalife.com", "sso.fed.dev.aws.swacorp.com", "sso.cfi.prod.aws.southwest.com"]
    
    def save_domains(self):
        with open("domains.json", "w") as file:
            json.dump(self.domains, file)
    
    def add_domain(self):
        domain = self.domain_entry.get().strip()
        if domain:
            self.domains.append(domain)
            self.save_domains()
            self.update_nslookup_table()
    
    def reset_domains(self):
        self.domains = ["sso.fed.prod.aws.swalife.com", "sso.fed.prod.aws.swacorp.com", "sso.fed.qa.aws.swalife.com", "sso.fed.qa.aws.swacorp.com", "sso.fed.dev.aws.swalife.com", "sso.fed.dev.aws.swacorp.com", "sso.cfi.prod.aws.southwest.com"]
        self.save_domains()
        self.update_nslookup_table()
    
    def update_nslookup_table(self):
        self.table.clear_table()
        resolver = dns.resolver.Resolver()
        for domain in self.domains:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                names = dns.resolver.resolve(domain, 'CNAME')
                name = names[0].to_text()
                ip_address = answers[0].to_text()
                hanger = self.get_hanger(name)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.table.insert_row((domain, name, ip_address, hanger, timestamp))
            except Exception as e:
                print(f"Error resolving {domain}: {e}")
        self.master.after(600000, self.update_nslookup_table)  # Auto-refresh every 10 minutes

    def get_hanger(self, name):
        for key, value in hanger_mappings.items():
            if key in name:
                return value
        return 'Unknown'

def main():
    create_errors_file()

    root = tk.Tk()
    root.title("tools")
    root.geometry("1200x800")

    initial_theme = load_custom_theme()
    apply_theme(initial_theme)

    menubar = tk.Menu(root)
    root.config(menu=menubar)
    
    options_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Options", menu=options_menu)
    options_menu.add_command(label="Custom Theme", command=open_custom_theme_window)

    top_frame = ttk.Frame(root, padding="5")
    top_frame.grid(row=0, column=0, columnspan=3, sticky="ew")
    ttk.Button(top_frame, text="Play Audio", command=play_audio).pack(side=tk.LEFT, padx=5, pady=5)

    main_frame = ttk.Frame(root, padding="5")
    main_frame.grid(row=1, column=0, columnspan=3, sticky="nsew")

    scrollbar = ttk.Scrollbar(main_frame, orient="vertical")
    scrollbar_x = ttk.Scrollbar(main_frame, orient="horizontal")
    
    scrollable_frame = ttk.Frame(main_frame)
    scrollable_frame.grid(row=0, column=0, sticky="nsew")
    
    scrollbar.grid(row=0, column=1, sticky="ns")
    scrollbar_x.grid(row=1, column=0, sticky="ew")
    
    main_frame.grid_rowconfigure(0, weight=1)
    main_frame.grid_columnconfigure(0, weight=1)

    for i in range(3):
        root.rowconfigure(i + 1, weight=1)
    root.columnconfigure(0, weight=1)

    theme_var = tk.StringVar(value=initial_theme)
    
    sidebar = ttk.Frame(scrollable_frame, padding="5")
    sidebar.grid(row=0, column=1, rowspan=10, sticky="ns")

    ttk.Label(sidebar, text="Choose Theme:").grid(row=1, column=0, padx=5, pady=5)
    ttk.Radiobutton(sidebar, text="Nord", variable=theme_var, value="standard", command=lambda: apply_theme(theme_var.get())).grid(row=2, column=0, padx=5, pady=5)
    ttk.Label(sidebar, text="Diagnostic Tools:").grid(row=5, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="SAML Decoder", command=lambda: open_saml_window(theme_var.get())).grid(row=8, column=0, padx=5, pady=5)

    nslookup = NSLookup(scrollable_frame, theme_var.get())
    http_request = HTTPRequest(scrollable_frame, theme_var.get())
 
    for widget in scrollable_frame.winfo_children():
        widget.grid_configure(sticky="nsew")

    scrollable_frame.columnconfigure(0, weight=1)
    scrollable_frame.rowconfigure(1, weight=1)
    scrollable_frame.rowconfigure(2, weight=1)
    scrollable_frame.rowconfigure(3, weight=1)
    scrollable_frame.rowconfigure(4, weight=1)
    scrollable_frame.rowconfigure(5, weight=1)

    apply_theme(theme_var.get())
    nslookup.expand()
    http_request.expand()
    root.mainloop()

if __name__ == "__main__":
    custom_theme = load_custom_theme()
    main()

```
