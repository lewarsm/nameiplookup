```
import json
import dns.resolver
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog

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
        
        self.table = CustomTable(self.frame, ("Domain", "Name", "IP Address", "Region", "Timestamp"), 2, 0, 4, title="NSLookup Results")
        
        self.frame.rowconfigure(2, weight=1)
        self.frame.columnconfigure(0, weight=1)

    def toggle_collapse(self):
        if self.is_collapsed:
            self.table.tree.grid()
            self.domain_entry.grid()
            self.add_domain_btn.grid()
            self.refresh_btn.grid()
            self.reset_btn.grid()
            self.collapse_btn.config(text="Collapse")
        else:
            self.table.tree.grid_remove()
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
            with open("nslookup.json", "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return ["google.com", "yahoo.com", "mail.com", "dogpile.com"]
    
    def save_domains(self):
        with open("nslookup.json", "w") as file:
            json.dump(self.domains, file)
    
    def add_domain(self):
        domain = self.domain_entry.get().strip()
        if domain:
            self.domains.append(domain)
            self.save_domains()
            self.update_nslookup_table()
    
    def reset_domains(self):
        self.domains = ["google.com", "yahoo.com", "mail.com", "dogpile.com"]
        self.save_domains()
        self.update_nslookup_table()
    
    def update_nslookup_table(self):
        self.table.clear_table()
        resolver = dns.resolver.Resolver()
        for domain in self.domains:
            try:
                answer = resolver.resolve(domain, 'A')
                for rdata in answer:
                    region = REGION_MAPPINGS.get(domain.split('.')[0], "unknown")
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.table.insert_row((domain, rdata, rdata.address, region, timestamp))
            except Exception as e:
                print(f"Error resolving {domain}: {e}")
        self.master.after(600000, self.update_nslookup_table)  # Auto-refresh every 10 minutes



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

        self.url_entry = ttk.Entry(self.frame, width=50)
        self.url_entry.grid(row=1, column=0, padx=5, pady=5)
        
        self.regex_entry = ttk.Entry(self.frame, width=50)
        self.regex_entry.grid(row=1, column=1, padx=5, pady=5)
        self.regex_entry.insert(0, "Enter regex")

        self.add_url_btn = ttk.Button(self.frame, text="Add URL", command=self.add_url)
        self.add_url_btn.grid(row=1, column=2, padx=5, pady=5)

        self.refresh_btn = ttk.Button(self.frame, text="Refresh", command=self.update_http_table)
        self.refresh_btn.grid(row=1, column=3, padx=5, pady=5)

        self.reset_btn = ttk.Button(self.frame, text="Reset URLs", command=self.reset_urls)
        self.reset_btn.grid(row=1, column=4, padx=5, pady=5)

        self.ignore_ssl_btn = ttk.Button(self.frame, text="Ignore SSL Verification", command=self.toggle_ssl_verification)
        self.ignore_ssl_btn.grid(row=1, column=5, padx=5, pady=5)
        
        self.table = CustomTable(self.frame, ("URL", "Status Code", "Status Text", "Timestamp"), 2, 0, 6, title="HTTP Request Results")
        
        self.frame.rowconfigure(2, weight=1)
        self.frame.columnconfigure(0, weight=1)

    def toggle_collapse(self):
        if self.is_collapsed:
            self.table.tree.grid()
            self.url_entry.grid()
            self.regex_entry.grid()
            self.add_url_btn.grid()
            self.refresh_btn.grid()
            self.reset_btn.grid()
            self.ignore_ssl_btn.grid()
            self.collapse_btn.config(text="Collapse")
        else:
            self.table.tree.grid_remove()
            self.url_entry.grid_remove()
            self.regex_entry.grid_remove()
            self.add_url_btn.grid_remove()
            self.refresh_btn.grid_remove()
            self.reset_btn.grid_remove()
            self.ignore_ssl_btn.grid_remove()
            self.collapse_btn.config(text="Expand")
        self.is_collapsed = not self.is_collapsed

    def toggle_ssl_verification(self):
        self.ignore_ssl_verification = not self.ignore_ssl_verification
        btn_text = "Verify SSL" if self.ignore_ssl_verification else "Ignore SSL Verification"
        self.ignore_ssl_btn.config(text=btn_text)

    def expand(self):
        if self.is_collapsed:
            self.toggle_collapse()

    def load_urls(self):
        if not os.path.exists("urls.json"):
            initial_data = [{"url": "www.google.com", "regex": "ok"}]
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
        self.urls = [{"url": "https://status.cloud.google.com", "regex": "ok"}, {"url": "https://portal.office.com", "regex": "ok"}]
        self.save_urls()
        self.update_http_table()

    def update_http_table(self):
        self.table.clear_table()
        for index, item in enumerate(self.urls):
            url = item.get("url")
            regex = item.get("regex")
            try:
                response = requests.get(url, verify=not self.ignore_ssl_verification)
                status_text = response.text
                if regex and re.search(regex, status_text):
                    status_text = "OK"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.table.insert_row((url, response.status_code, status_text, timestamp))
            except Exception as e:
                self.table.insert_row((url, "Error", str(e), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        self.master.after(600000, self.update_http_table)

def backup_data():
    try:
        data = {
            "nslookup": NSLookup(None, None).load_domains(),
            "httprequest": HTTPRequest(None, None).load_urls(),
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

    ttk.Button(toolbar_frame, text="Backup Data", command=backup_data).pack(side=tk.LEFT, padx=5, pady=5)
    ttk.Button(toolbar_frame, text="Restore Data", command=restore_data).pack(side=tk.LEFT, padx=5, pady=5)

    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(main_frame, text="Choose a tool:", font=("Helvetica", 16)).pack(pady=10)

    tools_frame = ttk.Frame(main_frame, padding="10")
    tools_frame.pack(fill=tk.BOTH, expand=True)

    theme = "clam"

    ttk.Button(tools_frame, text="OAuth Debugger", command=lambda: open_oidc_window(theme)).grid(row=0, column=0, padx=5, pady=5)
    ttk.Button(tools_frame, text="NSLookup Tool", command=lambda: NSLookup(root, style)).grid(row=0, column=1, padx=5, pady=5)
    ttk.Button(tools_frame, text="HTTPRequest Tool", command=lambda: HTTPRequest(root, style)).grid(row=1, column=0, padx=5, pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_main_window()
```
