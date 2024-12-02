```
import tkinter as tk
from tkinter import ttk
from datetime import datetime
import dns.resolver
import json

class CustomWindow:
    def __init__(self, title, width, height, theme):
        self.window = tk.Toplevel()
        self.window.title(title)
        self.window.geometry(f"{width}x{height}")
        self.theme = theme
        self.apply_theme()

        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

    def add_scrollbar(self, widget):
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=widget.yview)
        widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

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

    def clear_table(self):
        for row in self.table.get_children():
            self.table.delete(row)

    def insert_row(self, values):
        self.table.insert("", "end", values=values)

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
            return ["sso.fed.prod.aws.swalife.com"]
    
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
        self.domains = ["sso.fed.prod.aws.swalife.com"]
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
        self.master.after(600000, self.update_nslookup_table)  

    def get_hanger(self, name):
        for key, value in hanger_mappings.items():
            if key in name:
                return value
        return 'Unknown'

class HTTPRequest:
    def __init__(self, master, style):
        self.master = master
        self.style = style
        self.is_collapsed = False
        self.setup_ui()

    def setup_ui(self):
        self.frame = ttk.LabelFrame(self.master, text="HTTPRequest", padding="10")
        self.frame.grid(row=2, column=0, sticky="nsew")

        self.table_title_frame = ttk.Frame(self.frame)
        self.table_title_frame.grid(row=0, column=0, columnspan=4, sticky="ew")
        ttk.Label(self.table_title_frame, text="HTTPRequest").pack(side=tk.LEFT)

        self.collapse_btn = ttk.Button(self.table_title_frame, text="Collapse", command=self.toggle_collapse, style="Invert.TButton")
        self.collapse_btn.pack(side=tk.RIGHT, padx=5)

        self.endpoint_entry = ttk.Entry(self.frame, width=50)
        self.endpoint_entry.grid(row=1, column=0, padx=5, pady=5)

        self.send_request_btn = ttk.Button(self.frame, text="Send Request", command=self.send_request)
        self.send_request_btn.grid(row=1, column=1, padx=5, pady=5)

        self.response_text = tk.Text(self.frame, width=80, height=20)
        self.response_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.scrollbar_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.response_text.yview)
        self.scrollbar_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL, command=self.response_text.xview)
        self.response_text.configure(yscrollcommand=self.scrollbar_y.set, xscrollcommand=self.scrollbar_x.set)
        self.scrollbar_y.grid(row=2, column=2, sticky='ns')
        self.scrollbar_x.grid(row=3, column=0, columnspan=2, sticky='ew')

    def toggle_collapse(self):
        if self.is_collapsed:
            self.endpoint_entry.grid()
            self.send_request_btn.grid()
            self.response_text.grid()
            self.scrollbar_y.grid()
            self.scrollbar_x.grid()
            self.collapse_btn.config(text="Collapse")
        else:
            self.endpoint_entry.grid_remove()
            self.send_request_btn.grid_remove()
            self.response_text.grid_remove()
            self.scrollbar_y.grid_remove()
            self.scrollbar_x.grid_remove()
            self.collapse_btn.config(text="Expand")
        self.is_collapsed = not self.is_collapsed

    def expand(self):
        if self.is_collapsed:
            self.toggle_collapse()

    def send_request(self):
        endpoint = self.endpoint_entry.get().strip()
        if endpoint:
            response = self.perform_request(endpoint)
            self.response_text.insert(tk.END, response)

    def perform_request(self, endpoint):
        # Here you should implement the logic for sending the actual HTTP

    def perform_request(self, endpoint):
        # Here you should implement the logic for sending the actual HTTP request
        # This is a placeholder function
        try:
            response = f"Response from {endpoint}"
            return response
        except Exception as e:
            return f"An error occurred: {e}"

def main():
    def create_errors_file():
        # Placeholder function to create an errors file if needed
        pass

    def load_custom_theme():
        # Placeholder function to load a custom theme
        return "default"

    def apply_theme(theme):
        # Placeholder function to apply a theme
        pass

    def open_custom_theme_window():
        # Placeholder function to open a theme customization window
        pass

    def play_audio():
        # Placeholder function to play audio
        pass

    def expand_all_tables(*args):
        # Function to expand all tables
        for tool in args:
            tool.expand()

    def show_help():
        # Placeholder function to show help information
        pass

    def backup_data(*args):
        # Placeholder function to back up data for provided arguments
        pass

    def restore_data():
        # Placeholder function to restore data
        pass

    create_errors_file()

    root = tk.Tk()
    root.title("Southwest Airlines CyberOps Eng OpsTools")
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
    ttk.Button(top_frame, text="Expand All Tables", command=lambda: expand_all_tables(nslookup, http_request)).pack(side=tk.LEFT, padx=5, pady=5)
    ttk.Button(top_frame, text="Help", command=show_help).pack(side=tk.RIGHT, padx=5, pady=5)
    ttk.Button(top_frame, text="Custom Theme", command=open_custom_theme_window).pack(side=tk.RIGHT, padx=5, pady=5)
    ttk.Button(top_frame, text="Backup Settings", command=lambda: backup_data(NSLookup, HTTPRequest)).pack(side=tk.RIGHT, padx=5, pady=5)
    ttk.Button(top_frame, text="Restore Settings", command=restore_data).pack(side=tk.RIGHT, padx=5, pady=5)

    canvas = tk.Canvas(root)
    scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
    scrollbar_x = ttk.Scrollbar(root, orient="horizontal", command=canvas.xview)
    scrollable_frame = ttk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=scrollbar_x.set)

    canvas.grid(row=1, column=0, columnspan=3, sticky="nsew")
    scrollbar.grid(row=1, column=3, sticky="ns")
    scrollbar_x.grid(row=2, column=0, columnspan=3, sticky="ew")

    for i in range(3):
        root.rowconfigure(i + 1, weight=1)
    root.columnconfigure(0, weight=1)

    theme_var = tk.StringVar(value=initial_theme)
    
    sidebar = ttk.Frame(scrollable_frame, padding="5")
    sidebar.grid(row=0, column=1, rowspan=10, sticky="ns")

    logo = Image.open("sw.png")
    logo = logo.resize((100, 50), Image.Resampling.LANCZOS)
    logo_img = ImageTk.PhotoImage(logo)
    logo_label = ttk.Label(sidebar, image=logo_img)
    logo_label.image = logo_img
    logo_label.grid(row=0, column=0, padx=5, pady=5)

    ttk.Label(sidebar, text="Choose Theme:").grid(row=1, column=0, padx=5, pady=5)
    ttk.Radiobutton(sidebar, text="Nord", variable=theme_var, value="standard", command=lambda: apply_theme(theme_var.get())).grid(row=2, column=0, padx=5, pady=5)
    ttk.Label(sidebar, text="Diagnostic Tools:").grid(row=5, column=0, padx=5, pady=5)
   
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
