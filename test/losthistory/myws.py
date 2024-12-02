```
import tkinter as tk
from tkinter import ttk
import subprocess
import json
import time
import requests

# Nord Color Scheme
nord_colors = {
    'background': '#2E3440',
    'foreground': '#D8DEE9',
    'highlight': '#88C0D0',
    'error': '#BF616A',
    'header': '#4C566A',
    'row_odd': '#3B4252',
    'row_even': '#434C5E',
    'button': '#5E81AC'
}

# Region mappings
region_mappings = {
    'prod0': 'eu-west-1',
    'prod1': 'eu-west-2',
    'qa0': 'eu-west',
    'qa1': 'eu-east',
    'qa3': 'ca-central',
    'qa4': 'eu-central1'
}

class NSLookupFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=nord_colors['background'])
        self.create_widgets()

    def create_widgets(self):
        self.entry = tk.Entry(self, bg=nord_colors['background'], fg=nord_colors['foreground'])
        self.entry.grid(row=0, column=0, padx=10, pady=10)
        self.add_button = tk.Button(self, text="Add Domain", command=self.add_domain, bg=nord_colors['button'], fg=nord_colors['foreground'])
        self.add_button.grid(row=0, column=1, padx=10, pady=10)

        self.domains = ["google.com", "yahoo.com", "mail.com", "dogpile.com"]

        self.tree = ttk.Treeview(self, columns=("Domain", "Name", "IP Address", "Region", "Timestamp"), show="headings", style="Custom.Treeview")
        self.tree.heading("Domain", text="Domain")
        self.tree.heading("Name", text="Name")
        self.tree.heading("IP Address", text="IP Address")
        self.tree.heading("Region", text="Region")
        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        style = ttk.Style()
        style.configure("Custom.Treeview", background=nord_colors['row_even'], foreground=nord_colors['foreground'], rowheight=25, fieldbackground=nord_colors['background'])
        style.map('Custom.Treeview', background=[('selected', nord_colors['highlight'])])

        self.update_button = tk.Button(self, text="Update", command=self.update_table, bg=nord_colors['button'], fg=nord_colors['foreground'])
        self.update_button.grid(row=2, column=1, padx=10, pady=10, sticky='e')

        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(row=1, column=2, sticky='ns')

        self.update_table()
        self.after(600000, self.update_table)

    def add_domain(self):
        domain = self.entry.get()
        if domain and domain not in self.domains:
            self.domains.append(domain)
            self.entry.delete(0, tk.END)
            self.update_table()

    def update_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for domain in self.domains:
            result = self.nslookup(domain)
            for r in result:
                self.tree.insert("", "end", values=r)

    def nslookup(self, domain):
        try:
            output = subprocess.check_output(["nslookup", domain]).decode().split("\n")
            name = output[1].split(" ")[-1]
            ip_address = output[-3].split(" ")[-1]
            region = self.get_region(ip_address)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            return [(domain, name, ip_address, region, timestamp)]
        except:
            return [(domain, "Error", "Error", "Error", "Error")]

    def get_region(self, ip_address):
        for key, value in region_mappings.items():
            if key in ip_address:
                return value
        return "Unknown"

class HTTPRequestFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=nord_colors['background'])
        self.create_widgets()

    def create_widgets(self):
        self.tree = ttk.Treeview(self, columns=("Site", "Status Code", "Message", "Timestamp"), show="headings", style="Custom.Treeview")
        self.tree.heading("Site", text="Site")
        self.tree.heading("Status Code", text="Status Code")
        self.tree.heading("Message", text="Message")
        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        style = ttk.Style()
        style.configure("Custom.Treeview", background=nord_colors['row_even'], foreground=nord_colors['foreground'], rowheight=25, fieldbackground=nord_colors['background'])
        style.map('Custom.Treeview', background=[('selected', nord_colors['highlight'])])

        self.update_button = tk.Button(self, text="Update", command=self.update_table, bg=nord_colors['button'], fg=nord_colors['foreground'])
        self.update_button.grid(row=1, column=1, padx=10, pady=10, sticky='e')

        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(row=0, column=2, sticky='ns')

        self.update_table()
        self.after(600000, self.update_table)

    def update_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        sites = ["status.cloud.google.com", "portal.office.com"]
        for site in sites:
            result = self.http_request(site)
            self.tree.insert("", "end", values=result)

    def http_request(self, site):
        try:
            response = requests.get(f"https://{site}")
            status_code = response.status_code
            message = "OK" if "we're all good" in response.text else "N/A"
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            return (site, status_code, message, timestamp)
        except:
            return (site, "Error", "Error", "Error")

class App:
    def __init__(self, master):
        self.master = master
        self.canvas = tk.Canvas(master, bg=nord_colors['background'])
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.scrollbar = tk.Scrollbar(master, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(row=0, column=1, sticky='ns')

        self.frame = tk.Frame(self.canvas, bg=nord_colors['background'])
        self.canvas.create_window((0, 0), window=self.frame, anchor="nw")

        self.frame.bind("<Configure>", self.on_frame_configure)

        self.nslookup_frame = NSLookupFrame(self.frame)
        self.httprequest_frame = HTTPRequestFrame(self.frame)

    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

if __name__ == "__main__":
    root = tk.Tk()
    root.configure(bg=nord_colors['background'])
    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    app = App(root)
    root.mainloop()

```
