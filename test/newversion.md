```here goes```
```
import os
import re
import json
import requests
from datetime import datetime
import tkinter as tk
from tkinter import ttk

class CustomTable:
    def __init__(self, parent, columns, row, column, columnspan=1):
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
        
        self.regex_entry = ttk.Entry(self.frame, width=50)  # Entry for regular expression
        self.regex_entry.grid(row=1, column=1, padx=5, pady=5)
        self.regex_entry.insert(0, "Enter regex")  # Default placeholder text

        self.add_url_btn = ttk.Button(self.frame, text="Add URL", command=self.add_url)
        self.add_url_btn.grid(row=1, column=2, padx=5, pady=5)

        self.refresh_btn = ttk.Button(self.frame, text="Refresh", command=self.update_http_table)
        self.refresh_btn.grid(row=1, column=3, padx=5, pady=5)

        self.reset_btn = ttk.Button(self.frame, text="Reset URLs", command=self.reset_urls)
        self.reset_btn.grid(row=1, column=4, padx=5, pady=5)

        self.ignore_ssl_btn = ttk.Button(self.frame, text="Ignore SSL Verification", command=self.toggle_ssl_verification)
        self.ignore_ssl_btn.grid(row=1, column=5, padx=5, pady=5)
        
        self.table = CustomTable(self.frame, ("URL", "Status Code", "Status Text", "Timestamp"), 2, 0, 6)
        
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
        regex = self.regex_entry.get().strip()  # Get the regex pattern from the entry
        if url:
            self.urls.append({"url": url, "regex": regex})  # Save URL and regex as a dictionary
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
                if regex and re.search(regex, status_text):  # If regex matches response
                    status_text = "OK"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.table.insert_row((url, response.status_code, status_text, timestamp))
            except Exception as e:
                self.table.insert_row((url, "Error", str(e), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        self.master.after(600000, self.update_http_table)  # Auto-refresh every 10 minutes
```
