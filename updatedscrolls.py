import tkinter as tk
from tkinter import ttk, messagebox
import re
import subprocess
import json
import requests
import time
from datetime import datetime
import threading
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Nord color scheme
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
    'google': 'eu-central1'
}

class NSLookup:
    def __init__(self, parent):
        self.parent = parent
        self.domains = json.loads('{"domains": ["google.com", "yahoo.com", "mail.com", "dogpile.com"]}')
        self.create_widgets()
        self.update_table()

    def create_widgets(self):
        self.frame = ttk.Frame(self.parent)
        self.frame.pack(fill=tk.BOTH, expand=True)
        # Create vertical and horizontal scrollbars
        self.table_scroll_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL)
        self.table_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.table_scroll_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL)
        self.table_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.table = ttk.Treeview(self.frame, columns=('Domain', 'Name', 'IP Address', 'Region', 'Timestamp'), show='headings',yscrollcommand=self.table_scroll_y.set,xscrollcommand=self.table_scroll_x.set)
        self.table.heading('Domain', text='Domain')
        self.table.heading('Name', text='Name')
        self.table.heading('IP Address', text='IP Address')
        self.table.heading('Region', text='Region')
        self.table.heading('Timestamp', text='Timestamp')
        self.table.pack(fill=tk.BOTH, expand=True)
       # Configure scrollbars
        self.table_scroll_y.config(command=self.table.yview)
        self.table_scroll_x.config(command=self.table.xview)

        self.add_domain_entry = ttk.Entry(self.frame)
        self.add_domain_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.add_domain_button = ttk.Button(self.frame, text='Add Domain', command=self.add_domain)
        self.add_domain_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.update_button = ttk.Button(self.frame, text='Update', command=self.update_table)
        self.update_button.pack(side=tk.RIGHT, padx=5, pady=5)

    def add_domain(self):
        domain = self.add_domain_entry.get()
        if domain:
            self.domains['domains'].append(domain)
            self.add_domain_entry.delete(0, tk.END)
            self.update_table()

    def update_table(self):
        for row in self.table.get_children():
            self.table.delete(row)
        for domain in self.domains['domains']:
            result = self.nslookup(domain)
            if result:
                self.table.insert('', tk.END, values=result)

    def nslookup(self, domain):
        try:
            output = subprocess.check_output(['nslookup', domain]).decode('utf-8')
            print("output",output)
            lines = output.split('\n')
            #matchname = re.search(r"Name:\s+([^\n]+)", output)
            match = re.search(r"Name:\s+([^\n]+)\nAddress:\s+([^\n]+)", output)
            if match:
                name = match.group(1)
                ip_address = match.group(2)
            #name = lines[0].split(': ')[1] if len(lines) > 0 and ': ' in lines[0] else 'N/A'
            #ip_address = lines[3].split(': ')[1] if len(lines) > 3 and ': ' in lines[3] else 'N/A'
            region = self.get_region(name)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return (domain, name, ip_address, region, timestamp)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to lookup {domain}: {e}')
            return None

    def get_region(self, name):
        for key, value in region_mappings.items():
            if key in name:
                return value
        return 'Unknown'

class HTTPRequest:
    def __init__(self, parent):
        self.parent = parent
        self.sites = ['status.cloud.google.com', 'portal.office.com']
        self.create_widgets()
        self.update_table()

    def create_widgets(self):
        self.frame = ttk.Frame(self.parent)
        self.frame.pack(fill=tk.BOTH, expand=True)
        # Create vertical and horizontal scrollbars
        self.table_scroll_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL)
        self.table_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.table_scroll_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL)
        self.table_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.table = ttk.Treeview(self.frame, columns=('Site', 'HTTP Code', 'Message'), show='headings',yscrollcommand=self.table_scroll_y.set,xscrollcommand=self.table_scroll_x.set)
        self.table.heading('Site', text='Site')
        self.table.heading('HTTP Code', text='HTTP Code')
        self.table.heading('Message', text='Message')
        self.table.pack(fill=tk.BOTH, expand=True)
       # Configure scrollbars
        self.table_scroll_y.config(command=self.table.yview)
        self.table_scroll_x.config(command=self.table.xview)

        self.add_site_entry = ttk.Entry(self.frame)
        self.add_site_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.add_site_button = ttk.Button(self.frame, text='Add Site', command=self.add_site)
        self.add_site_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.update_button = ttk.Button(self.frame, text='Update', command=self.update_table)
        self.update_button.pack(side=tk.RIGHT, padx=5, pady=5)

    def add_site(self):
        site = self.add_site_entry.get()
        if site:
            self.sites.append(site)
            self.add_site_entry.delete(0, tk.END)
            self.update_table()

    def update_table(self):
        for row in self.table.get_children():
            self.table.delete(row)
        for site in self.sites:
            result = self.http_request(site)
            if result:
                self.table.insert('', tk.END, values=result)

    def http_request(self, site):
        try:
            response = requests.get(f'https://{site}')
            message = 'OK' if 'we\'re all good' in response.text else ''
            return (site, response.status_code, message)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to request {site}: {e}')
            return None

class JWKS:
    def __init__(self, parent):
        self.parent = parent
        self.url = 'https://auth.pingone.com/0a7af83d-4ed9-4510-93cd-506fe835f69a/as/jwks'
        self.create_widgets()
        self.update_table()

    def create_widgets(self):
        self.frame = ttk.Frame(self.parent)
        self.frame.pack(fill=tk.BOTH, expand=True)
        # Create vertical and horizontal scrollbars
        self.table_scroll_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL)
        self.table_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.table_scroll_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL)
        self.table_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.table = ttk.Treeview(self.frame, columns=('Key ID', 'Creation Date', 'Expiration Date'), show='headings',yscrollcommand=self.table_scroll_y.set,xscrollcommand=self.table_scroll_x.set)
        self.table.heading('Key ID', text='Key ID')
        self.table.heading('Creation Date', text='Creation Date')
        self.table.heading('Expiration Date', text='Expiration Date')
        self.table.pack(fill=tk.BOTH, expand=True)
       # Configure scrollbars
        self.table_scroll_y.config(command=self.table.yview)
        self.table_scroll_x.config(command=self.table.xview)

        self.url_entry = ttk.Entry(self.frame)
        self.url_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.url_entry.insert(0, self.url)

        self.update_button = ttk.Button(self.frame, text='Update', command=self.update_table)
        self.update_button.pack(side=tk.RIGHT, padx=5, pady=5)

    def update_table(self):
        for row in self.table.get_children():
            self.table.delete(row)
        self.url = self.url_entry.get()
        keys = self.get_jwks_keys(self.url)
        for key in keys:
            self.table.insert('', tk.END, values=key)

    def get_jwks_keys(self, url):
        try:
            response = requests.get(url)
            jwks = response.json()
            keys = []
            for key in jwks['keys']:
                key_id = key['kid']
                cert = key['x5c'][0]
                x509_cert = x509.load_pem_x509_certificate(f'-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----'.encode(), default_backend())
                creation_date = x509_cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S')
                expiration_date = x509_cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')
                keys.append((key_id, creation_date, expiration_date))
            return keys
        except Exception as e:
            messagebox.showerror('Error', f'Failed to get JWKS keys: {e}')
            return []

class App:
    def __init__(self, root):
        self.root = root
        self.root.title('Network Tools')
        self.root.configure(bg=nord_colors['background'])

        self.nslookup = NSLookup(self.root)
        self.http_request = HTTPRequest(self.root)
        self.jwks = JWKS(self.root)

        self.auto_update()

    def auto_update(self):
        self.nslookup.update_table()
        self.http_request.update_table()
        self.jwks.update_table()
        self.root.after(600000, self.auto_update)  # Update every 10 minutes

if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
