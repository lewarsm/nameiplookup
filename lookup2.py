import tkinter as tk
from tkinter import ttk
import subprocess
import re
from datetime import datetime
import json

# Define Nord color scheme
nord_colors = {
    "background": "#2E3440",
    "foreground": "#D8DEE9",
    "highlight": "#88C0D0",
    "error": "#BF616A",
    "header": "#4C566A",
    "row_odd": "#3B4252",
    "row_even": "#434C5E",
    "button": "#5E81AC"  # Blue color for the button
}

# Define region mapping in JSON format
region_mapping_json = '''
{
    "prod0": "eu-west-1",
    "prod1": "eu-west-2",
    "qa0": "eu-west",
    "qa1": "eu-east",
    "qa3": "ca-central",
    "qa4": "eu-central1"
}
'''

# Load region mapping from JSON
region_mapping = json.loads(region_mapping_json)

def nslookup(domain):
    ip_addresses = set()
    names = set()
    for _ in range(3):
        try:
            result = subprocess.run(['nslookup', domain], capture_output=True, text=True)
            # Extract IP addresses and names using regex
            ips = re.findall(r'Address: (\\d+\\.\\d+\\.\\d+\\.\\d+)', result.stdout)
            name = re.search(r'Name:\\s+([^\s]+)', result.stdout)
            ip_addresses.update(ips)
            if name:
                names.add(name.group(1))
        except Exception as e:
            return str(e), str(e)
    return list(names), list(ip_addresses)

def get_region(name):
    for key in region_mapping:
        if key in name:
            return region_mapping[key]
    return 'Unknown'

def show_results():
    domains = ["google.com", "yahoo.com", "mail.com", "dogpile.com"]
    custom_domain = domain_entry.get().strip()
    if custom_domain:
        domains.append(custom_domain)
    
    results = []
    
    for domain in domains:
        names, ips = nslookup(domain)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        region = get_region(names[0]) if names else 'Unknown'
        results.append((domain, names[0] if names else 'No Name found', ips[0] if ips else 'No IP found', region, timestamp))
    
    for item in tree.get_children():
        tree.delete(item)
    
    if any('No IP found' in result for result in results):
        result_label.config(text="Failed to retrieve IP addresses. Please check your network connection.", fg=nord_colors["error"])
    else:
        for i, (domain, name, ip, region, time) in enumerate(results):
            tree.insert("", "end", values=(domain, name, ip, region, time), tags=('visible', 'oddrow' if i % 2 == 0 else 'evenrow'))
        
        result_label.config(text="", fg=nord_colors["foreground"])

    root.after(600000, show_results)

root = tk.Tk()
root.title("NSLookup Tool")
root.configure(bg=nord_colors["background"])

tk.Label(root, text="DNS Lookup for google.com, yahoo.com, mail.com, and dogpile.com", bg=nord_colors["background"], fg=nord_colors["foreground"]).grid(row=0, columnspan=2, padx=10, pady=10)

tk.Label(root, text="Enter a domain name:", bg=nord_colors["background"], fg=nord_colors["foreground"]).grid(row=1, column=0, padx=10, pady=10)
domain_entry = tk.Entry(root)
domain_entry.grid(row=1, column=1, padx=10, pady=10)

columns = ("Domain", "Name", "IP Address", "Region", "Timestamp")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
tree.grid(row=2, columnspan=2, padx=10, pady=10)

# Apply Nord color scheme to the Treeview
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview", background=nord_colors["row_odd"], foreground=nord_colors["foreground"], fieldbackground=nord_colors["background"])
style.configure("Treeview.Heading", background=nord_colors["header"], foreground=nord_colors["foreground"])
style.map("Treeview", background=[("selected", nord_colors["highlight"])])

tree.tag_configure('oddrow', background=nord_colors["row_odd"])
tree.tag_configure('evenrow', background=nord_colors["row_even"])

result_label = tk.Label(root, text="", justify="left", bg=nord_colors["background"], fg=nord_colors["foreground"])
result_label.grid(row=3, columnspan=2, padx=10, pady=10)

tk.Button(root, text="Run Lookup", command=show_results, bg=nord_colors["button"], fg=nord_colors["foreground"]).grid(row=4, columnspan=2, pady=20)

root.after(1000, show_results)

root.mainloop()
