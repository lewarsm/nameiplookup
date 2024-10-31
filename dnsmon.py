import tkinter as tk
from tkinter import ttk
import subprocess
import re
from datetime import datetime

# Define Nord color scheme
nord_colors = {
    "background": "#2E3440",
    "foreground": "#D8DEE9",
    "highlight": "#88C0D0",
    "error": "#BF616A",
    "header": "#4C566A",
    "row_odd": "#3B4252",
    "row_even": "#434C5E"
}

def nslookup(domain):
    ip_addresses = set()
    names = set()
    for _ in range(3):
        try:
            result = subprocess.run(['nslookup', domain], capture_output=True, text=True)
            # Extract IP addresses and names using regex
            ips = re.findall(r'Address: (\d+\.\d+\.\d+\.\d+)', result.stdout)
            name = re.search(r'Name:\s+([^\s]+)', result.stdout)
            ip_addresses.update(ips)
            if name:
                names.add(name.group(1))
        except Exception as e:
            return str(e), str(e)
    return list(names), list(ip_addresses)

def show_results():
    domain1 = "google.com"
    domain2 = "yahoo.com"
    names1, result1 = nslookup(domain1)
    names2, result2 = nslookup(domain2)
    
    for item in tree.get_children():
        tree.delete(item)
    
    if not result1 or not result2:
        result_label.config(text="Failed to retrieve IP addresses. Please check your network connection.", fg=nord_colors["error"])
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        current_results = [
            (domain1, names1[0] if names1 else 'No Name found', result1[0] if result1 else 'No IP found', timestamp),
            (domain2, names2[0] if names2 else 'No Name found', result2[0] if result2 else 'No IP found', timestamp)
        ]
        
        for i, (domain, name, ip, time) in enumerate(current_results):
            tree.insert("", "end", values=(domain, name, ip, time), tags=('oddrow' if i % 2 == 0 else 'evenrow'))
        
        result_label.config(text="", fg=nord_colors["foreground"])

    root.after(600000, show_results)

root = tk.Tk()
root.title("NSLookup Tool")
root.configure(bg=nord_colors["background"])

tk.Label(root, text="DNS Lookup for google.com and yahoo.com", bg=nord_colors["background"], fg=nord_colors["foreground"]).grid(row=0, columnspan=2, padx=10, pady=10)

columns = ("Domain", "Name", "IP Address", "Timestamp")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
tree.grid(row=1, columnspan=2, padx=10, pady=10)

# Apply Nord color scheme to the Treeview
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview", background=nord_colors["row_odd"], foreground=nord_colors["foreground"], fieldbackground=nord_colors["background"])
style.configure("Treeview.Heading", background=nord_colors["header"], foreground=nord_colors["foreground"])
style.map("Treeview", background=[("selected", nord_colors["highlight"])])

tree.tag_configure('oddrow', background=nord_colors["row_odd"])
tree.tag_configure('evenrow', background=nord_colors["row_even"])

result_label = tk.Label(root, text="", justify="left", bg=nord_colors["background"], fg=nord_colors["foreground"])
result_label.grid(row=2, columnspan=2, padx=10, pady=10)

tk.Button(root, text="Run Lookup", command=show_results, bg=nord_colors["highlight"], fg=nord_colors["foreground"]).grid(row=3, columnspan=2, pady=20)

root.after(1000, show_results)

root.mainloop()
