```
import base64
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class JWKSCheck:
    def __init__(self, master, style):
        self.master = master
        self.style = style
        self.is_collapsed = False
        self.default_url = "https://sso.fed.dev.aws.swacorp.com/pf/JWKS"
        self.url = self.default_url
        self.setup_ui()
        self.update_jwks_table()

    def setup_ui(self):
        self.frame = ttk.LabelFrame(self.master, padding="10")
        self.frame.grid(row=3, column=0, sticky="nsew")

        self.table_title_frame = ttk.Frame(self.frame)
        self.table_title_frame.grid(row=0, column=0, columnspan=4, sticky="ew")
        ttk.Label(self.table_title_frame, text="JWKSCheck").pack(side=tk.LEFT)

        self.collapse_btn = ttk.Button(self.table_title_frame, text="Collapse", command=self.toggle_collapse, style="Invert.TButton")
        self.collapse_btn.pack(side=tk.RIGHT, padx=5)

        self.url_entry = ttk.Entry(self.frame, width=50)
        self.url_entry.insert(0, "https://auth.pingone.com/0a7af83d-4ed9-4510-93cd-506fe835f69a/as/jwks")
        self.url_entry.grid(row=1, column=0, padx=5, pady=5)

        self.add_url_btn = ttk.Button(self.frame, text="Set URL", command=self.set_url)
        self.add_url_btn.grid(row=1, column=1, padx=5, pady=5)

        self.refresh_btn = ttk.Button(self.frame, text="Refresh", command=self.update_jwks_table)
        self.refresh_btn.grid(row=1, column=2, padx=5, pady=5)

        self.cert_table = self.setup_table(self.frame, ("Key ID", "Name", "Not Valid Before", "Not Valid After"))
        self.cert_table.grid(row=2, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")

        self.cert_scrollbar_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.cert_table.yview)
        self.cert_table.configure(yscroll=self.cert_scrollbar_y.set)
        self.cert_scrollbar_y.grid(row=2, column=4, sticky='ns')

        self.ec_table = self.setup_table(self.frame, ("Key Type", "Key ID", "Use", "X", "Y", "Curve"))
        self.ec_table.grid(row=3, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")

        self.ec_scrollbar_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.ec_table.yview)
        self.ec_table.configure(yscroll=self.ec_scrollbar_y.set)
        self.ec_scrollbar_y.grid(row=3, column=4, sticky='ns')

        self.frame.rowconfigure(2, weight=1)
        self.frame.columnconfigure(0, weight=1)
        self.cert_table.bind("<Double-1>", self.delete_row)
        self.ec_table.bind("<Double-1>", self.delete_row)

    def delete_row(self, event):
        selected_item = self.table.selection()[0]
        self.table.delete(selected_item)

    def toggle_collapse(self):
        if self.is_collapsed:
            self.cert_table.grid()
            self.cert_scrollbar_y.grid()
            self.ec_table.grid()
            self.ec_scrollbar_y.grid()
            self.url_entry.grid()
            self.add_url_btn.grid()
            self.refresh_btn.grid()
            self.collapse_btn.config(text="Collapse")
        else:
            self.cert_table.grid_remove()
            self.cert_scrollbar_y.grid_remove()
            self.ec_table.grid_remove()
            self.ec_scrollbar_y.grid_remove()
            self.url_entry.grid_remove()
            self.add_url_btn.grid_remove()
            self.refresh_btn.grid_remove()
            self.collapse_btn.config(text="Expand")
        self.is_collapsed = not self.is_collapsed

    def expand(self):
        if self.is_collapsed:
            self.toggle_collapse()

    def set_url(self):
        self.url = self.url_entry.get().strip()
        if not self.url:
            self.url = self.default_url
        self.update_jwks_table()

    def update_jwks_table(self):
        self.clear_table(self.cert_table)
        self.clear_table(self.ec_table)
        try:
            response = requests.get(self.url, verify=False)
            response.raise_for_status()
            jwks = response.json()
            for key in jwks.get('keys', []):
                if 'x5c' in key:
                    for cert in key['x5c']:
                        cert_bytes = base64.b64decode(cert)
                        x509_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                        key_id = key['kid']
                        name = x509_cert.subject
                        not_valid_before = x509_cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
                        not_valid_after = x509_cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
                        self.cert_table.insert("", "end", values=(key_id, name, not_valid_before, not_valid_after))
                if key['kty'] == 'EC':
                    key_type = key['kty']
                    key_id = key['kid']
                    use = key['use']
                    x = key.get('x', '')
                    y = key.get('y', '')
                    curve = key.get('crv', '')
                    self.ec_table.insert("", "end", values=(key_type, key_id, use, x, y, curve))
        except Exception as e:
            print(f"Error fetching JWKS: {e}")
        self.master.after(600000, self.update_jwks_table)  # Auto-refresh every 10 minutes

    def setup_table(self, master, columns):
        table = ttk.Treeview(master, columns=columns, show="headings")
        for col in columns:
            table.heading(col, text=col)
            table.column(col, anchor=tk.W, width=150)
        return table

    def clear_table(self, table):
        for item in table.get_children():
            table.delete(item)
```
