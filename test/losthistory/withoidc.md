```
import tkinter as tk
from tkinter import ttk
import requests
import json
import jwt
import base64
import hashlib
import os
import re
from datetime import datetime
import dns.resolver
import uuid
import random
import string
import webbrowser
import ssl
from OpenSSL import crypto

class OIDCDebugger:
    def __init__(self, master, theme):
        self.master = master
        self.theme = theme
        self.generate_self_signed_cert()
        self.window = tk.Toplevel()
        self.window.title("OIDC Debugger")
        self.window.geometry("800x600")
        self.apply_theme()
        self.setup_ui()

    def apply_theme(self):
        style = ttk.Style(self.window)
        style.theme_use(self.theme)
        theme_colors = NORD_STYLES.get(self.theme, NORD_STYLES["standard"])
        self.window.configure(background=theme_colors["background"])

    def setup_ui(self):
        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.endpoint_entry = ttk.Entry(self.frame, width=50)
        self.endpoint_entry.grid(row=0, column=0, padx=5, pady=5)
        self.endpoint_entry.insert(0, "Enter well-known endpoint URL")

        self.client_id_entry = ttk.Entry(self.frame, width=50)
        self.client_id_entry.grid(row=1, column=0, padx=5, pady=5)
        self.client_id_entry.insert(0, "Enter Client ID")

        self.client_secret_entry = ttk.Entry(self.frame, width=50, show="*")
        self.client_secret_entry.grid(row=2, column=0, padx=5, pady=5)
        self.client_secret_entry.insert(0, "Enter Client Secret")

        self.use_pkce = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Use PKCE", variable=self.use_pkce).grid(row=3, column=0, padx=5, pady=5)

        self.generate_request_btn = ttk.Button(self.frame, text="Generate Auth Request", command=self.generate_auth_request)
        self.generate_request_btn.grid(row=4, column=0, padx=5, pady=5)

        self.auth_url_text = tk.Text(self.frame, height=5, width=80)
        self.auth_url_text.grid(row=5, column=0, padx=5, pady=5)

        self.submit_btn = ttk.Button(self.frame, text="Submit Auth Request", command=self.submit_auth_request)
        self.submit_btn.grid(row=6, column=0, padx=5, pady=5)

        self.response_text = tk.Text(self.frame, height=10, width=80)
        self.response_text.grid(row=7, column=0, padx=5, pady=5)

        self.certificate_btn = ttk.Button(self.frame, text="Show Certificate", command=self.show_certificate)
        self.certificate_btn.grid(row=8, column=0, padx=5, pady=5)

        self.replace_certificate_btn = ttk.Button(self.frame, text="Replace Certificate", command=self.replace_certificate)
        self.replace_certificate_btn.grid(row=9, column=0, padx=5, pady=5)

    def generate_self_signed_cert(self):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "SomeState"
        cert.get_subject().L = "SomeCity"
        cert.get_subject().O = "SomeOrganization"
        cert.get_subject().OU = "SomeOrganizationalUnit"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        with open("server.crt", "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        with open("server.key", "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))
        self.cert = cert

    def show_certificate(self):
        cert_details = crypto.dump_certificate(crypto.FILETYPE_TEXT, self.cert).decode('utf-8')
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, cert_details)

    def replace_certificate(self):
        cert_file_path = tk.filedialog.askopenfilename(title="Select Certificate File", filetypes=[("Certificate Files", "*.crt *.pem")])
        key_file_path = tk.filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key *.pem")])

        if cert_file_path and key_file_path:
            with open(cert_file_path, "r") as cert_file:
                self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
            with open(key_file_path, "r") as key_file:
                self.key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(tk.END, "Certificate and key replaced successfully.\n")
        else:
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(tk.END, "Certificate or key file not selected.\n")

    def generate_auth_request(self):
        well_known_url = self.endpoint_entry.get().strip()
        client_id = self.client_id_entry.get().strip()
        client_secret = self.client_secret_entry.get().strip()

        if not well_known_url or not client_id:
            self.response_text.insert(tk.END, "Please enter the well-known endpoint and client credentials.\n")
            return

        try:
            response = requests.get(well_known_url)
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error fetching well-known configuration: {response.status_code}\n")
                return

            config = response.json()
            auth_endpoint = config.get("authorization_endpoint")
            token_endpoint = config.get("token_endpoint")

            if not auth_endpoint or not token_endpoint:
                self.response_text.insert(tk.END, "Error: Unable to find authorization or token endpoint in the configuration.\n")
                return

            state = self.generate_state()
            nonce = self.generate_nonce()
            params = {
                "client_id": client_id,
                "redirect_uri": "https://localhost/callback",
                "response_type": "code",
                "scope": "openid profile",
                "state": state,
                "nonce": nonce
            }

            if self.use_pkce.get():
                code_verifier, code_challenge = self.generate_pkce()
                params.update({
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256"
                })
                self.code_verifier = code_verifier
            else:
                self.code_verifier = None

            auth_url = f"{auth_endpoint}?{self.encode_params(params)}"
            self.auth_url_text.delete(1.0, tk.END)
            self.auth_url_text.insert(tk.END, auth_url)
            self.state = state
            self.token_endpoint = token_endpoint
            self.client_id = client_id
            self.client_secret = client_secret

        except Exception as e:
            self.response_text.insert(tk.END, f"Error generating auth request: {e}\n")

    def generate_state(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8').rstrip('=')

    def generate_nonce(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8').rstrip('=')

    def generate_pkce(self):
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge

    def encode_params(self, params):
        return '&'.join([f"{k}={requests.utils.quote(v)}" for k, v in params.items()])

    def submit_auth_request(self):
        auth_url = self.auth_url_text.get(1.0, tk.END).strip()
        if not auth_url:
            self.response_text.insert(tk.END, "Please generate an authentication request URL first.\n")
            return
        webbrowser.open(auth_url)
        self.response_text.insert(tk.END, "Please complete the authentication in your browser.\n")

    def exchange_code_for_tokens(self, code):
        try:
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://localhost/callback",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
            if self.code_verifier:
                data["code_verifier"] = self.code_verifier

            response = requests.post(self.token_endpoint, data=data, verify="server.crt")
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error fetching tokens: {response.status_code}\n")
                return

            tokens = response.json()
            self.display_tokens(tokens)
    def display_tokens(self, tokens):
        try:
            self.response_text.delete(1.0, tk.END)
            for key, value in tokens.items():
               self.response_text.insert(tk.END, f"{key}: {value}\n")

            if "id_token" in tokens:
                self.decode_jwt(tokens["id_token"])
            if "access_token" in tokens:
                self.introspect_token(tokens["access_token"], "access")
            if "refresh_token" in tokens:
                self.introspect_token(tokens["refresh_token"], "refresh")
        except Exception as e:
            self.response_text.insert(tk.END, f"Error displaying tokens: {e}\n")


    def decode_jwt(self, token):
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            self.response_text.insert(tk.END, f"Decoded ID Token: {json.dumps(decoded, indent=4)}\n")
        except Exception as e:
            self.response_text.insert(tk.END, f"Error decoding JWT: {e}\n")

    def introspect_token(self, token, token_type):
        try:
            data = {
                "token": token,
                "token_type_hint": token_type,
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
            response = requests.post(f"{self.token_endpoint}/introspect", data=data, verify="server.crt")
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error introspecting {token_type} token: {response.status_code}\n")
                return

            introspection = response.json()
            self.response_text.insert(tk.END, f"Introspected {token_type.capitalize()} Token: {json.dumps(introspection, indent=4)}\n")
        except Exception as e:
            self.response_text.insert(tk.END, f"Error introspecting {token_type} token: {e}\n")

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
    ttk.Button(sidebar, text="OIDC Debugger", command=lambda: OIDCDebugger(scrollable_frame, theme_var.get())).grid(row=9, column=0, padx=5, pady=5)

    nslookup = NSLookup(scrollable_frame, theme_var.get())
    http_request = HTTPRequest(scrollable_frame, theme_var.get())
    oidc_debugger = OIDCDebugger(scrollable_frame, theme_var.get())

    for widget in scrollable_frame.winfo_children():
        widget.grid_configure(sticky="nsew")

    scrollable_frame.columnconfigure(0, weight=1)
    scrollable_frame.rowconfigure(1, weight=1)
    scrollable_frame.rowconfigure(2, weight=1)
    scrollable_frame.rowconfigure(3, weight=1)
    scrollable_frame.rowconfigure(4, weight=1)
    scrollable_frame.rowconfigure(5, weight=1)
    scrollable_frame.rowconfigure(6, weight=1)
    scrollable_frame.rowconfigure(7, weight=1)
    scrollable_frame.rowconfigure(8, weight=1)
    scrollable_frame.rowconfigure(9, weight=1)

    apply_theme(theme_var.get())
    nslookup.expand()
    http_request.expand()
    oidc_debugger.expand()
    root.mainloop()

if __name__ == "__main__":
    custom_theme = load_custom_theme()
    main()

```
