```
import os
import json
import re  # Import the re module for regular expressions
import dns.resolver
import requests
import base64
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk, colorchooser, filedialog
import subprocess
import ssl
import pygame
from PIL import Image, ImageTk
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import webbrowser
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlencode, urlparse, parse_qs
from io import BytesIO

import warnings

#Silence Self Signed Certificate Errors
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Styling configurations
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
    },
    "frost": {
        "background": "#8FBCBB",
        "foreground": "#2E3440",
        "highlight": "#88C0D0",
        "error": "#BF616A",
        "header": "#4C566A",
        "row_odd": "#A3BE8C",
        "row_even": "#EBCB8B",
        "button": "#5E81AC",
        "invert_button": "#D08770"
    },
    "aurora": {
        "background": "#A3BE8C",
        "foreground": "#2E3440",
        "highlight": "#88C0D0",
        "error": "#BF616A",
        "header": "#4C566A",
        "row_odd": "#B48EAD",
        "row_even": "#D08770",
        "button": "#5E81AC",
        "invert_button": "#88C0D0"
    }
}

hanger_mappings = {
    'prod0': 'hanger0',
    'prod1': 'hanger1',
    'qa0': 'hanger0',
    'qa1': 'hanger1',
    'dev0': 'hanger0',
    'dev1': 'hanger1'
}

# Load custom theme if it exists
def load_custom_theme():
    if os.path.exists("customtheme.json"):
        with open("customtheme.json", "r") as file:
            custom_theme = json.load(file)
        if custom_theme:
            NORD_STYLES["custom"] = custom_theme
            return "custom"
    return "standard"

# Save custom theme to a file
def save_custom_theme(theme):
    with open("customtheme.json", "w") as file:
        json.dump(theme, file)

# Apply theme
def apply_theme(theme):
    style = ttk.Style()
    colors = NORD_STYLES[theme]
    style.configure("TFrame", background=colors["background"])
    style.configure("TLabelFrame", background=colors["background"], foreground=colors["foreground"])
    style.configure("Treeview", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
    style.configure("Treeview.Heading", background=colors["header"], foreground=colors["foreground"])
    style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
    style.map("TButton", background=[("active", colors["highlight"])])
    style.configure("TEntry", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
    style.configure("TText", background=colors["background"], foreground=colors["foreground"])
    style.configure("Invert.TButton", background=colors["invert_button"], foreground=colors["foreground"])
    style.map("Invert.TButton", background=[("active", colors["highlight"])])

# Custom theme window
def open_custom_theme_window():
    def load_theme_values():
        if os.path.exists("customtheme.json"):
            with open("customtheme.json", "r") as file:
                custom_theme = json.load(file)
            if not custom_theme:
                custom_theme = NORD_STYLES["standard"]
        else:
            custom_theme = NORD_STYLES["standard"]

        background_entry.insert(0, custom_theme["background"])
        foreground_entry.insert(0, custom_theme["foreground"])
        highlight_entry.insert(0, custom_theme["highlight"])
        error_entry.insert(0, custom_theme["error"])
        header_entry.insert(0, custom_theme["header"])
        row_odd_entry.insert(0, custom_theme["row_odd"])
        row_even_entry.insert(0, custom_theme["row_even"])
        button_entry.insert(0, custom_theme["button"])
        invert_button_entry.insert(0, custom_theme["invert_button"])

    def choose_color(entry):
        color_code = colorchooser.askcolor(title="Choose color")[1]
        if color_code:
            entry.delete(0, tk.END)
            entry.insert(0, color_code)

    def apply_theme_and_save():
        custom_theme = {
            "background": background_entry.get(),
            "foreground": foreground_entry.get(),
            "highlight": highlight_entry.get(),
            "error": error_entry.get(),
            "header": header_entry.get(),
            "row_odd": row_odd_entry.get(),
            "row_even": row_even_entry.get(),
            "button": button_entry.get(),
            "invert_button": invert_button_entry.get()
        }
        save_custom_theme(custom_theme)
        NORD_STYLES["custom"] = custom_theme
        apply_theme("custom")
        custom_theme_window.destroy()

    custom_theme_window = tk.Toplevel()
    custom_theme_window.title("Custom Theme")
    custom_theme_window.geometry("400x400")

    frame = ttk.Frame(custom_theme_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    labels = [
        "Background", "Foreground", "Highlight", "Error", 
        "Header", "Row Odd", "Row Even", "Button", "Invert Button"
    ]
    entries = {}

    for i, label in enumerate(labels):
        ttk.Label(frame, text=label).grid(row=i, column=0, padx=5, pady=5)
        entry = ttk.Entry(frame, width=20)
        entry.grid(row=i, column=1, padx=5, pady=5)
        entries[label.lower().replace(" ", "_")] = entry
        ttk.Button(frame, text="Choose", command=lambda e=entry: choose_color(e)).grid(row=i, column=2, padx=5, pady=5)

    background_entry = entries["background"]
    foreground_entry = entries["foreground"]
    highlight_entry = entries["highlight"]
    error_entry = entries["error"]
    header_entry = entries["header"]
    row_odd_entry = entries["row_odd"]
    row_even_entry = entries["row_even"]
    button_entry = entries["button"]
    invert_button_entry = entries["invert_button"]

    load_theme_values()

    ttk.Button(frame, text="Apply and Save Theme", command=apply_theme_and_save).grid(row=len(labels), column=1, pady=10)

def open_jwks_check_window(theme):
    jwks_check_window = CustomWindow("JWKS Check Tool", 800, 600, theme)
    JWKSCheck(jwks_check_window.frame, theme)

def open_tcp_tools_window(theme):
    tcp_tools_window = CustomWindow("TCP Tools", 800, 600, theme)
    frame = tcp_tools_window.frame

    ttk.Label(frame, text="Host: ").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    host_entry = ttk.Entry(frame, width=50)
    host_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

    tool_selection = ttk.Combobox(frame, values=["Ping", "Dig/Nslookup", "Traceroute"], state="readonly")
    tool_selection.grid(row=1, column=0, padx=5, pady=5)
    tool_selection.set("Ping")

    result_text = create_scrollable_text(frame, 20, 60, theme, 3, 0, 2)

    def run_tool():
        host = host_entry.get().strip()
        tool = tool_selection.get()
        if host:
            try:
                result_text.delete(1.0, tk.END)
                if tool == "Ping":
                    response = subprocess.run(["ping", "-c", "4", host], capture_output=True, text=True)
                elif tool == "Dig":
                    response = subprocess.run(["dig", host], capture_output=True, text=True)
                elif tool == "Traceroute":
                    response = subprocess.run(["traceroute", host], capture_output=True, text=True)
                else:
                    result_text.insert(tk.END, "Unknown tool selected.")
                    return
                result_text.insert(tk.END, response.stdout)
            except Exception as e:
                result_text.insert(tk.END, f"Error running {tool}: {e}")

    ttk.Button(frame, text="Run", command=run_tool).grid(row=1, column=0, padx=5, pady=5, sticky="e")
    ttk.Button(frame, text="Close", command=tcp_tools_window.window.destroy).grid(row=1, column=1, padx=5, pady=5, sticky="e")

def show_cert_details_window():
    cert_data = load_certificates()
    cert_window = tk.Toplevel()
    cert_window.title("Certificate Details")
    cert_window.geometry("600x400")

    frame = ttk.Frame(cert_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    text_widget = tk.Text(frame, wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    cert_pem = cert_data["certificate"]
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    public_key_pem = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    text_widget.insert(tk.END, "Certificate:\n")
    text_widget.insert(tk.END, cert_pem)
    text_widget.insert(tk.END, "\n\nPublic Key:\n")
    text_widget.insert(tk.END, public_key_pem)

    ttk.Button(cert_window, text="Close", command=cert_window.destroy).pack(padx=5, pady=5)

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


def open_jwt_window(theme):
    jwt_window = CustomWindow("JWT Decoder", 600, 400, theme)
    frame = jwt_window.frame

    jwt_entry = create_labeled_entry(frame, "JWT:", 0, 0, width=80)

    result_text = create_scrollable_text(frame, 15, 60, theme, 2, 0, 2)

    def decode_jwt():
        token = jwt_entry.get().strip()
        if not token:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a JWT.")
            return

        try:
            # Split the JWT into its parts
            header_b64, payload_b64, signature_b64 = token.split('.')
            
            # Decode the JWT parts
            header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
            
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Header:\n{json.dumps(header, indent=4)}\n\n")
            result_text.insert(tk.END, f"Payload:\n{json.dumps(payload, indent=4)}\n\n")
            result_text.insert(tk.END, f"Signature:\n{signature_b64}\n")
        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Error decoding JWT: {e}")

    ttk.Button(frame, text="Decode JWT", command=decode_jwt).grid(row=1, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Close", command=jwt_window.window.destroy).grid(row=3, column=1, padx=5, pady=5, sticky="e")

def open_ssl_cert_reader(theme):
    ssl_cert_window = CustomWindow("SSL Certificate Reader", 800, 600, theme)
    frame = ssl_cert_window.frame

    cert_file_entry = create_labeled_entry(frame, "Certificate File Path:", 0, 0)
    cert_text_entry = create_scrollable_text(frame, 10, 60, theme, 2, 0, 2)

    result_text = create_scrollable_text(frame, 10, 60, theme, 4, 0, 2)

    def read_ssl_certificate():
        cert_file_path = cert_file_entry.get().strip()
        cert_text = cert_text_entry.get("1.0", tk.END).strip()
        
        if not cert_file_path and not cert_text:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a certificate file path or paste the certificate text.")
            return

        try:
            if cert_file_path:
                with open(cert_file_path, "rb") as cert_file:
                    cert_data = cert_file.read()
            else:
                cert_data = cert_text.encode()

            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Certificate Details:\n\n")
            result_text.insert(tk.END, cert.public_bytes(serialization.Encoding.PEM).decode())

            # Display certificate details
            result_text.insert(tk.END, f"\nIssuer: {cert.issuer.rfc4514_string()}")
            result_text.insert(tk.END, f"\nSubject: {cert.subject.rfc4514_string()}")
            result_text.insert(tk.END, f"\nSerial Number: {cert.serial_number}")
            result_text.insert(tk.END, f"\nNot Valid Before: {cert.not_valid_before}")
            result_text.insert(tk.END, f"\nNot Valid After: {cert.not_valid_after}")
            result_text.insert(tk.END, f"\nPublic Key:\n{cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")
        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Error reading certificate: {e}")

    ttk.Button(frame, text="Read Certificate", command=read_ssl_certificate).grid(row=3, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Close", command=ssl_cert_window.window.destroy).grid(row=5, column=1, padx=5, pady=5, sticky="e")


def generate_self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"localhost")
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    
    key_file = "key_file.pem"
    cert_file = "cert_file.pem"
    
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_certificates():
    key_file = "key_file.pem"
    cert_file = "cert_file.pem"

    if os.path.exists(key_file) and os.path.exists(cert_file):
        return {"private_key": key_file, "certificate": cert_file}
    generate_self_signed_cert()
    return {"private_key": key_file, "certificate": cert_file}


def show_certificate():
    cert_data = load_certificates()
    cert_window = tk.Toplevel()
    cert_window.title("Certificate Details")
    cert_window.geometry("600x400")

    frame = ttk.Frame(cert_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    text_widget = tk.Text(frame, wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_widget.insert(tk.END, "Certificate:\n")
    text_widget.insert(tk.END, cert_data["certificate"])
    text_widget.insert(tk.END, "\n\nPrivate Key:\n")
    text_widget.insert(tk.END, cert_data["private_key"])

    ttk.Button(cert_window, text="Close", command=cert_window.destroy).pack(padx=5, pady=5)

def create_labeled_entry(frame, text, row, col, width=50):
    ttk.Label(frame, text=text).grid(row=row, column=col, padx=5, pady=5)
    entry = ttk.Entry(frame, width=width)
    entry.grid(row=row + 1, column=col, padx=5, pady=5, sticky="ew")
    return entry

def create_scrollable_text(frame, height, width, theme, row, col, colspan=1):
    text_widget = tk.Text(frame, wrap=tk.WORD, height=height, width=width, bg=NORD_STYLES[theme]["background"], fg=NORD_STYLES[theme]["foreground"])
    text_widget.grid(row=row, column=col, columnspan=colspan, padx=5, pady=5, sticky="nsew")
    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.grid(row=row, column=col + colspan, sticky="ns")
    return text_widget

def fetch_well_known(endpoint, result_text):
    try:
        response = requests.get(endpoint, verify=False)
        response.raise_for_status()
        well_known_data = response.json()
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, json.dumps(well_known_data, indent=4))
    except Exception as e:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Error fetching well-known endpoint: {e}")

def get_tokens(well_known_url, client_id, client_secret, redirect_uri, auth_code, result_text, flow):
    try:
        well_known_response = requests.get(well_known_url, verify=False)
        well_known_response.raise_for_status()
        well_known_data = well_known_response.json()
        token_url = well_known_data.get("token_endpoint")

        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'code': auth_code,
            'grant_type': 'authorization_code'
        }

        token_response = requests.post(token_url, verify=False, data=data)
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        id_token = token_data.get("id_token", "N/A")

        if flow == "OIDC":
            introspect_url = well_known_data.get("introspection_endpoint")
            introspect_response = requests.post(introspect_url, verify=False, data={
                'token': access_token,
                'client_id': client_id,
                'client_secret': client_secret
            })
            introspect_data = introspect_response.json()
            userinfo_url = well_known_data.get("userinfo_endpoint")
            userinfo_response = requests.get(userinfo_url, verify=False, headers={
                'Authorization': f"Bearer {access_token}"
            })
            userinfo_data = userinfo_response.json()
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Access Token:\n{access_token}\n\nID Token:\n{id_token}\n\nIntrospect Response:\n{introspect_data}\n\nUserinfo Response:\n{userinfo_data}")
        elif flow == "OAuth":
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Access Token:\n{access_token}\n\nID Token:\n{id_token}")
    except Exception as e:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Error retrieving tokens: {e}")

# Function to start a simple HTTP server to handle the redirect URI
class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if '/callback' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            auth_code = self.path.split('code=')[-1]
            self.wfile.write(f"Authorization Code: {auth_code}".encode('utf-8'))
            # Close the server once the auth code is received
            threading.Thread(target=httpd.shutdown).start()

def start_http_server():
    global httpd
    server_address = ('', 8000)
    cert_data = load_certificates()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_data["certificate"], keyfile=cert_data["private_key"])

    httpd = HTTPServer(server_address, RedirectHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


# Function to open the authorization URL in the browser
#def open_authorization_url(auth_url):
 #   webbrowser.open(auth_url)


def open_oauth_window(theme):
    oauth_window = CustomWindow("OAuth Debugger", 1200, 600, theme)
    frame = oauth_window.frame

    well_known_entry = create_labeled_entry(frame, "OAuth Well-Known Endpoint:", 1, 0)
    token_endpoint_entry = create_labeled_entry(frame, "Token Endpoint:", 3, 0)
    client_id_entry = create_labeled_entry(frame, "Client ID:", 5, 0)
    client_secret_entry = create_labeled_entry(frame, "Client Secret:", 7, 0)
    scopes_entry = create_labeled_entry(frame, "Scopes (space-separated):", 9, 0)

    result_text = create_scrollable_text(frame, 15, 60, theme, 11, 0, 2)

    well_known_table_frame = ttk.Frame(frame)
    well_known_table_frame.grid(row=0, column=3, rowspan=12, padx=10, pady=10, sticky="nsew")

    well_known_table = CustomTable(well_known_table_frame, ("Key", "Value"), 0, 0)

    def fetch_well_known_oauth():
        well_known_url = well_known_entry.get().strip()
        if not well_known_url:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a Well-Known Endpoint URL.")
            return

        try:
            well_known_response = requests.get(well_known_url, verify=False)
            well_known_response.raise_for_status()
            well_known_data = well_known_response.json()
            token_endpoint = well_known_data.get("token_endpoint", "")
            token_endpoint_entry.delete(0, tk.END)
            token_endpoint_entry.insert(0, token_endpoint)
            result_text.insert(tk.END, "Well-Known Endpoint fetched successfully.\n")
            
            well_known_table.clear_table()
            for key, value in well_known_data.items():
                well_known_table.insert_row((key, value))
        except Exception as e:
            result_text.insert(tk.END, f"Error fetching Well-Known Endpoint: {e}")

    def decode_jwt(token):
        try:
            header, payload, signature = token.split('.')
            header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
            payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
            decoded = {
                "header": json.loads(header_decoded),
                "payload": json.loads(payload_decoded),
                "signature": signature
            }
            return json.dumps(decoded, indent=4)
        except Exception as e:
            return f"Error decoding JWT: {e}"

    def get_oauth_tokens():
        token_endpoint = token_endpoint_entry.get().strip()
        client_id = client_id_entry.get().strip()
        client_secret = client_secret_entry.get().strip()
        scopes = scopes_entry.get().strip()

        if not all([token_endpoint, client_id, client_secret, scopes]):
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please fill in all fields to get tokens.")
            return

        result_text.delete(1.0, tk.END)
        try:
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials',
                'scope': scopes
            }

            response = requests.post(token_endpoint, data=data, verify=False)
            response.raise_for_status()
            token_data = response.json()
            access_token = token_data.get('access_token')
            result_text.insert(tk.END, f"Access Token:\n{access_token}\n\n")
            result_text.insert(tk.END, f"Token Type:\n{token_data.get('token_type')}\n\n")
            result_text.insert(tk.END, f"Expires In:\n{token_data.get('expires_in')}\n\n")

            if access_token:
                decoded_token = decode_jwt(access_token)
                result_text.insert(tk.END, f"Decoded Access Token:\n{decoded_token}\n\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error retrieving OAuth tokens: {e}")

    def show_cert_details():
        show_certificate_details()

    ttk.Button(frame, text="Fetch Well-Known OAuth", command=fetch_well_known_oauth).grid(row=2, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Get Tokens", command=get_oauth_tokens).grid(row=10, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Show Certificate Details", command=show_cert_details).grid(row=0, column=0, padx=5, pady=5, sticky="e")
    ttk.Button(frame, text="Close", command=oauth_window.window.destroy).grid(row=12, column=1, padx=5, pady=5, sticky="e")

def show_certificate_details():
    cert_data = load_certificates()
    cert_window = tk.Toplevel()
    cert_window.title("Certificate Details")
    cert_window.geometry("600x400")

    frame = ttk.Frame(cert_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    text_widget = tk.Text(frame, wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True)

    scrollbar_x = ttk.Scrollbar(frame, orient="horizontal", command=text_widget.xview)
    text_widget.configure(xscrollcommand=scrollbar_x.set)
    scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

    scrollbar_y = ttk.Scrollbar(frame, orient="vertical", command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar_y.set)
    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

    text_widget.insert(tk.END, "Certificate:\n")
    with open(cert_data["certificate"], "r") as cert_file:
        cert_content = cert_file.read()
        text_widget.insert(tk.END, cert_content)
    text_widget.insert(tk.END, "\n\nPublic Key:\n")
    cert = x509.load_pem_x509_certificate(cert_content.encode(), default_backend())
    public_key = cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    text_widget.insert(tk.END, public_key)

    ttk.Button(cert_window, text="Close", command=cert_window.destroy).pack(padx=5, pady=5)


def open_oidc_window(theme, well_known_data=None):
    oidc_window = CustomWindow("OIDC Debugger", 1200, 900, theme)
    frame = oidc_window.frame

    well_known_entry = create_labeled_entry(frame, "OIDC Well-Known Endpoint:", 1, 0)
    if well_known_data:
        well_known_entry.insert(0, well_known_data)

    result_text = create_scrollable_text(frame, 10, 60, theme, 3, 0, 2)
    my_auth_url = ""

    well_known_table_frame = ttk.Frame(frame)
    well_known_table_frame.grid(row=0, column=3, rowspan=12, padx=10, pady=10, sticky="nsew")

    well_known_table = CustomTable(well_known_table_frame, ("Key", "Value"), 0, 0, title="Well-Known Endpoint Data")

    auth_url_table_frame = ttk.Frame(frame)
    auth_url_table_frame.grid(row=16, column=0, rowspan=2, padx=10, pady=10, sticky="ew")

    auth_url_table = CustomTable(auth_url_table_frame, ("Auth URL",), 0, 0)

    ttk.Button(frame, text="Fetch Well-Known", command=lambda: fetch_well_known(well_known_entry.get(), result_text, well_known_table,my_auth_url)).grid(row=2, column=1, padx=5, pady=5)

    client_id_entry = create_labeled_entry(frame, "Client ID:", 5, 0)
    client_secret_entry = create_labeled_entry(frame, "Client Secret:", 7, 0)
    auth_code_entry = create_labeled_entry(frame, "Authorization Code:", 9, 0)
    scopes_entry = create_labeled_entry(frame, "Scopes (space-separated):", 11, 0)

    redirect_uri_entry = ttk.Entry(frame, width=50)
    redirect_uri_entry.insert(0, "https://localhost:8000/callback")
    redirect_uri_entry.grid(row=13, column=0, padx=5, pady=5)

    token_endpoint_entry = create_labeled_entry(frame, "Token Endpoint:", 15, 0)
    introspect_endpoint_entry = create_labeled_entry(frame, "Introspect Endpoint:", 17, 0)
    userinfo_endpoint_entry = create_labeled_entry(frame, "Userinfo Endpoint:", 19, 0)
    authorization_endpoint_entry = create_labeled_entry(frame, "Authorization Endpoint:", 19, 0)

    state_entry = create_labeled_entry(frame, "State:", 21, 0)
    nonce_entry = create_labeled_entry(frame, "Nonce:", 23, 0)

    request_table_frame = ttk.Frame(frame)
    request_table_frame.grid(row=0, column=5, rowspan=14, padx=10, pady=10, sticky="nsew")

    request_table = CustomTable(request_table_frame, ("Parameter", "Value"), 0, 0)

    introspection_frame = ttk.Frame(frame)
    introspection_frame.grid(row=14, column=5, rowspan=5, padx=10, pady=10, sticky="nsew")

    introspection_request_table = CustomTable(introspection_frame, ("Parameter", "Value"), 0, 0)
    introspection_response_table = CustomTable(introspection_frame, ("Field", "Value"), 1, 0)

    def update_request_table():
        request_table.clear_table()
        request_table.insert_row(("Client ID", client_id_entry.get()))
        request_table.insert_row(("Client Secret", client_secret_entry.get()))
        request_table.insert_row(("Redirect URI", redirect_uri_entry.get()))
        request_table.insert_row(("Authorization Code", auth_code_entry.get()))
        request_table.insert_row(("Scopes", scopes_entry.get()))
        request_table.insert_row(("State", state_entry.get()))
        request_table.insert_row(("Nonce", nonce_entry.get()))

    def populate_endpoints(well_known_data):
        token_endpoint = well_known_data.get("token_endpoint", "")
        introspect_endpoint = well_known_data.get("introspection_endpoint", "")
        authorization_endpoint = well_known_data.get("authorization_endpoint", "")
        userinfo_endpoint = well_known_data.get("userinfo_endpoint", "")
        token_endpoint_entry.delete(0, tk.END)
        token_endpoint_entry.insert(0, token_endpoint)
        introspect_endpoint_entry.delete(0, tk.END)
        introspect_endpoint_entry.insert(0, introspect_endpoint)
        userinfo_endpoint_entry.delete(0, tk.END)
        userinfo_endpoint_entry.insert(0, userinfo_endpoint)
        #authorization_endpoint_entry.delete(0, tk.END)
       # authorization_endpoint_entry.insert(0, authorization_endpoint)

    def fetch_well_known(url, result_text, well_known_table, my_auth_url):
        if not url:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a Well-Known Endpoint URL.")
            return

        try:
            well_known_response = requests.get(url, verify=False)
            well_known_response.raise_for_status()
            well_known_data = well_known_response.json()
            populate_endpoints(well_known_data)
            result_text.insert(tk.END, "Well-Known Endpoint fetched successfully.\n")
            
            well_known_table.clear_table()
            for key, value in well_known_data.items():
                well_known_table.insert_row((key, value))
               	if key == "authorization_endpoint":
                    my_auth_url=value
                    #print (value)
        except Exception as e:
            result_text.insert(tk.END, f"Error fetching Well-Known Endpoint: {e}")

    def decode_jwt(token):
        try:
            header, payload, signature = token.split('.')
            header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
            payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
            decoded = {
                "header": json.loads(header_decoded),
                "payload": json.loads(payload_decoded),
                "signature": signature
            }
            return json.dumps(decoded, indent=4)
        except Exception as e:
            return f"Error decoding JWT: {e}"

    def construct_auth_url():
        #auth_url_base = well_known_table("authorization_endpoint")
        state = state_entry.get()
        nonce = nonce_entry.get()
        params = {
            "response_type": "code",
            "client_id": client_id_entry.get(),
            "redirect_uri": redirect_uri_entry.get(),
            "scope": scopes_entry.get(),
            "state": state,
            "nonce": nonce
        }
        auth_url = f"{auth_url_base}?{urlencode(params)}"
        result_text.insert(tk.END, f"Authorization URL:\n{auth_url}\n\n")
        auth_url_table.clear_table()
        auth_url_table.insert_row((auth_url,))
        print (auth_url)
        return auth_url

    def open_authorization_url():
        auth_url = construct_auth_url()
        webbrowser.open(auth_url)

    def extract_auth_code_from_url(callback_url):
        parsed_url = urlparse(callback_url)
        auth_code = parse_qs(parsed_url.query).get('code', [None])[0]
        return auth_code

    def get_and_display_tokens(auth_code):
        update_request_table()
        token_endpoint = token_endpoint_entry.get()
        client_id = client_id_entry.get()
        client_secret = client_secret_entry.get()
        redirect_uri = redirect_uri_entry.get()
        result_text.delete(1.0, tk.END)
        try:
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'code': auth_code,
                'grant_type': 'authorization_code'
            }

            token_response = requests.post(token_endpoint, data=data, verify=False)
            token_response.raise_for_status()
            token_data = token_response.json()

            access_token = token_data.get("access_token")
            id_token = token_data.get("id_token", "N/A")
            refresh_token = token_data.get("refresh_token", "N/A")

            result_text.insert(tk.END, f"Access Token:\n{access_token}\n\nID Token:\n{id_token}\n\nRefresh Token:\n{refresh_token}\n\n")

            if access_token:
                decoded_token = decode_jwt(access_token)
                result_text.insert(tk.END, f"Decoded Access Token:\n{decoded_token}\n\n")

            if id_token and id_token != "N/A":
                decoded_id_token = decode_jwt(id_token)
                result_text.insert(tk.END, f"Decoded ID Token:\n{decoded_id_token}\n\n")

            introspect_and_userinfo(access_token)
        except Exception as e:
            result_text.insert(tk.END, f"Error retrieving tokens: {e}")

    def introspect_and_userinfo(access_token):
        introspect_endpoint = introspect_endpoint_entry.get()
        userinfo_endpoint = userinfo_endpoint_entry.get()

        introspection_request_table.clear_table()
        introspection_response_table.clear_table()
        try:
            introspect_data = {
                'token': access_token,
                'client_id': client_id_entry.get(),
                'client_secret': client_secret_entry.get()
            }

            introspection_request_table.insert_row(("token", access_token))
            introspection_request_table.insert_row(("client_id", client_id_entry.get()))
            introspection_request_table.insert_row(("client_secret", client_secret_entry.get()))

            introspect_response = requests.post(introspect_endpoint, data=introspect_data, verify=False)
            introspect_response.raise_for_status()
            introspect_response_data = introspect_response.json()

            result_text.insert(tk.END, "Introspection Response:\n")
            for key, value in introspect_response_data.items():
                introspection_response_table.insert_row((key, value))
                result_text.insert(tk.END, f"{key}: {value}\n")

            userinfo_response = requests.get(userinfo_endpoint, headers={'Authorization': f'Bearer {access_token}'}, verify=False)
            userinfo_response.raise_for_status()
            userinfo_data = userinfo_response.json()

            result_text.insert(tk.END, "\nUserinfo Response:\n")
            for key, value in userinfo_data.items():
                result_text.insert(tk.END, f"{key}: {value}\n")

        except Exception as e:
            result_text.insert(tk.END, f"Error during introspection or userinfo fetch: {e}")

    def show_cert_details():
        show_certificate_details()

    ttk.Button(frame, text="Get Tokens", command=lambda: get_and_display_tokens(auth_code_entry.get())).grid(row=19, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Construct Auth URL", command=construct_auth_url).grid(row=18, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Open Auth URL", command=open_authorization_url).grid(row=18, column=2, padx=5, pady=5)
    ttk.Button(frame, text="Show Certificate Details", command=show_cert_details).grid(row=0, column=0, padx=5, pady=5, sticky="e")
    ttk.Button(frame, text="Close", command=oidc_window.window.destroy).grid(row=20, column=1, padx=5, pady=5, sticky="e")

def show_certificate_details():
    cert_data = load_certificates()
    cert_window = tk.Toplevel()
    cert_window.title("Certificate Details")
    cert_window.geometry("600x400")

    frame = ttk.Frame(cert_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    text_widget = tk.Text(frame, wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True)

    scrollbar_x = ttk.Scrollbar(frame, orient="horizontal", command=text_widget.xview)
    text_widget.configure(xscrollcommand=scrollbar_x.set)
    scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

    scrollbar_y = ttk.Scrollbar(frame, orient="vertical", command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar_y.set)
    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

    text_widget.insert(tk.END, "Certificate:\n")
    with open(cert_data["certificate"], "r") as cert_file:
        cert_content = cert_file.read()
        text_widget.insert(tk.END, cert_content)
    text_widget.insert(tk.END, "\n\nPublic Key:\n")
    cert = x509.load_pem_x509_certificate(cert_content.encode(), default_backend())
    public_key = cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    text_widget.insert(tk.END, public_key)

    ttk.Button(cert_window, text="Close", command=cert_window.destroy).pack(padx=5, pady=5)


class CustomWindow:
    def __init__(self, title, width, height, theme):
        self.window = tk.Toplevel()
        self.window.title(title)
        self.window.geometry(f"{width}x{height}")
        self.theme = theme
        self.apply_theme()

        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

    def apply_theme(self):
        style = ttk.Style(self.window)
        colors = NORD_STYLES[self.theme]
        style.configure("TFrame", background=colors["background"])
        style.configure("TLabel", background=colors["background"], foreground=colors["foreground"])
        style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
        style.map("TButton", background=[("active", colors["highlight"])])
        style.configure("TEntry", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
        style.configure("TText", background=colors["background"], foreground=colors["foreground"])

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

def create_errors_file():
    file_name = 'errors.json'
    if not os.path.exists(file_name):
        with open(file_name, 'w') as file:
            json.dump([], file)
        print(f"{file_name} created.")
    else:
        print(f"{file_name} already exists.")

def show_help():
    help_window = tk.Toplevel()
    help_window.title("Help")
    help_window.geometry("400x300")

    style = ttk.Style(help_window)
    colors = NORD_STYLES["standard"]
    style.configure("TFrame", background=colors["background"])
    style.configure("TLabel", background=colors["background"], foreground=colors["foreground"])
    style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
    style.map("TButton", background=[("active", colors["highlight"])])

    frame = ttk.Frame(help_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    help_text = (
        "Welcome to the Network Tools Application!\n\n"
        "Features:\n"
        "- NSLookup: Perform DNS lookups for a list of domains.\n"
        "- HTTPRequest: Perform HTTP requests to a list of URLs.\n"
        "- JWKSCheck: Verify certificates from a JWKS endpoint.\n"
        "- Play Audio: Play an audio file.\n"
        "- Ping Tool: Diagnose network issues by pinging hosts.\n"
        "- JWT Decoder: Decode and display JWTs.\n"
        "- SAML Decoder: Decode and display SAML tokens.\n"
        "- OIDC Debugger: Test OIDC using PKCE and view tokens.\n"
        "- OAuth Debugger: Test OAuth using Client Credentials and view tokens.\n"
        "- SSL Certificate Reader: Read and display SSL certificate details.\n"
        "- Backup and Restore all current settings.\n"
        "Double-click any row to delete it.\n"
    )

    ttk.Label(frame, text=help_text).pack(padx=5, pady=5)
    ttk.Button(frame, text="Close", command=help_window.destroy).pack(padx=5, pady=5)

def play_audio():
    pygame.mixer.init()
    fun = "aHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL3NvdW5kYm9hcmRzL0NhcnRvb25zL1RIRSBTSU1QU09OUy9NUiBCVVJOUy9NUDMvRVhDRUxMRU5UIC0gQVVESU8gRlJPTSBKQVlVWlVNSS5DT00ubXAz"
    url = base64.b64decode(fun)
    response = requests.get(url, verify=False)
    audio_data = BytesIO(response.content)
    pygame.mixer.music.load(audio_data)
    pygame.mixer.music.play()

def expand_all_tables(*args):
    for widget in args:
        widget.expand()

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
            return ["sso.fed.prod.aws.swalife.com", "sso.fed.prod.aws.swacorp.com", "sso.fed.qa.aws.swalife.com", "sso.fed.qa.aws.swacorp.com", "sso.fed.dev.aws.swalife.com", "sso.fed.dev.aws.swacorp.com", "sso.cfi.prod.aws.southwest.com" ]
    
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
        self.domains = ["sso.fed.prod.aws.swalife.com", "sso.fed.prod.aws.swacorp.com", "sso.fed.qa.aws.swalife.com", "sso.fed.qa.aws.swacorp.com", "sso.fed.dev.aws.swalife.com", "sso.fed.dev.aws.swacorp.com", "sso.cfi.prod.aws.southwest.com" ]
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
            #self.table.tree.grid()
            self.table.frame.grid()
            self.url_entry.grid()
            self.regex_entry.grid()
            self.add_url_btn.grid()
            self.refresh_btn.grid()
            self.reset_btn.grid()
            self.ignore_ssl_btn.grid()
            self.collapse_btn.config(text="Collapse")
        else:
            self.table.frame.grid_remove()
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
            initial_data = [{"url" : "sso.fed.prod.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok" }, {"url" : "sso.fed.prod.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.qa.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.qa.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.dev.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.dev.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.cfi.prod.aws.southwest.com/pf/heartbeat.ping", "regex" : "ok"}]
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
        self.urls = [{"url" : "sso.fed.prod.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok" }, {"url" : "sso.fed.prod.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.qa.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.qa.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.dev.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.dev.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.cfi.prod.aws.southwest.com/pf/heartbeat.ping", "regex" : "ok"}]
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
                if regex and re.search(regex, status_text):  # If regex matches response
                    status_text = "OK"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.table.insert_row((url, response.status_code, status_text, timestamp))
            except Exception as e:
                self.table.insert_row((url, "Error", str(e), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        self.master.after(600000, self.update_http_table)  # Auto-refresh every 10 minutes

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

        self.cert_scrollbar_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL, command=self.cert_table.xview)
        self.cert_table.configure(xscroll=self.cert_scrollbar_x.set)
        self.cert_scrollbar_x.grid(row=3, column=0, columnspan=4, sticky='ew')

        self.ec_table = self.setup_table(self.frame, ("Key Type", "Key ID", "Use", "X", "Y", "Curve"))
        self.ec_table.grid(row=4, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")

        self.ec_scrollbar_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.ec_table.yview)
        self.ec_table.configure(yscroll=self.ec_scrollbar_y.set)
        self.ec_scrollbar_y.grid(row=4, column=4, sticky='ns')

        self.ec_scrollbar_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL, command=self.ec_table.xview)
        self.ec_table.configure(xscroll=self.ec_scrollbar_x.set)
        self.ec_scrollbar_x.grid(row=5, column=0, columnspan=4, sticky='ew')

        self.frame.rowconfigure(2, weight=1)
        self.frame.rowconfigure(4, weight=1)
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
            self.cert_scrollbar_x.grid()
            self.ec_table.grid()
            self.ec_scrollbar_y.grid()
            self.ec_scrollbar_x.grid()
            self.url_entry.grid()
            self.add_url_btn.grid()
            self.refresh_btn.grid()
            self.collapse_btn.config(text="Collapse")
        else:
            self.cert_table.grid_remove()
            self.cert_scrollbar_y.grid_remove()
            self.cert_scrollbar_x.grid_remove()
            self.ec_table.grid_remove()
            self.ec_scrollbar_y.grid_remove()
            self.ec_scrollbar_x.grid_remove()
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
            table.column(col, anchor=tk.W, width=150, stretch=True)
        return table

    def clear_table(self, table):
        for item in table.get_children():
            table.delete(item)

def backup_data(NSLookup, HTTPRequest):
    try:
        # Get Lookup Table
        try:
            with open("domains.json", "r") as file:
                nslookup_data=json.load(file)
        except FileNotFoundError:
            nslookup_data=["sso.fed.prod.aws.swalife.com", "sso.fed.prod.aws.swacorp.com", "sso.fed.qa.aws.swalife.com", "sso.fed.qa.aws.swacorp.com", "sso.fed.dev.aws.swalife.com", "sso.fed.dev.aws.swacorp.com", "sso.cfi.prod.aws.southwest.com" ]
        # Get HTTP Table
        if not os.path.exists("urls.json"):
            http_data = [{"url" : "sso.fed.prod.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok" }, {"url" : "sso.fed.prod.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.qa.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.qa.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.dev.aws.swalife.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.fed.dev.aws.swacorp.com/pf/heartbeat.ping", "regex" : "ok"}, {"url" : "sso.cfi.prod.aws.southwest.com/pf/heartbeat.ping", "regex" : "ok"}]
        with open("urls.json", "r") as file:
            http_data=json.load(file)
        #JOIN DATA
        data = {
            "nslookup": nslookup_data,
            "httprequest": http_data,
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

def main():
    create_errors_file()

    # Start local HTTP server for OIDC flow
    httpd_thread = threading.Thread(target=start_http_server)
    httpd_thread.daemon = True
    httpd_thread.start()

    root = tk.Tk()
    root.title("Southwest Airlines CyberOps Eng OpsTools")
    root.geometry("1200x800")

    # Apply custom theme if it exists, otherwise apply default theme
    initial_theme = load_custom_theme()
    apply_theme(initial_theme)

    # Add a menu bar with a Custom Theme option
    menubar = tk.Menu(root)
    root.config(menu=menubar)
    
    options_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Options", menu=options_menu)
    options_menu.add_command(label="Custom Theme", command=open_custom_theme_window)

    # Add a frame at the top for navigation
    top_frame = ttk.Frame(root, padding="5")
    top_frame.grid(row=0, column=0, columnspan=3, sticky="ew")
    ttk.Button(top_frame, text="Play Audio", command=play_audio).pack(side=tk.LEFT, padx=5, pady=5)
    ttk.Button(top_frame, text="Expand All Tables", command=lambda: expand_all_tables(nslookup, http_request, jwks_check)).pack(side=tk.LEFT, padx=5, pady=5)
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
    ttk.Radiobutton(sidebar, text="Frost", variable=theme_var, value="frost", command=lambda: apply_theme(theme_var.get())).grid(row=3, column=0, padx=5, pady=5)
    ttk.Radiobutton(sidebar, text="Aurora", variable=theme_var, value="aurora", command=lambda: apply_theme(theme_var.get())).grid(row=4, column=0, padx=5, pady=5)
    ttk.Label(sidebar, text="Diagnostic Tools:").grid(row=5, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="TCP Tools", command=lambda: open_tcp_tools_window(theme_var.get())).grid(row=6, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="JWT Decoder", command=lambda: open_jwt_window(theme_var.get())).grid(row=7, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="SAML Decoder", command=lambda: open_saml_window(theme_var.get())).grid(row=8, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="OIDC Debugger", command=lambda: open_oidc_window(theme_var.get())).grid(row=9, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="OAuth Debugger", command=lambda: open_oauth_window(theme_var.get())).grid(row=10, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="SSL Certificate Reader", command=lambda: open_ssl_cert_reader(theme_var.get())).grid(row=11, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="JWKS Check", command=lambda: open_jwks_check_window(theme_var.get())).grid(row=12, column=0, padx=5, pady=5)


    nslookup = NSLookup(scrollable_frame, theme_var.get())
    http_request = HTTPRequest(scrollable_frame, theme_var.get())
 #   jwks_check = JWKSCheck(scrollable_frame, theme_var.get())

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
#    jwks_check.expand()
    root.mainloop()

if __name__ == "__main__":
    custom_theme = load_custom_theme()
    main()

```
