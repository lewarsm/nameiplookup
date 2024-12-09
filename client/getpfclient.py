import tkinter as tk
from tkinter import ttk, messagebox
import requests
from requests.auth import HTTPBasicAuth
import json

class PingFederateClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PingFederate Client App")
        
        self.base_urls = ["https://mine:9031/.well-known/openid-configuration", "https://localhost:9031/.well-known/openid-configuration"]
        
        self.setup_ui()
        
    def setup_ui(self):
        tk.Label(self.root, text="User ID").grid(row=0, column=0)
        self.user_id_entry = tk.Entry(self.root)
        self.user_id_entry.grid(row=0, column=1)
        
        tk.Label(self.root, text="Password").grid(row=1, column=0)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.grid(row=1, column=1)
        
        tk.Label(self.root, text="OpenID Configuration URL").grid(row=2, column=0)
        self.url_var = tk.StringVar(self.root)
        self.url_var.set(self.base_urls[0])
        self.url_dropdown = ttk.Combobox(self.root, textvariable=self.url_var, values=self.base_urls, state="readonly")
        self.url_dropdown.grid(row=2, column=1)
        
        tk.Label(self.root, text="Base URL").grid(row=3, column=0)
        self.base_url_entry = tk.Entry(self.root)
        self.base_url_entry.grid(row=3, column=1)
        self.base_url_entry.insert(0, self.url_var.get().replace("/.well-known/openid-configuration", "").replace("9031", "9999"))

        self.ignore_cert_var = tk.BooleanVar()
        self.ignore_cert_checkbutton = tk.Checkbutton(self.root, text="Ignore Self-Signed Certificates", variable=self.ignore_cert_var)
        self.ignore_cert_checkbutton.grid(row=4, column=0, columnspan=2)

        tk.Button(self.root, text="Fetch Clients", command=self.fetch_clients).grid(row=5, column=0, columnspan=2)
        
        self.client_listbox = tk.Listbox(self.root, selectmode=tk.SINGLE)
        self.client_listbox.grid(row=6, column=0, columnspan=2, sticky="nsew")
        
        tk.Button(self.root, text="Get Client Info", command=self.get_client_info).grid(row=7, column=0, columnspan=2)
        
        self.result_text = tk.Text(self.root, height=10, width=50)
        self.result_text.grid(row=8, column=0, columnspan=2, sticky="nsew")
        
        self.root.grid_rowconfigure(6, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        
    def fetch_clients(self):
        base_url = self.base_url_entry.get()
        clients_url = f"{base_url}/pf-admin-api/v1/oauth/clients"
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()
        verify_ssl = not self.ignore_cert_var.get()
        
        response = requests.get(clients_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=verify_ssl)
        if response.status_code == 200:
            clients = response.json().get("items", [])
            self.client_listbox.delete(0, tk.END)
            for client in clients:
                self.client_listbox.insert(tk.END, client["clientId"])
        else:
            messagebox.showerror("Error", f"Failed to fetch clients: {response.status_code}")
            
    def get_client_info(self):
        selected_client_index = self.client_listbox.curselection()
        if not selected_client_index:
            messagebox.showerror("Error", "Please select a client from the list")
            return
        
        selected_client = self.client_listbox.get(selected_client_index)
        base_url = self.base_url_entry.get()
        client_info_url = f"{base_url}/pf-admin-api/v1/oauth/clients/{selected_client}"
        access_token_manager_url = f"{base_url}/pf-admin-api/v1/oauth/accessTokenManagers/jwt"
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()
        verify_ssl = not self.ignore_cert_var.get()
        
        client_info_response = requests.get(client_info_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=verify_ssl)
        if client_info_response.status_code == 200:
            client_info = client_info_response.json()
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, json.dumps(client_info, indent=4))
            
            access_token_manager_response = requests.get(access_token_manager_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=verify_ssl)
            if access_token_manager_response.status_code == 200:
                access_token_manager_info = access_token_manager_response.json()
                self.result_text.insert(tk.END, "\n\n")
                self.result_text.insert(tk.END, json.dumps(access_token_manager_info, indent=4))
            else:
                messagebox.showerror("Error", f"Failed to fetch access token manager info: {access_token_manager_response.status_code}")
        else:
            messagebox.showerror("Error", f"Failed to fetch client info: {client_info_response.status_code}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PingFederateClientApp(root)
    root.mainloop()
