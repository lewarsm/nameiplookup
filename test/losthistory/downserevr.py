```
import requests
import tkinter as tk
import json
import jwt

def exchange_code_for_tokens(self, code):
    try:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": f"https://localhost:{self.server_port}/callback",
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

        # Call userinfo endpoint with the access token
        userinfo_response = self.fetch_user_info(tokens["access_token"])
        if userinfo_response:
            self.response_text.insert(tk.END, f"User Info: {json.dumps(userinfo_response, indent=4)}\n")
        
        # Shutdown the HTTP server after successfully fetching and displaying tokens
        self.httpd.shutdown()

    except Exception as e:
        self.response_text.insert(tk.END, f"Error exchanging code for tokens: {e}\n")

def fetch_user_info(self, access_token):
    try:
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        response = requests.get(self.userinfo_endpoint, headers=headers, verify="server.crt")
        if response.status_code != 200:
            self.response_text.insert(tk.END, f"Error fetching user info: {response.status_code}\n")
            return None

        return response.json()

    except Exception as e:
        self.response_text.insert(tk.END, f"Error fetching user info: {e}\n")
        return None

# Other methods remain unchanged
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

```
