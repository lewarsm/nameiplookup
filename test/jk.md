```
import base64
import requests

def open_jwks_check_window(theme):
    jwks_check_window = CustomWindow("JWKS Check Tool", 800, 600, theme)
    frame = jwks_check_window.frame

    jwks_url_entry = create_labeled_entry(frame, "JWKS URL:", 0, 0)
    token_entry = create_labeled_entry(frame, "Token:", 1, 0)

    result_text = create_scrollable_text(frame, 20, 60, theme, 3, 0, 2)

    def check_jwks():
        jwks_url = jwks_url_entry.get().strip()
        token = token_entry.get().strip()
        if jwks_url and token:
            try:
                result_text.delete(1.0, tk.END)
                jwks_response = requests.get(jwks_url)
                jwks_response.raise_for_status()
                jwks_data = jwks_response.json()
                header, payload, signature = token.split('.')
                header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
                payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
                result_text.insert(tk.END, f"Header:\n{header_decoded}\n\n")
                result_text.insert(tk.END, f"Payload:\n{payload_decoded}\n\n")
                result_text.insert(tk.END, f"JWKS Data:\n{json.dumps(jwks_data, indent=4)}\n\n")
            except Exception as e:
                result_text.insert(tk.END, f"Error checking JWKS: {e}")

    ttk.Button(frame, text="Check JWKS", command=check_jwks).grid(row=2, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Close", command=jwks_check_window.window.destroy).grid(row=4, column=1, padx=5, pady=5, sticky="e")

```
