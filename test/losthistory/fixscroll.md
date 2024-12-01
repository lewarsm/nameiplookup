```
import tkinter as tk
from tkinter import ttk

class NSLookup:
    def __init__(self, parent):
        self.canvas = ttk.Canvas(parent, width=300, height=200)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Add vertical scrollbar
        self.v_scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.canvas.yview)
        self.v_scrollbar.pack(side=tk.LEFT, fill=tk.Y)

        # Configure canvas scrollbar
        self.canvas.configure(yscrollcommand=self.v_scrollbar.set)

        # Add content to canvas
        self.populate_canvas()

    def populate_canvas(self):
        # Example content
        self.canvas.create_rectangle(50, 50, 400, 300, fill="blue")
        self.canvas.create_text(225, 175, text="NSLookup Content", fill="white")

        # Configure scroll region
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))


class HTTPRequest:
    def __init__(self, parent):
        self.canvas = ttk.Canvas(parent, width=300, height=200)
        self.canvas.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Add vertical scrollbar
        self.v_scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.canvas.yview)
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Configure canvas scrollbar
        self.canvas.configure(yscrollcommand=self.v_scrollbar.set)

        # Add content to canvas
        self.populate_canvas()

    def populate_canvas(self):
        # Example content
        self.canvas.create_rectangle(50, 50, 400, 300, fill="green")
        self.canvas.create_text(225, 175, text="HTTPRequest Content", fill="white")

        # Configure scroll region
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Separate Scrollbars Example")

    # Create frames for each class
    nslookup_frame = ttk.Frame(root)
    nslookup_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    httprequest_frame = ttk.Frame(root)
    httprequest_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # Initialize classes with their respective frames
    nslookup = NSLookup(nslookup_frame)
    httprequest = HTTPRequest(httprequest_frame)

    root.mainloop()

```
