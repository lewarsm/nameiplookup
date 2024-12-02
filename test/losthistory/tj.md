```
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

class FirstFrame:
    def __init__(self, parent):
        # Create a frame inside the parent
        self.frame = ttk.Frame(parent, borderwidth=2, relief="groove")
        self.frame.grid(row=1, column=0, sticky="nsew")

        # Create a canvas and add a scrollbar
        self.canvas = tk.Canvas(self.frame)
        self.scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Add content to the canvas
        self.content_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.content_frame, anchor="nw")

        # Populate the frame with widgets
        for i in range(20):
            ttk.Label(self.content_frame, text=f"Item {i+1} in FirstFrame").grid(row=i, column=0, padx=10, pady=5)

        self.content_frame.update_idletasks()
        self.canvas.config(scrollregion=self.canvas.bbox("all"))


class SecondFrame:
    def __init__(self, parent):
        # Create a frame inside the parent
        self.frame = ttk.Frame(parent, borderwidth=2, relief="groove")
        self.frame.grid(row=2, column=0, sticky="nsew")

        # Create a canvas and add a scrollbar
        self.canvas = tk.Canvas(self.frame)
        self.scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Add content to the canvas
        self.content_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.content_frame, anchor="nw")

        # Populate the frame with widgets
        for i in range(20):
            ttk.Label(self.content_frame, text=f"Item {i+1} in SecondFrame").grid(row=i, column=0, padx=10, pady=5)

        self.content_frame.update_idletasks()
        self.canvas.config(scrollregion=self.canvas.bbox("all"))


class App:
    def __init__(self, root):
        root.title("Tkinter Canvas with Multiple Frames")
        root.geometry("800x600")

        # Configure the main grid layout
        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=0)
        root.rowconfigure(0, weight=0)
        root.rowconfigure(1, weight=1)
        root.rowconfigure(2, weight=1)

        # Add a top bar with a Help button
        self.top_bar = ttk.Frame(root, borderwidth=2, relief="groove")
        self.top_bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        help_button = ttk.Button(self.top_bar, text="Help", command=self.show_help)
        help_button.pack(side="left", padx=5, pady=5)

        # Add a toolbar on the right with buttons for Ping and Nslookup
        self.toolbar = ttk.Frame(root, borderwidth=2, relief="groove")
        self.toolbar.grid(row=1, column=1, rowspan=2, sticky="ns")
        ping_button = ttk.Button(self.toolbar, text="Ping", command=self.open_ping_window)
        ping_button.pack(pady=10)
        nslookup_button = ttk.Button(self.toolbar, text="Nslookup", command=self.open_nslookup_window)
        nslookup_button.pack(pady=10)

        # Create frames using FirstFrame and SecondFrame classes
        self.first_frame = FirstFrame(root)
        self.second_frame = SecondFrame(root)

    def show_help(self):
        messagebox.showinfo("Help", "This is a sample application with multiple frames, a top bar, and a toolbar.")

    def open_ping_window(self):
        ping_window = tk.Toplevel()
        ping_window.title("Ping")
        ping_window.geometry("400x300")
        ttk.Label(ping_window, text="Ping Functionality").pack(pady=20)

    def open_nslookup_window(self):
        nslookup_window = tk.Toplevel()
        nslookup_window.title("Nslookup")
        nslookup_window.geometry("400x300")
        ttk.Label(nslookup_window, text="Nslookup Functionality").pack(pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()

```
