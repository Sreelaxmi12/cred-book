import os
import json
import base64
import tkinter as tk
from tkinter import messagebox
from hashlib import sha256
from cryptography.fernet import Fernet

VAULT_FILE = 'vault.json'

BG_COLOR = '#121212'
FG_PURPLE = '#BB86FC'
FG_GREEN = '#03DAC6'
FONT = ('Segoe UI', 11)

def generate_key(master_password):
    return base64.urlsafe_b64encode(sha256(master_password.encode()).digest())

def load_vault(key):
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, 'rb') as f:
        encrypted_data = f.read()

    if not encrypted_data:
        return {}

    try:
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data)
    except Exception:
        messagebox.showerror("Error", "Incorrect master password or corrupted vault.")
        return None

def save_vault(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json.dumps(data).encode())

    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypted_data)

class PasswordKeeperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Keeper")
        self.root.configure(bg=BG_COLOR)

        self.vault = {}
        self.key = None
        self.show_passwords = False

        self.create_login_ui()

    def create_login_ui(self):
        self.clear_window()

        tk.Label(self.root, text="Enter Master Password", bg=BG_COLOR, fg=FG_PURPLE, font=FONT).pack(pady=10)
        self.master_entry = tk.Entry(self.root, show="*", width=30, font=FONT, bg=BG_COLOR, fg=FG_GREEN, insertbackground=FG_GREEN)
        self.master_entry.pack(pady=10)
        tk.Button(self.root, text="Unlock Vault", command=self.unlock_vault, font=FONT, bg=FG_PURPLE, fg=BG_COLOR).pack(pady=10)

    def unlock_vault(self):
        master_password = self.master_entry.get()
        self.key = generate_key(master_password)
        self.vault = load_vault(self.key)

        if self.vault is not None:
            self.show_add_view()

    def show_add_view(self):
        self.clear_window()

        header_frame = tk.Frame(self.root, bg=BG_COLOR)
        header_frame.pack(fill="x")

        tk.Label(header_frame, text="Add New Password", bg=BG_COLOR, fg=FG_PURPLE, font=(FONT[0], 14, 'bold')).pack(side="left", padx=10, pady=10)

        tk.Button(header_frame, text="Stored Passwords", command=self.show_vault_view, font=(FONT[0], 10), bg=FG_PURPLE, fg=BG_COLOR).pack(side="right", padx=10, pady=10)

        self.service_entry = self.entry_with_label("Service")
        self.username_entry = self.entry_with_label("Username")
        self.password_entry = self.entry_with_label("Password", show="*")

        tk.Button(self.root, text="Save", command=self.save_password, font=FONT, bg=FG_GREEN, fg=BG_COLOR).pack(pady=15)

    def show_vault_view(self):
        self.clear_window()

        header_frame = tk.Frame(self.root, bg=BG_COLOR)
        header_frame.pack(fill="x")

        tk.Label(header_frame, text="Stored Passwords", bg=BG_COLOR, fg=FG_PURPLE, font=(FONT[0], 14, 'bold')).pack(side="left", padx=10, pady=10)

        tk.Button(header_frame, text="Back", command=self.show_add_view, font=(FONT[0], 10), bg=FG_PURPLE, fg=BG_COLOR).pack(side="right", padx=10, pady=10)

        self.output = tk.Text(self.root, height=15, width=60, bg=BG_COLOR, fg=FG_GREEN, font=FONT, insertbackground=FG_GREEN)
        self.output.pack(pady=10)

        tk.Button(self.root, text="Show Passwords" if not self.show_passwords else "Hide Passwords",
                  command=self.toggle_passwords, font=FONT, bg=FG_PURPLE, fg=BG_COLOR).pack(pady=10)

        self.display_passwords()

    def save_password(self):
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not service or not username or not password:
            messagebox.showwarning("Input Error", "Please fill all fields.")
            return

        self.vault[service] = {"username": username, "password": password}
        save_vault(self.vault, self.key)
        messagebox.showinfo("Saved", f"Password for {service} saved.")
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def display_passwords(self):
        self.output.delete("1.0", tk.END)
        if not self.vault:
            self.output.insert(tk.END, "Vault is empty.\n")
        else:
            for service, creds in self.vault.items():
                pwd = creds['password'] if self.show_passwords else '••••••'
                line = f"{service} → Username: {creds['username']}, Password: {pwd}\n"
                self.output.insert(tk.END, line)

    def toggle_passwords(self):
        self.show_passwords = not self.show_passwords
        self.show_vault_view()

    def entry_with_label(self, label, show=None):
        tk.Label(self.root, text=label, bg=BG_COLOR, fg=FG_PURPLE, font=FONT).pack()
        entry = tk.Entry(self.root, show=show, width=30, font=FONT, bg=BG_COLOR, fg=FG_GREEN, insertbackground=FG_GREEN)
        entry.pack(pady=3)
        return entry

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordKeeperApp(root)
    root.mainloop()
