import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk 
from cryptography.fernet import Fernet

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryptor ")
        self.master.geometry("400x400")
        self.master.configure(bg="#2F4F4F") 

        self.key = None
        self.file_paths = []
        self.folder_path = None
        
        # Load and display logo
        self.load_logo()

        # Setup GUI elements
        self.setup_widgets()

    def load_logo(self):
        image_path = os.path.join(os.path.dirname(__file__), 'src', 'logo.png')
        logo_image = Image.open(image_path).resize((100, 100))
        self.logo_icon = ImageTk.PhotoImage(logo_image)
        self.master.iconphoto(True, self.logo_icon)

    def setup_widgets(self):
        tk.Label(self.master, image=self.logo_icon, bg="#2F4F4F").pack(pady=10)

        tk.Label(self.master, text="Select File or Folder:", bg="#2F4F4F", fg="white").pack(pady=10)
        
        self.path_label = tk.Label(self.master, text="", wraplength=300, justify="center", bg="#2F4F4F", fg="white")
        self.path_label.pack(pady=5)

        button_frame = tk.Frame(self.master, bg="#2F4F4F")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Browse File", command=self.browse_file).pack(side="left", padx=10)
        tk.Button(button_frame, text="Browse Folder", command=self.browse_folder).pack(side="right", padx=10)

        tk.Button(self.master, text="Encrypt", command=self.encrypt).pack(pady=10)
        tk.Button(self.master, text="Decrypt", command=self.decrypt).pack(pady=10)


    def browse_file(self):
        file_paths = filedialog.askopenfilenames()
        if file_paths:
            self.file_paths = file_paths
            self.folder_path = None
            self.path_label.config(text="\n".join(file_paths))

    def browse_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.folder_path = folder_path
            self.file_paths = []
            self.path_label.config(text=folder_path)

    def generate_or_load_key(self, is_generate=True):
        key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")]) if is_generate else filedialog.askopenfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
        
        if not key_file_path:
            tk.messagebox.showwarning("Key File Not Selected", "Key file not selected. Operation canceled.")
            return False
        
        self.key_file = key_file_path

        if os.path.exists(key_file_path):
            with open(key_file_path, "rb") as key_file:
                self.key = key_file.read()
        elif is_generate:
            self.key = Fernet.generate_key()
            with open(key_file_path, "wb") as key_file:
                key_file.write(self.key)
        else:
            tk.messagebox.showwarning("Key File Not Found", "Key file not found or couldn't be loaded.")
            return False
        
        return True

    def encrypt(self):
        if not self.file_paths and not self.folder_path:
            tk.messagebox.showwarning("No Selection", "Please select a file or folder to encrypt.")
            return
        
        if self.key is None and not self.generate_or_load_key(is_generate=True):
            return

        paths = self.file_paths or [self.folder_path]
        for path in paths:
            if os.path.isfile(path):
                self.encrypt_file(path)
            elif os.path.isdir(path):
                self.encrypt_folder(path)

        tk.messagebox.showinfo("Encryption Completed", "All files and folders have been encrypted.")

    def decrypt(self):
        if not self.file_paths and not self.folder_path:
            tk.messagebox.showwarning("No Selection", "Please select a file or folder to decrypt.")
            return
        
        if self.key is None and not self.generate_or_load_key(is_generate=False):
            return

        paths = self.file_paths or [self.folder_path]
        for path in paths:
            if os.path.isfile(path):
                self.decrypt_file(path)
            elif os.path.isdir(path):
                self.decrypt_folder(path)

        tk.messagebox.showinfo("Decryption Completed", "All files and folders have been decrypted.")

    def encrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                data = file.read()

            encrypted_filename = Fernet(self.key).encrypt(os.path.basename(file_path).encode()).decode()
            encrypted_file_path = os.path.join(os.path.dirname(file_path), encrypted_filename + ".encrypted")
            
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(Fernet(self.key).encrypt(data))

            os.remove(file_path)
        except Exception as e:
            print(f"Failed to encrypt {file_path}: {str(e)}")

    def decrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            decrypted_filename = Fernet(self.key).decrypt(os.path.basename(file_path)[:-10].encode()).decode()
            decrypted_file_path = os.path.join(os.path.dirname(file_path), decrypted_filename)

            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(Fernet(self.key).decrypt(encrypted_data))

            os.remove(file_path)
        except Exception as e:
            print(f"Failed to decrypt {file_path}: {str(e)}")

    def encrypt_folder(self, folder_path):
        encrypted_folder_name = Fernet(self.key).encrypt(os.path.basename(folder_path).encode()).decode()
        encrypted_folder_path = os.path.join(os.path.dirname(folder_path), encrypted_folder_name + ".encrypted")

        os.rename(folder_path, encrypted_folder_path)

        for root, _, files in os.walk(encrypted_folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.encrypt_file(file_path)

    def decrypt_folder(self, folder_path):
        decrypted_folder_name = Fernet(self.key).decrypt(os.path.basename(folder_path)[:-10].encode()).decode()
        decrypted_folder_path = os.path.join(os.path.dirname(folder_path), decrypted_folder_name)

        for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.decrypt_file(file_path)

        os.rename(folder_path, decrypted_folder_path)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
