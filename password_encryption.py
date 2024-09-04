import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryptor")
        self.master.geometry("400x400")
        self.master.configure(bg="#2F4F4F") 

        self.salt = b'salt'
        self.iterations = 100000
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

        tk.Button(self.master, text="Browse", command=self.browse_file).pack(pady=10)

        tk.Button(self.master, text="Encrypt", command=self.encrypt).pack(pady=5)
        tk.Button(self.master, text="Decrypt", command=self.decrypt).pack(pady=5)

    def browse_file(self):
        file_paths = filedialog.askopenfilenames()
        if file_paths:
            self.path_label.config(text="\n".join(file_paths))
            self.file_paths = file_paths

    def encrypt(self):
        if self.file_paths:
            password = self.get_password()
            if password:
                for file_path in self.file_paths:
                    with open(file_path, 'rb') as file:
                        data = file.read()

                    key = self.derive_key(password)

                    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
                    encryptor = cipher.encryptor()
                    encrypted_data = encryptor.update(data) + encryptor.finalize()

                    encrypted_file_path = file_path + ".encrypted"
                    with open(encrypted_file_path, 'wb') as encrypted_file:
                        encrypted_file.write(encrypted_data)

                    os.remove(file_path)

                tk.messagebox.showinfo("Encryption Completed", "Encryption completed.")
            else:
                tk.messagebox.showwarning("Invalid Password", "Please enter a valid password.")

        else:
            tk.messagebox.showwarning("No File Selected", "Please select a file or folder to encrypt.")

    def decrypt(self):
        if self.file_paths:
            password = self.get_password()
            if password:
                for file_path in self.file_paths:
                    with open(file_path, 'rb') as encrypted_file:
                        encrypted_data = encrypted_file.read()

                    key = self.derive_key(password)

                    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

                    decrypted_file_path = file_path[:-10]  
                    with open(decrypted_file_path, 'wb') as decrypted_file:
                        decrypted_file.write(decrypted_data)

                    os.remove(file_path)  

                tk.messagebox.showinfo("Decryption Completed", "Decryption completed.")
            else:
                tk.messagebox.showwarning("Invalid Password", "Please enter a valid password.")

        else:
            tk.messagebox.showwarning("No File Selected", "Please select a file or folder to decrypt.")

    def get_password(self):
        password = tk.simpledialog.askstring("Password", "Enter password:")
        return password.encode('utf-8') if password else None

    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
