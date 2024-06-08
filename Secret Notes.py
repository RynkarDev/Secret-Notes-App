from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64

def generate_key(master_key):
    return base64.urlsafe_b64encode(master_key.ljust(32)[:32].encode())

def encrypt_message(master_key, message):
    key = generate_key(master_key)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(master_key, encrypted_message):
    key = generate_key(master_key)
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        messagebox.showerror("Error", "Invalid Master Key")
        return None

def save_note():
    title = title_entry.get()
    note = note_text.get("1.0", END).strip()
    master_key = master_key_entry.get()
    if not title or not master_key:
        messagebox.showerror("Error", "All fields are required!")
        return
    encrypted_note = encrypt_message(master_key, note)
    
    with open(f"{title}.txt", "wb") as file:
        file.write(f"Title:{title}\n".encode())
        file.write(encrypted_note)
        messagebox.showinfo("Success", "Note saved successfully!")

def load_note():
    title = title_entry.get()
    master_key = master_key_entry.get()
    if not title or not master_key:
        messagebox.showerror("Error", "Title and Master Key required!")
        return
    try:
        with open(f"{title}.txt", "rb") as file:
            lines = file.readlines()
            encrypted_note = b''.join(lines[1:]).strip()
            decrypted_note = decrypt_message(master_key, encrypted_note)
            if decrypted_note:
                note_text.delete("1.0", END)
                note_text.insert("1.0", decrypted_note)
                messagebox.showinfo("Success", "Note loaded successfully!")
    except FileNotFoundError:
        messagebox.showerror("Error", "Note not found")

window = Tk()
window.title("Secret Notes")
window.geometry("400x600")

Label(window, text="Enter your title").pack(pady=10)
title_entry = Entry(window, width=50)
title_entry.pack(pady=5)

Label(window, text="Note").pack(pady=10)
note_text = Text(window, width=50, height=20)
note_text.pack(pady=5)

Label(window, text="Enter masterkey").pack(pady=10)
master_key_entry = Entry(window, show="*", width=50)
master_key_entry.pack(pady=5)

save_and_encryption_button = Button(window, text="Save & Encrypt", command=save_note)
save_and_encryption_button.pack(pady=10)

load_button = Button(window, text="Load Note", command=load_note)
load_button.pack(pady=10)

window.mainloop()