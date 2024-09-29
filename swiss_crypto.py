import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Hash import SHA256, MD5, SHA1
from Crypto import Random
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Helper functions for encryption and decryption
def encrypt_aes(key, plaintext):
    key = key.ljust(32)[:32].encode()  # AES requires 16, 24, or 32 byte key
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(plaintext.encode())).decode()

def decrypt_aes(key, ciphertext):
    key = key.ljust(32)[:32].encode()
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(ciphertext[AES.block_size:]).decode()

def encrypt_des(key, plaintext):
    key = key.ljust(8)[:8].encode()  # DES requires 8 byte key
    iv = Random.new().read(DES.block_size)
    cipher = DES.new(key, DES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(plaintext.encode())).decode()

def decrypt_des(key, ciphertext):
    key = key.ljust(8)[:8].encode()
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CFB, iv)
    return cipher.decrypt(ciphertext[DES.block_size:]).decode()

def encrypt_arc4(key, plaintext):
    key = key.encode()
    cipher = ARC4.new(key)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

def decrypt_arc4(key, ciphertext):
    key = key.encode()
    cipher = ARC4.new(key)
    return cipher.decrypt(base64.b64decode(ciphertext)).decode()

# Hash functions
def hash_sha256(data):
    hash_obj = SHA256.new(data.encode())
    return hash_obj.hexdigest()

def hash_md5(data):
    hash_obj = MD5.new(data.encode())
    return hash_obj.hexdigest()

def hash_sha1(data):
    hash_obj = SHA1.new(data.encode())
    return hash_obj.hexdigest()

# Send secure email
def send_secure_email(sender, receiver, subject, message, password):
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = receiver
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
        messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {e}")

# Clear input fields
def clear_inputs():
    for widget in frame_encrypt.winfo_children():
        widget.pack_forget()

    for widget in frame_decrypt.winfo_children():
        widget.pack_forget()
        
    for widget in frame_hash.winfo_children():
        widget.pack_forget()

    for widget in frame_email.winfo_children():
        widget.pack_forget()

# GUI Setup
root = tk.Tk()
root.title("Swift Crypto")

# Main frame layout
main_frame = tk.Frame(root)
main_frame.pack(padx=10, pady=10, fill="both", expand=True)

# Separate frames for Encryption, Decryption, Hashing, and Email (Side by Side)
frame_encrypt = tk.LabelFrame(main_frame, text="Encryption", padx=10, pady=10)
frame_encrypt.grid(row=0, column=0, padx=5, pady=5)

frame_decrypt = tk.LabelFrame(main_frame, text="Decryption", padx=10, pady=10)
frame_decrypt.grid(row=0, column=1, padx=5, pady=5)

frame_hash = tk.LabelFrame(main_frame, text="Hash Functions", padx=10, pady=10)
frame_hash.grid(row=1, column=0, padx=5, pady=5)

frame_email = tk.LabelFrame(main_frame, text="Secure Email", padx=10, pady=10)
frame_email.grid(row=1, column=1, padx=5, pady=5)

cipher_type = tk.StringVar()
hash_type = tk.StringVar()

# Function to show inputs for encryption based on the cipher selected
def show_encrypt_inputs(*args):
    clear_inputs()
    if cipher_type.get() in ["AES", "DES", "ARC4"]:
        tk.Label(frame_encrypt, text="Key:").pack()
        entry_encrypt_key.pack()
        tk.Label(frame_encrypt, text="Plaintext:").pack()
        entry_encrypt_plaintext.pack()
        encrypt_button.pack()
        result_encrypt.pack()

# Function to show inputs for decryption based on the cipher selected
def show_decrypt_inputs(*args):
    clear_inputs()
    if cipher_type.get() in ["AES", "DES", "ARC4"]:
        tk.Label(frame_decrypt, text="Key:").pack()
        entry_decrypt_key.pack()
        tk.Label(frame_decrypt, text="Ciphertext:").pack()
        entry_decrypt_ciphertext.pack()
        decrypt_button.pack()
        result_decrypt.pack()

# Function to show inputs for hashing based on the hash type selected
def show_hash_inputs(*args):
    clear_inputs()
    if hash_type.get() in ["SHA-256", "MD5", "SHA-1"]:
        tk.Label(frame_hash, text="Data to Hash:").pack()
        entry_hash_data.pack()
        hash_button.pack()
        result_hash.pack()

# Encryption function
def encrypt():
    key = entry_encrypt_key.get()
    plaintext = entry_encrypt_plaintext.get()
    result = ""
    
    if cipher_type.get() == "AES":
        result = encrypt_aes(key, plaintext)
    elif cipher_type.get() == "DES":
        result = encrypt_des(key, plaintext)
    elif cipher_type.get() == "ARC4":
        result = encrypt_arc4(key, plaintext)

    result_encrypt.delete(1.0, tk.END)
    result_encrypt.insert(tk.END, result)

# Decryption function
def decrypt():
    key = entry_decrypt_key.get()
    ciphertext = entry_decrypt_ciphertext.get()
    result = ""
    
    if cipher_type.get() == "AES":
        result = decrypt_aes(key, ciphertext)
    elif cipher_type.get() == "DES":
        result = decrypt_des(key, ciphertext)
    elif cipher_type.get() == "ARC4":
        result = decrypt_arc4(key, ciphertext)

    result_decrypt.delete(1.0, tk.END)
    result_decrypt.insert(tk.END, result)

# Hashing function
def hash_data():
    data = entry_hash_data.get()
    result = ""
    
    if hash_type.get() == "SHA-256":
        result = hash_sha256(data)
    elif hash_type.get() == "MD5":
        result = hash_md5(data)
    elif hash_type.get() == "SHA-1":
        result = hash_sha1(data)

    result_hash.delete(1.0, tk.END)
    result_hash.insert(tk.END, result)

# Email sending function
def send_email():
    sender = entry_email_sender.get()
    receiver = entry_email_receiver.get()
    subject = entry_email_subject.get()
    message = entry_email_message.get("1.0", tk.END).strip()
    password = entry_email_password.get()
    
    send_secure_email(sender, receiver, subject, message, password)

# Widgets for encryption inputs
entry_encrypt_key = tk.Entry(frame_encrypt)
entry_encrypt_plaintext = tk.Entry(frame_encrypt)
encrypt_button = tk.Button(frame_encrypt, text="Encrypt", command=encrypt)
result_encrypt = tk.Text(frame_encrypt, height=4, width=50)

# Widgets for decryption inputs
entry_decrypt_key = tk.Entry(frame_decrypt)
entry_decrypt_ciphertext = tk.Entry(frame_decrypt)
decrypt_button = tk.Button(frame_decrypt, text="Decrypt", command=decrypt)
result_decrypt = tk.Text(frame_decrypt, height=4, width=50)

# Widgets for hash inputs
entry_hash_data = tk.Entry(frame_hash)
hash_button = tk.Button(frame_hash, text="Hash", command=hash_data)
result_hash = tk.Text(frame_hash, height=4, width=50)

# Widgets for secure email inputs
entry_email_sender = tk.Entry(frame_email)
entry_email_receiver = tk.Entry(frame_email)
entry_email_subject = tk.Entry(frame_email)
entry_email_password = tk.Entry(frame_email, show='*')
entry_email_message = tk.Text(frame_email, height=5, width=30)
send_email_button = tk.Button(frame_email, text="Send Email", command=send_email)

# Dropdown menu to select encryption/decryption type
cipher_menu_encrypt = tk.OptionMenu(frame_encrypt, cipher_type, "AES", "DES", "ARC4", command=show_encrypt_inputs)
cipher_type.set("Select Cipher for Encryption")
cipher_menu_encrypt.pack()

cipher_menu_decrypt = tk.OptionMenu(frame_decrypt, cipher_type, "AES", "DES", "ARC4", command=show_decrypt_inputs)
cipher_type.set("Select Cipher for Decryption")
cipher_menu_decrypt.pack()

# Dropdown menu to select hash type
hash_menu = tk.OptionMenu(frame_hash, hash_type, "SHA-256", "MD5", "SHA-1", command=show_hash_inputs)
hash_type.set("Select Hash Type")
hash_menu.pack()

# Email input fields
tk.Label(frame_email, text="Sender Email:").pack()
entry_email_sender.pack()
tk.Label(frame_email, text="Receiver Email:").pack()
entry_email_receiver.pack()
tk.Label(frame_email, text="Subject:").pack()
entry_email_subject.pack()
tk.Label(frame_email, text="Password:").pack()
entry_email_password.pack()
tk.Label(frame_email, text="Message:").pack()
entry_email_message.pack()
send_email_button.pack()

root.mainloop()
