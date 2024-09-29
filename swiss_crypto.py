import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from Crypto.Cipher import ARC4, DES, AES
import tkinter as tk
from tkinter import messagebox
import base64
import hashlib
import os

# Hashing Functions
def hash_md5(data):
    return hashlib.md5(data.encode()).hexdigest()

def hash_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

def hash_sha224(data):
    return hashlib.sha224(data.encode()).hexdigest()

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def hash_sha384(data):
    return hashlib.sha384(data.encode()).hexdigest()

def hash_sha512(data):
    return hashlib.sha512(data.encode()).hexdigest()

# Encryption and Decryption Functions
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data.encode())
    return base64.b64encode(encrypted_data).decode()

def aes_decrypt(encrypted_data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decoded_encrypted_data = base64.b64decode(encrypted_data)
    decrypted_data = cipher.decrypt(decoded_encrypted_data).decode().rstrip('{')
    return decrypted_data

def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = pad(data, 8)
    encrypted_data = cipher.encrypt(padded_data.encode())
    return base64.b64encode(encrypted_data).decode()

def des_decrypt(encrypted_data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decoded_encrypted_data = base64.b64decode(encrypted_data)
    decrypted_data = cipher.decrypt(decoded_encrypted_data).decode().rstrip('{')
    return decrypted_data

def arc4_encrypt(data, key):
    cipher = ARC4.new(key)
    encrypted_data = cipher.encrypt(data.encode())
    return base64.b64encode(encrypted_data).decode()

def arc4_decrypt(encrypted_data, key):
    cipher = ARC4.new(key)
    decoded_encrypted_data = base64.b64decode(encrypted_data)
    decrypted_data = cipher.decrypt(decoded_encrypted_data).decode()
    return decrypted_data

# Helper functions
def pad(data, block_size=32):
    padding = '{'
    return data + (block_size - len(data) % block_size) * padding

# Secure Email Function
def send_secure_email(sender_email, receiver_email, subject, message, password, encryption_key):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    encrypted_message = aes_encrypt(message, encryption_key)

    msg.attach(MIMEText(encrypted_message))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()

# GUI Functions
def perform_hashing():
    data = input_entry.get()
    hashed_value = hash_functions[hash_var.get()](data)
    result_label.config(text=f"Hashed Value: {hashed_value}")

def perform_encryption():
    data = input_entry.get()
    key = key_entry.get().ljust(32)[:32]
    encrypted_value = encryption_functions[enc_var.get()](data, key.encode())
    result_label.config(text=f"Encrypted Value: {encrypted_value}")

def perform_decryption():
    encrypted_data = input_entry.get()
    key = key_entry.get().ljust(32)[:32]
    decrypted_value = decryption_functions[enc_var.get()](encrypted_data, key.encode())
    result_label.config(text=f"Decrypted Value: {decrypted_value}")

def perform_secure_email():
    sender = sender_entry.get()
    receiver = receiver_entry.get()
    subject = subject_entry.get()
    message = input_entry.get()
    password = password_entry.get()
    encryption_key = key_entry.get().ljust(32)[:32]

    send_secure_email(sender, receiver, subject, message, password, encryption_key.encode())
    messagebox.showinfo("Success", "Secure Email Sent Successfully")

# GUI Setup
root = tk.Tk()
root.title("Swiss Crypto Tool")
root.geometry("500x600")

# Input fields
input_label = tk.Label(root, text="Input:")
input_label.pack()

input_entry = tk.Entry(root, width=50)
input_entry.pack()

key_label = tk.Label(root, text="Encryption Key (Optional):")
key_label.pack()

key_entry = tk.Entry(root, width=50)
key_entry.pack()

# Hashing
hash_var = tk.StringVar(value="MD5")
hash_label = tk.Label(root, text="Select Hashing Algorithm:")
hash_label.pack()

hash_algorithms = [("MD5", "MD5"), ("SHA1", "SHA1"), ("SHA224", "SHA224"), ("SHA256", "SHA256"),
                   ("SHA384", "SHA384"), ("SHA512", "SHA512")]

for text, mode in hash_algorithms:
    tk.Radiobutton(root, text=text, variable=hash_var, value=mode).pack()

hash_button = tk.Button(root, text="Hash", command=perform_hashing)
hash_button.pack()

# Encryption/Decryption
enc_var = tk.StringVar(value="AES")
enc_label = tk.Label(root, text="Select Encryption Algorithm:")
enc_label.pack()

encryption_algorithms = [("AES", "AES"), ("DES", "DES"), ("ARC4", "ARC4")]
for text, mode in encryption_algorithms:
    tk.Radiobutton(root, text=text, variable=enc_var, value=mode).pack()

enc_button = tk.Button(root, text="Encrypt", command=perform_encryption)
enc_button.pack()

dec_button = tk.Button(root, text="Decrypt", command=perform_decryption)
dec_button.pack()

# Secure Email
sender_label = tk.Label(root, text="Sender Email:")
sender_label.pack()

sender_entry = tk.Entry(root, width=50)
sender_entry.pack()

receiver_label = tk.Label(root, text="Receiver Email:")
receiver_label.pack()

receiver_entry = tk.Entry(root, width=50)
receiver_entry.pack()

subject_label = tk.Label(root, text="Subject:")
subject_label.pack()

subject_entry = tk.Entry(root, width=50)
subject_entry.pack()

password_label = tk.Label(root, text="Password:")
password_label.pack()

password_entry = tk.Entry(root, show="*", width=50)
password_entry.pack()

email_button = tk.Button(root, text="Send Secure Email", command=perform_secure_email)
email_button.pack()

# Output
result_label = tk.Label(root, text="")
result_label.pack()

# Mapping algorithms to functions
hash_functions = {
    "MD5": hash_md5,
    "SHA1": hash_sha1,
    "SHA224": hash_sha224,
    "SHA256": hash_sha256,
    "SHA384": hash_sha384,
    "SHA512": hash_sha512
}

encryption_functions = {
    "AES": aes_encrypt,
    "DES": des_encrypt,
    "ARC4": arc4_encrypt
}

decryption_functions = {
    "AES": aes_decrypt,
    "DES": des_decrypt,
    "ARC4": arc4_decrypt
}

# Main loop
root.mainloop()
