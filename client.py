import requests
import string
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def get_user_input():
    file_path = input("Enter the path of the file you want to upload: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    return file_path, username, password

def upload_file(file_path, username, password, server_url):
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Generate a random salt and derive encryption key from the password
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    cipher_suite = Fernet(key)

    # Encrypt the file data
    encrypted_data = cipher_suite.encrypt(file_data)

    response = requests.post(f"{server_url}/upload", data={'username': username, 'password': password}, files={'file': encrypted_data})
    print(response.text)

import os

if __name__ == "__main__":
    server_ip = input("Enter the server's IP address: ")
    server_port = int(input("Enter the server's port: "))
    server_url = f"http://{server_ip}:{server_port}"

    file_path, username, password = get_user_input()
    if not os.path.exists(file_path):
        print("File not found.")
    elif not username or not password:
        print("Username and password cannot be empty.")
    else:
        try:
            upload_file(file_path, username, password, server_url)
            print("File uploaded successfully.")
        except Exception as e:
            print(f"An error occurred: {e}")
