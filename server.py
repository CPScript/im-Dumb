from flask import Flask, request, jsonify
import socket
import os
import random
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
file_storage = {}

def generate_random_string(length=16):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length))

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

if __name__ == '__main__':
    port = random.randint(5000, 10000)
    server_ip = socket.gethostbyname(socket.gethostname())
    server_url = f"http://{server_ip}:{port}"
    
    print(f"Server is running at {server_url}")

    app.run(host='0.0.0.0', port=port)

@app.route('/upload', methods=['POST'])
def upload_file():
    username = request.form.get('username')
    password = request.form.get('password')
    file = request.files['file']

    # Generate a random salt and encryption key from password
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    cipher_suite = Fernet(key)

    # Encrypt
    file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)

    # Store encrypted data
    file_storage[username] = {'encrypted_data': encrypted_data, 'salt': salt}
    return "File uploaded successfully."

@app.route('/get/<username>/<password>')
def get_file(username, password):
    if username in file_storage:
        stored_data = file_storage[username]
        salt = stored_data['salt']
        key = generate_key_from_password(password, salt)
        cipher_suite = Fernet(key)

        encrypted_data = stored_data['encrypted_data']
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return decrypted_data

    return "Invalid credentials or file not found."
