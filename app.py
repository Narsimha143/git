from flask import Flask, request, render_template
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(_name_)
backend = default_backend()
password = b"supersecretpassword"  # This should be securely managed

def get_key_and_nonce(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)
    nonce = os.urandom(12)
    return key, nonce, salt

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    text = request.form['text']
    key, nonce, salt = get_key_and_nonce(password)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
    encrypted_text = base64.b64encode(salt + nonce + ciphertext + encryptor.tag).decode()
    return render_template('index.html', encrypted_text=encrypted_text)
  @app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_text = request.form['encrypted_text']
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:-16]
        tag = encrypted_data[-16:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        key = kdf.derive(password)
     cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_text = decrypted_text.decode()
    except Exception as e:
        decrypted_text = f"Decryption failed: {str(e)}"
    return render_template('index.html', decrypted_text=decrypted_text)

if _name_ == '_main_':
    app.run(debug=True)
