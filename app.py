from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os
import base64

app = Flask(__name__)

# --- CIFRADO SIMÉTRICO (AES) ---
def derivar_clave_simetrica(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits para AES-256
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode())

def cifrar_aes(mensaje: str, passphrase: str) -> str:
    salt = os.urandom(16)
    clave = derivar_clave_simetrica(passphrase, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_mensaje = mensaje.encode() + b'\0' * (16 - len(mensaje.encode()) % 16)
    cifrado = encryptor.update(padded_mensaje) + encryptor.finalize()
    data = salt + iv + cifrado
    return base64.b64encode(data).decode()

def descifrar_aes(cifrado_b64: str, passphrase: str) -> str:
    try:
        data = base64.b64decode(cifrado_b64)
        salt = data[:16]
        iv = data[16:32]
        cifrado_real = data[32:]
        clave = derivar_clave_simetrica(passphrase, salt)
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
        decryptor = cipher.decryptor()
        descifrado = decryptor.update(cifrado_real) + decryptor.finalize()
        return descifrado.rstrip(b'\0').decode()
    except Exception as e:
        return f"Error: {str(e)}"

# --- CIFRADO ASIMÉTRICO (RSA) ---
def generar_claves_rsa(passphrase: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode(), public_pem.decode()

def cifrar_rsa(mensaje: str, public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    cifrado = public_key.encrypt(
        mensaje.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(cifrado).decode()

def descifrar_rsa(cifrado_b64: str, private_key_pem: str, passphrase: str) -> str:
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=passphrase.encode()
        )
        cifrado = base64.b64decode(cifrado_b64)
        descifrado = private_key.decrypt(
            cifrado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return descifrado.decode()
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

# Rutas para AES
@app.route('/cifrar_aes', methods=['POST'])
def cifrar_aes_route():
    data = request.json
    passphrase = data['passphrase']
    mensaje = data['mensaje']
    cifrado = cifrar_aes(mensaje, passphrase)
    return jsonify({'cifrado': cifrado})

@app.route('/descifrar_aes', methods=['POST'])
def descifrar_aes_route():
    data = request.json
    passphrase = data['passphrase']
    cifrado = data['cifrado']
    descifrado = descifrar_aes(cifrado, passphrase)
    if descifrado.startswith("Error"):
        return jsonify({'error': descifrado})
    return jsonify({'descifrado': descifrado})

# Rutas para RSA
@app.route('/generar_rsa', methods=['POST'])
def generar_rsa():
    data = request.json
    passphrase = data['passphrase']
    private_pem, public_pem = generar_claves_rsa(passphrase)
    return jsonify({'private_key': private_pem, 'public_key': public_pem})

@app.route('/cifrar_rsa', methods=['POST'])
def cifrar_rsa_route():
    data = request.json
    mensaje = data['mensaje']
    public_key = data['public_key']
    cifrado = cifrar_rsa(mensaje, public_key)
    return jsonify({'cifrado': cifrado})

@app.route('/descifrar_rsa', methods=['POST'])
def descifrar_rsa_route():
    data = request.json
    cifrado = data['cifrado']
    private_key = data['private_key']
    passphrase = data['passphrase']
    descifrado = descifrar_rsa(cifrado, private_key, passphrase)
    if descifrado.startswith("Error"):
        return jsonify({'error': descifrado})
    return jsonify({'descifrado': descifrado})

if __name__ == '__main__':
    app.run(debug=True)