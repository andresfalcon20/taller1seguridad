from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as sym_padding
from io import BytesIO
import os
import base64
from typing import cast

app = Flask(__name__)

# --- CIFRADO SIMÉTRICO (AES) para Archivos ---

def derivar_clave_simetrica(passphrase: str, salt: bytes) -> bytes:
    """Deriva una clave AES-256 de una passphrase usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits para AES-256
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode())

def cifrar_aes_bytes(data_bytes: bytes, passphrase: str) -> bytes:
    """Cifra bytes usando AES-256 en modo CBC. Retorna bytes: salt||iv||cifrado."""
    salt = os.urandom(16)
    clave = derivar_clave_simetrica(passphrase, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data_bytes) + padder.finalize()
    cifrado = encryptor.update(padded) + encryptor.finalize()
    return salt + iv + cifrado

def descifrar_aes_bytes(enc_data: bytes, passphrase: str) -> bytes:
    """Descifra bytes usando AES-256 en modo CBC. Asume formato: salt||iv||cifrado."""
    salt = enc_data[:16]
    iv = enc_data[16:32]
    cifrado_real = enc_data[32:]
    clave = derivar_clave_simetrica(passphrase, salt)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    descifrado_padded = decryptor.update(cifrado_real) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(descifrado_padded) + unpadder.finalize()

# --- CIFRADO ASIMÉTRICO (RSA) para Mensajes ---

def generar_claves_rsa(passphrase: str):
    """Genera un par de claves RSA (2048-bit). La privada se cifra con la passphrase."""
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
    """Cifra un mensaje usando clave pública RSA (OAEP/SHA256)."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    # Castear a RSA PublicKey para evitar advertencias de tipo
    public_key = cast(rsa.RSAPublicKey, public_key)
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
    """Descifra un mensaje usando clave privada RSA cifrada (OAEP/SHA256)."""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=passphrase.encode()
        )
        # Castear a RSA PrivateKey para la llamada a .decrypt()
        private_key = cast(rsa.RSAPrivateKey, private_key)
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

# --- RUTAS FLASK ---

@app.route('/')
def index():
    """Renderiza la plantilla principal."""
    return render_template('index.html')

# Rutas para RSA (Cifrado Asimétrico de Mensajes)
@app.route('/generar_rsa', methods=['POST'])
def generar_rsa_route():
    """Endpoint para generar claves RSA."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON inválido o faltante'}), 400
    passphrase = data.get('passphrase')
    if not passphrase:
        return jsonify({'error': 'Falta el campo "passphrase"'}), 400
    private_pem, public_pem = generar_claves_rsa(passphrase)
    return jsonify({'private_key': private_pem, 'public_key': public_pem})

@app.route('/cifrar_rsa', methods=['POST'])
def cifrar_rsa_route():
    """Endpoint para cifrar un mensaje con clave pública RSA."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON inválido o faltante'}), 400
    mensaje = data.get('mensaje')
    public_key = data.get('public_key')
    if not mensaje or not public_key:
        return jsonify({'error': 'Faltan campos: "mensaje" o "public_key"'}), 400
    try:
        cifrado = cifrar_rsa(mensaje, public_key)
        return jsonify({'cifrado': cifrado})
    except Exception as e:
        return jsonify({'error': f"Error en cifrado RSA: {str(e)}"}), 500

@app.route('/descifrar_rsa', methods=['POST'])
def descifrar_rsa_route():
    """Endpoint para descifrar un mensaje con clave privada RSA."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON inválido o faltante'}), 400
    cifrado = data.get('cifrado')
    private_key = data.get('private_key')
    passphrase = data.get('passphrase')
    if not cifrado or not private_key or passphrase is None:
        return jsonify({'error': 'Faltan campos: "cifrado", "private_key" o "passphrase"'}), 400

    descifrado = descifrar_rsa(cifrado, private_key, passphrase)
    if descifrado.startswith("Error"):
        return jsonify({'error': descifrado}), 400
    return jsonify({'descifrado': descifrado})

# Rutas para AES (Cifrado Simétrico de Archivos)
@app.route('/upload_cifrar_aes', methods=['POST'])
def upload_cifrar_aes_route():
    """Endpoint para cifrar un archivo con AES-256 y devolverlo para descarga."""
    # Espera multipart/form-data con 'file' y 'passphrase'
    if 'file' not in request.files:
        return jsonify({'error': 'Falta el archivo (field "file")'}), 400
    file = request.files['file']
    passphrase = request.form.get('passphrase')
    if not passphrase:
        return jsonify({'error': 'Falta el campo "passphrase"'}), 400
    
    data = file.read()
    try:
        enc = cifrar_aes_bytes(data, passphrase)
    except Exception as e:
        return jsonify({'error': f'Error cifrando: {str(e)}'}), 500
    
    # Devolver como attachment para descargar
    bio = BytesIO(enc)
    bio.seek(0)
    filename = (file.filename or 'file') + '.enc'
    return_bytes = bio.read()
    return (return_bytes, 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename="{filename}"'
    })


@app.route('/upload_descifrar_aes', methods=['POST'])
def upload_descifrar_aes_route():
    """Endpoint para descifrar un archivo con AES-256 y devolverlo para descarga."""
    if 'file' not in request.files:
        return jsonify({'error': 'Falta el archivo (field "file")'}), 400
    file = request.files['file']
    passphrase = request.form.get('passphrase')
    if not passphrase:
        return jsonify({'error': 'Falta el campo "passphrase"'}), 400
    
    enc = file.read()
    try:
        dec = descifrar_aes_bytes(enc, passphrase)
    except Exception as e:
        return jsonify({'error': f'Error descifrando: Contraseña incorrecta o archivo dañado. Detalle: {str(e)}'}), 400
        
    bio = BytesIO(dec)
    bio.seek(0)
    # intentar remover sufijo .enc
    filename = file.filename or 'file'
    if filename.endswith('.enc'):
        filename = filename[:-4]
    
    return (bio.read(), 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename="{filename}"'
    })


if __name__ == '__main__':
    # Usar puerto 5000 por defecto en debug mode
    app.run(debug=True)