from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import padding as sym_padding
from io import BytesIO
import struct
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

def cifrar_aes(mensaje, passphrase: str) -> str:
    # mensaje puede ser str o bytes. Devuelve base64(salt||iv||cifrado)
    if isinstance(mensaje, str):
        mensaje_bytes = mensaje.encode()
    else:
        mensaje_bytes = mensaje
    salt = os.urandom(16)
    clave = derivar_clave_simetrica(passphrase, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(mensaje_bytes) + padder.finalize()
    cifrado = encryptor.update(padded) + encryptor.finalize()
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
        descifrado_padded = decryptor.update(cifrado_real) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        descifrado = unpadder.update(descifrado_padded) + unpadder.finalize()
        return descifrado.decode()
    except Exception as e:
        return f"Error: {str(e)}"

def cifrar_aes_bytes(data_bytes: bytes, passphrase: str) -> bytes:
    # Retorna bytes: salt||iv||cifrado
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
    salt = enc_data[:16]
    iv = enc_data[16:32]
    cifrado_real = enc_data[32:]
    clave = derivar_clave_simetrica(passphrase, salt)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    descifrado_padded = decryptor.update(cifrado_real) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(descifrado_padded) + unpadder.finalize()

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

# Generación determinista de claves (Ed25519) a partir de una frase
def derivar_semilla_desde_frase(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes para semilla Ed25519
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode())

def generar_claves_desde_frase(passphrase: str, salt: bytes = None):
    # Si no se pasa salt, generar uno aleatorio y devolverlo para reproducibilidad
    if salt is None:
        salt = os.urandom(16)
    seed = derivar_semilla_desde_frase(passphrase, salt)
    # Crear clave privada Ed25519 a partir de la semilla derivada
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()

    # Cifrar la clave privada PEM con la passphrase proporcionada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return salt, private_pem.decode(), public_pem.decode()

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

# Cifrado híbrido para archivos: AES para datos + RSA para clave
def cifrar_file_hibrido_rsa(file_bytes: bytes, public_key_pem: str) -> bytes:
    # Generar clave AES aleatoria
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(file_bytes) + padder.finalize()
    cifrado = encryptor.update(padded) + encryptor.finalize()

    # Cifrar la clave AES con RSA
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Empaquetar: 4 bytes len(encrypted_key) || encrypted_key || iv || cifrado
    packed = struct.pack('>I', len(encrypted_key)) + encrypted_key + iv + cifrado
    return packed

def descifrar_file_hibrido_rsa(packed_bytes: bytes, private_key_pem: str, passphrase: str) -> bytes:
    try:
        # Extraer longitud de la clave RSA cifrada
        key_len = struct.unpack('>I', packed_bytes[:4])[0]
        offset = 4
        encrypted_key = packed_bytes[offset:offset+key_len]
        offset += key_len
        iv = packed_bytes[offset:offset+16]
        offset += 16
        cifrado = packed_bytes[offset:]

        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=passphrase.encode())
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        descifrado_padded = decryptor.update(cifrado) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(descifrado_padded) + unpadder.finalize()
    except Exception as e:
        raise

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


@app.route('/generar_desde_frase', methods=['POST'])
def generar_desde_frase_route():
    data = request.json
    passphrase = data.get('passphrase')
    if not passphrase:
        return jsonify({'error': 'Falta el campo "passphrase"'}), 400
    salt_b64 = data.get('salt')
    try:
        if salt_b64:
            salt = base64.b64decode(salt_b64)
        else:
            salt = None
    except Exception:
        return jsonify({'error': 'Salt inválido: debe ser base64'}), 400

    salt, private_pem, public_pem = generar_claves_desde_frase(passphrase, salt)
    return jsonify({'salt': base64.b64encode(salt).decode(), 'private_key': private_pem, 'public_key': public_pem})


# Endpoints para subir/descargar archivos cifrados
@app.route('/upload_cifrar_aes', methods=['POST'])
def upload_cifrar_aes():
    # Espera multipart/form-data con 'file' y 'passphrase'
    if 'file' not in request.files:
        return jsonify({'error': 'Falta el archivo (field "file")'}), 400
    file = request.files['file']
    passphrase = request.form.get('passphrase')
    if not passphrase:
        return jsonify({'error': 'Falta el campo "passphrase"'}), 400
    data = file.read()
    enc = cifrar_aes_bytes(data, passphrase)
    # Devolver como attachment para descargar
    bio = BytesIO(enc)
    bio.seek(0)
    filename = file.filename + '.enc'
    return_bytes = bio.read()
    return (return_bytes, 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename="{filename}"'
    })


@app.route('/upload_descifrar_aes', methods=['POST'])
def upload_descifrar_aes():
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
        return jsonify({'error': f'Error descifrando: {str(e)}'}), 400
    bio = BytesIO(dec)
    bio.seek(0)
    # intentar remover sufijo .enc
    filename = file.filename
    if filename.endswith('.enc'):
        filename = filename[:-4]
    return (bio.read(), 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename="{filename}"'
    })


@app.route('/upload_cifrar_rsa', methods=['POST'])
def upload_cifrar_rsa():
    # Espera 'file' y 'public_key' (PEM)
    if 'file' not in request.files:
        return jsonify({'error': 'Falta el archivo (field "file")'}), 400
    file = request.files['file']
    # La clave pública puede venir en form 'public_key' (texto) o como archivo 'public_key_file'
    public_key = request.form.get('public_key')
    if not public_key and 'public_key_file' in request.files:
        public_key = request.files['public_key_file'].read().decode()
    if not public_key:
        return jsonify({'error': 'Falta el campo "public_key" (PEM) o archivo "public_key_file"'}), 400
    data = file.read()
    packed = cifrar_file_hibrido_rsa(data, public_key)
    bio = BytesIO(packed)
    bio.seek(0)
    filename = file.filename + '.enc'
    return (bio.read(), 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename="{filename}"'
    })


@app.route('/upload_descifrar_rsa', methods=['POST'])
def upload_descifrar_rsa():
    # Espera 'file' (el paquete) y 'private_key' y 'passphrase'
    if 'file' not in request.files:
        return jsonify({'error': 'Falta el archivo (field "file")'}), 400
    file = request.files['file']
    # La clave privada puede venir en form 'private_key' (texto) o como archivo 'private_key_file'
    private_key = request.form.get('private_key')
    if not private_key and 'private_key_file' in request.files:
        private_key = request.files['private_key_file'].read().decode()
    passphrase = request.form.get('passphrase')
    if not private_key or passphrase is None:
        return jsonify({'error': 'Faltan campos "private_key" (o archivo "private_key_file") o "passphrase"'}), 400
    packed = file.read()
    try:
        dec = descifrar_file_hibrido_rsa(packed, private_key, passphrase)
    except Exception as e:
        return jsonify({'error': f'Error descifrando: {str(e)}'}), 400
    bio = BytesIO(dec)
    bio.seek(0)
    filename = file.filename
    if filename.endswith('.enc'):
        filename = filename[:-4]
    return (bio.read(), 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename="{filename}"'
    })

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