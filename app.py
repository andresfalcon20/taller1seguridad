from flask import Flask, request, jsonify, render_template, send_file
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from io import BytesIO
import os
import json
import gnupg  # Instala con: pip install python-gnupg

app = Flask(__name__)

# Configurar GPG (asegúrate de que GPG esté instalado en el sistema)
gpg = gnupg.GPG()

def derivar_clave_simetrica(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits para AES-256
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode())

def cifrar_aes_bytes(data_bytes: bytes, passphrase: str) -> bytes:
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generar_gpg', methods=['POST'])
def generar_gpg_route():
    data = request.get_json()
    passphrase = data.get('passphrase')
    name = data.get('name', 'Usuario')
    email = data.get('email', 'usuario@example.com')
    if not passphrase:
        return jsonify({'error': 'Falta passphrase'}), 400
    
    input_data = gpg.gen_key_input(
        key_type="RSA",
        key_length=2048,
        name_real=name,
        name_email=email,
        passphrase=passphrase
    )
    key = gpg.gen_key(input_data)
    fingerprint = key.fingerprint
    
    public_key = gpg.export_keys(fingerprint)
    private_key = gpg.export_keys(fingerprint, secret=True, passphrase=passphrase)
    
    return jsonify({
        'private_key': private_key,
        'public_key': public_key,
        'fingerprint': fingerprint
    })

@app.route('/cifrar_datos_gpg', methods=['POST'])
def cifrar_datos_gpg_route():
    data = request.get_json()
    datos = data.get('datos')
    public_key = data.get('public_key')
    fingerprint = data.get('fingerprint')
    if not datos or not public_key or not fingerprint:
        return jsonify({'error': 'Faltan datos'}), 400
    
    # Importar clave pública temporalmente
    gpg.import_keys(public_key)
    
    # Cifrar
    cifrado = gpg.encrypt(datos, fingerprint, always_trust=True)
    if not cifrado.ok:
        return jsonify({'error': cifrado.stderr}), 500
    
    return jsonify({'cifrado': str(cifrado)})

@app.route('/descifrar_datos_gpg', methods=['POST'])
def descifrar_datos_gpg_route():
    data = request.get_json()
    cifrado = data.get('cifrado')
    private_key = data.get('private_key')
    passphrase = data.get('passphrase')
    fingerprint = data.get('fingerprint')
    if not cifrado or not private_key or not passphrase or not fingerprint:
        return jsonify({'error': 'Faltan datos'}), 400
    
    # Importar clave privada temporalmente
    gpg.import_keys(private_key)
    
    # Descifrar
    descifrado = gpg.decrypt(cifrado, passphrase=passphrase)
    if not descifrado.ok:
        return jsonify({'error': descifrado.stderr}), 400
    
    return jsonify({'descifrado': str(descifrado)})

@app.route('/upload_cifrar_aes', methods=['POST'])
def upload_cifrar_aes_route():
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
    filename = file.filename or 'file'
    if filename.endswith('.enc'):
        filename = filename[:-4]
    
    return (bio.read(), 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename="{filename}"'
    })

if __name__ == '__main__':
    app.run(debug=True)