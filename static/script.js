// --- AES ---
async function cifrarAES() {
    const passphrase = document.getElementById('passphrase_aes').value;
    const mensaje = document.getElementById('mensaje_aes').value;
    const response = await fetch('/cifrar_aes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase, mensaje })
    });
    const data = await response.json();
    document.getElementById('resultado_aes').textContent = 'Cifrado AES: ' + data.cifrado;
    document.getElementById('cifrado_aes_input').value = data.cifrado;
}

async function descifrarAES() {
    const passphrase = document.getElementById('passphrase_aes').value;
    const cifrado = document.getElementById('cifrado_aes_input').value;
    const response = await fetch('/descifrar_aes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase, cifrado })
    });
    const data = await response.json();
    document.getElementById('resultado_desc_aes').textContent = data.descifrado || data.error;
}

// --- RSA ---
async function generarRSA() {
    const passphrase = document.getElementById('passphrase_rsa').value;
    const response = await fetch('/generar_rsa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase })
    });
    const data = await response.json();
    document.getElementById('claves_rsa').textContent = 'Clave Privada:\n' + data.private_key + '\n\nClave Pública:\n' + data.public_key;
    // Almacena las claves para usar en cifrar/descifrar
    window.privateKey = data.private_key;
    window.publicKey = data.public_key;
}

async function cifrarRSA() {
    const mensaje = document.getElementById('mensaje_rsa').value;
    if (!window.publicKey) {
        alert('Genera las claves RSA primero.');
        return;
    }
    const response = await fetch('/cifrar_rsa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mensaje, public_key: window.publicKey })
    });
    const data = await response.json();
    document.getElementById('resultado_rsa').textContent = 'Cifrado RSA: ' + data.cifrado;
    document.getElementById('cifrado_rsa_input').value = data.cifrado;
}

async function descifrarRSA() {
    const cifrado = document.getElementById('cifrado_rsa_input').value;
    const passphrase = document.getElementById('passphrase_rsa').value;
    if (!window.privateKey) {
        alert('Genera las claves RSA primero.');
        return;
    }
    const response = await fetch('/descifrar_rsa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cifrado, private_key: window.privateKey, passphrase })
    });
    const data = await response.json();
    document.getElementById('resultado_desc_rsa').textContent = data.descifrado || data.error;
}