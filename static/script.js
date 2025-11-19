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
    if (!passphrase) { alert("Escribe tu passphrase"); return; }

    const response = await fetch('/generar_rsa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase })
    });
    const data = await response.json();

    document.getElementById('claves_rsa').textContent =
        'Clave Privada:\n' + data.private_key + '\n\nClave Pública:\n' + data.public_key;

    // Guardamos para cifrar/descifrar automáticamente
    window.privateKey = data.private_key;
    window.publicKey = data.public_key;

    alert("Claves generadas correctamente. Ahora puedes cifrar un mensaje.");
}

// Cifrar y mostrar automáticamente en el input
async function cifrarYMostrar() {
    const mensaje = document.getElementById('mensaje_rsa').value;
    if (!window.publicKey) { alert("Genera las claves primero"); return; }
    if (!mensaje) { alert("Escribe un mensaje a cifrar"); return; }

    const response = await fetch('/cifrar_rsa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mensaje, public_key: window.publicKey })
    });
    const data = await response.json();

    document.getElementById('cifrado_rsa_input').value = data.cifrado;
    document.getElementById('resultado_desc_rsa').textContent = "";
}

// Descifrar y mostrar el resultado
async function descifrarYMostrar() {
    const cifrado = document.getElementById('cifrado_rsa_input').value;
    const passphrase = document.getElementById('passphrase_rsa').value;
    if (!window.privateKey) { alert("Genera las claves primero"); return; }
    if (!cifrado) { alert("No hay mensaje cifrado"); return; }

    const response = await fetch('/descifrar_rsa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cifrado, private_key: window.privateKey, passphrase })
    });
    const data = await response.json();

    document.getElementById('resultado_desc_rsa').textContent = data.descifrado || data.error;
}
