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
function generarRSA() {
    const passphrase = document.getElementById('passphrase_rsa').value;
    if (!passphrase) { alert("Escribe tu passphrase"); return; }

    // 1) Convertir passphrase en bytes
    const md = forge.md.sha256.create();
    md.update(passphrase);
    const seed = md.digest().getBytes();

    // 2) Crear PRNG determinístico
    const prng = forge.random.createInstance();
    prng.seedFileSync = () => seed;

    // 3) Generar RSA determinístico
    const keypair = forge.pki.rsa.generateKeyPair({
        bits: 2048,
        e: 0x10001,
        prng: prng
    });

    const privatePem = forge.pki.privateKeyToPem(keypair.privateKey);
    const publicPem = forge.pki.publicKeyToPem(keypair.publicKey);

    // Mostrar en pantalla
    document.getElementById('claves_rsa').textContent =
        "Clave Privada:\n" + privatePem + "\n\nClave Pública:\n" + publicPem;

    // Guardar globalmente para cifrar/descifrar
    window.privateKey = keypair.privateKey;
    window.publicKey = keypair.publicKey;

    alert("Claves generadas correctamente.");
}