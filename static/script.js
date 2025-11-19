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

// Helper para descargar blobs
function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

// --- Upload / File AES ---
async function uploadCifrarAES() {
    const input = document.getElementById('file_aes');
    if (!input.files.length) { alert('Selecciona un archivo.'); return; }
    const file = input.files[0];
    const passphrase = document.getElementById('passphrase_file_aes').value || '';
    const fd = new FormData();
    fd.append('file', file);
    fd.append('passphrase', passphrase);
    sendFormDataWithProgress('/upload_cifrar_aes', fd, 'progress_file_aes', (blob) => {
        downloadBlob(blob, file.name + '.enc');
        document.getElementById('file_aes_status').textContent = 'Archivo cifrado descargado.';
    });
}

async function uploadDescifrarAES() {
    const input = document.getElementById('file_aes');
    if (!input.files.length) { alert('Selecciona un archivo cifrado (.enc).'); return; }
    const file = input.files[0];
    const passphrase = document.getElementById('passphrase_file_aes').value || '';
    const fd = new FormData();
    fd.append('file', file);
    fd.append('passphrase', passphrase);
    sendFormDataWithProgress('/upload_descifrar_aes', fd, 'progress_file_aes', (blob) => {
        let filename = file.name;
        if (filename.endsWith('.enc')) filename = filename.slice(0, -4);
        downloadBlob(blob, filename);
        document.getElementById('file_aes_status').textContent = 'Archivo descifrado descargado.';
    });
}

// --- Upload / File RSA Híbrido ---
async function uploadCifrarRSA() {
    const input = document.getElementById('file_rsa');
    if (!input.files.length) { alert('Selecciona un archivo.'); return; }
    const file = input.files[0];
    const pub = document.getElementById('public_key_input').value || '';
    const pubFileInput = document.getElementById('public_key_file');
    if (!pub.trim() && (!pubFileInput || !pubFileInput.files.length)) { alert('Pega la clave pública PEM o sube el archivo.'); return; }
    const fd = new FormData();
    fd.append('file', file);
    if (pub.trim()) fd.append('public_key', pub);
    else fd.append('public_key_file', pubFileInput.files[0]);
    sendFormDataWithProgress('/upload_cifrar_rsa', fd, 'progress_file_rsa', (blob) => {
        downloadBlob(blob, file.name + '.enc');
        document.getElementById('file_rsa_status').textContent = 'Archivo cifrado (RSA híbrido) descargado.';
    });
}

async function uploadDescifrarRSA() {
    const input = document.getElementById('file_rsa');
    if (!input.files.length) { alert('Selecciona un archivo cifrado (.enc).'); return; }
    const file = input.files[0];
    const priv = document.getElementById('private_key_input').value || '';
    const privFileInput = document.getElementById('private_key_file');
    const pass = document.getElementById('passphrase_private_rsa').value || '';
    if (!priv.trim() && (!privFileInput || !privFileInput.files.length)) { alert('Pega la clave privada PEM o sube el archivo.'); return; }
    const fd = new FormData();
    fd.append('file', file);
    if (priv.trim()) fd.append('private_key', priv);
    else fd.append('private_key_file', privFileInput.files[0]);
    fd.append('passphrase', pass);
    sendFormDataWithProgress('/upload_descifrar_rsa', fd, 'progress_file_rsa', (blob) => {
        let filename = file.name;
        if (filename.endsWith('.enc')) filename = filename.slice(0, -4);
        downloadBlob(blob, filename);
        document.getElementById('file_rsa_status').textContent = 'Archivo descifrado descargado.';
    });
}

// Envía FormData con XMLHttpRequest y actualiza progress element id; llama onSuccess(blob) al terminar
function sendFormDataWithProgress(url, formData, progressElementId, onSuccess) {
    const progressEl = document.getElementById(progressElementId);
    progressEl.value = 0;
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url);
    xhr.responseType = 'blob';
    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressEl.value = percent;
        }
    };
    xhr.onprogress = function(e) {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressEl.value = percent;
        }
    };
    xhr.onload = function() {
        if (xhr.status === 200) {
            progressEl.value = 100;
            onSuccess(xhr.response);
        } else {
            try {
                const reader = new FileReader();
                reader.onload = function() {
                    try {
                        const j = JSON.parse(reader.result);
                        alert(j.error || 'Error: ' + xhr.status);
                    } catch(e) {
                        alert('Error: ' + xhr.status + ' ' + xhr.statusText);
                    }
                };
                reader.readAsText(xhr.response);
            } catch(e) {
                alert('Error en la petición: ' + xhr.statusText);
            }
        }
    };
    xhr.onerror = function() { alert('Error de red durante la transferencia.'); };
    xhr.send(formData);
}