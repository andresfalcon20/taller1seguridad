const GPG_KEYS = {
    privateKey: localStorage.getItem('gpg_private_key_ascii'),
    publicKey: localStorage.getItem('gpg_public_key_ascii'),
    fingerprint: localStorage.getItem('gpg_fingerprint')
};

const keyStatusElement = document.getElementById('key_status');

function displayStatus(message, type, element) {
    element.textContent = message;
    element.className = 'mt-2 text-sm text-center font-semibold';
    if (type === 'success') {
        element.classList.add('text-green-600');
    } else if (type === 'error') {
        element.classList.add('text-red-600');
    } else {
        element.classList.add('text-gray-500');
    }
}

function updateKeyStatus() {
    if (GPG_KEYS.privateKey && GPG_KEYS.publicKey) {
        displayStatus("Claves GPG cargadas correctamente.", 'success', keyStatusElement);
    } else {
        displayStatus("Estado: Claves no generadas. Por favor, genera un par.", 'info', keyStatusElement);
    }
}

document.addEventListener('DOMContentLoaded', updateKeyStatus);

function downloadTextFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
}

async function generarGPGDescargar() {
    const passphrase = document.getElementById('passphrase_rsa').value;
    const nombre = document.getElementById('nombre').value || 'Usuario';
    const correo = document.getElementById('correo').value || 'usuario@example.com';
    if (!passphrase) {
        displayStatus("⚠️ Introduce una Passphrase.", 'error', keyStatusElement);
        return;
    }
    
    displayStatus("Generando claves GPG... (Puede tardar)", 'info', keyStatusElement);

    try {
        const response = await fetch('/generar_gpg', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passphrase: passphrase, name: nombre, email: correo })
        });

        const result = await response.json();

        if (response.ok) {
            GPG_KEYS.privateKey = result.private_key;
            GPG_KEYS.publicKey = result.public_key;
            GPG_KEYS.fingerprint = result.fingerprint;
            localStorage.setItem('gpg_private_key_ascii', result.private_key);
            localStorage.setItem('gpg_public_key_ascii', result.public_key);
            localStorage.setItem('gpg_fingerprint', result.fingerprint);
            
            // Solo descargar, sin mostrar en página
            downloadTextFile(result.private_key, 'private_key.asc');
            downloadTextFile(result.public_key, 'public_key.asc');
            
            displayStatus("✅ Claves generadas y descargadas", 'success', keyStatusElement);
        } else {
            displayStatus(`Error: ${result.error}`, 'error', keyStatusElement);
        }
    } catch (error) {
        displayStatus(`Error de conexión: ${error.message}`, 'error', keyStatusElement);
    }
}

// Funciones AES sin cambios...
async function uploadCifrarAES() {
    const fileInput = document.getElementById('file_aes');
    const passphrase = document.getElementById('passphrase_file_aes').value;
    const statusElement = document.getElementById('file_aes_status');
    const progressBar = document.getElementById('progress_file_aes');

    if (fileInput.files.length === 0 || !passphrase) {
        displayStatus("⚠️ Selecciona un archivo y proporciona una Passphrase.", 'error', statusElement);
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('passphrase', passphrase);

    displayStatus("Cifrando archivo... Espere.", 'info', statusElement);
    progressBar.value = 50;

    try {
        const response = await fetch('/upload_cifrar_aes', {
            method: 'POST',
            body: formData
        });

        progressBar.value = 100;
        
        if (response.ok) {
            const blob = await response.blob();
            // Intentar obtener el nombre del archivo del encabezado Content-Disposition si está disponible
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = fileInput.files[0].name + '.enc'; 
            if (contentDisposition && contentDisposition.indexOf('filename=') !== -1) {
                filename = contentDisposition.split('filename=')[1].replace(/"/g, '');
            }

            downloadFile(blob, filename);
            displayStatus(`✅ Archivo cifrado y descargado como: ${filename}`, 'success', statusElement);
        } else {
            const errorText = await response.json().then(data => data.error).catch(() => 'Error de servidor desconocido.');
            displayStatus(`Error de cifrado: ${errorText}`, 'error', statusElement);
        }
    } catch (error) {
        displayStatus(`Error de conexión: ${error.message}`, 'error', statusElement);
    } finally {
        progressBar.value = 0;
    }
}

async function uploadDescifrarAES() {
    const fileInput = document.getElementById('file_aes');
    const passphrase = document.getElementById('passphrase_file_aes').value;
    const statusElement = document.getElementById('file_aes_status');
    const progressBar = document.getElementById('progress_file_aes');

    if (fileInput.files.length === 0 || !passphrase) {
        displayStatus("⚠️ Selecciona el archivo cifrado y proporciona la Passphrase correcta.", 'error', statusElement);
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('passphrase', passphrase);

    displayStatus("Descifrando archivo... Espere.", 'info', statusElement);
    progressBar.value = 50;

    try {
        const response = await fetch('/upload_descifrar_aes', {
            method: 'POST',
            body: formData
        });
        
        progressBar.value = 100;

        if (response.ok) {
            const blob = await response.blob();
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = fileInput.files[0].name.replace('.enc', '');
            if (contentDisposition && contentDisposition.indexOf('filename=') !== -1) {
                filename = contentDisposition.split('filename=')[1].replace(/"/g, '');
            }

            downloadFile(blob, filename);
            displayStatus(`✅ Archivo descifrado y descargado como: ${filename}`, 'success', statusElement);
        } else {
            const errorText = await response.json().then(data => data.error).catch(() => 'Error de servidor desconocido.');
            displayStatus(`Error de descifrado: ${errorText}.`, 'error', statusElement);
        }
    } catch (error) {
        displayStatus(`Error de conexión: ${error.message}`, 'error', statusElement);
    } finally {
        progressBar.value = 0;
    }
}

function downloadFile(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
}