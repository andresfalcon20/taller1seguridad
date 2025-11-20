// Almacenamiento local para claves RSA generadas (solo para propósitos de prueba)
const RSA_KEYS = {
    privateKey: localStorage.getItem('rsa_private_key_pem'),
    publicKey: localStorage.getItem('rsa_public_key_pem')
};

// Referencias a elementos comunes
const keyStatusElement = document.getElementById('key_status');

/**
 * Muestra un mensaje de estado en la interfaz.
 * @param {string} message - El mensaje a mostrar.
 * @param {string} type - El tipo de mensaje ('success', 'error', 'info').
 * @param {HTMLElement} element - El elemento donde mostrar el mensaje.
 */
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

/**
 * Actualiza el estado de las claves RSA en la interfaz.
 */
function updateKeyStatus() {
    if (RSA_KEYS.privateKey && RSA_KEYS.publicKey) {
        displayStatus("Claves RSA cargadas correctamente.", 'success', keyStatusElement);
    } else {
        displayStatus("Estado: Claves no generadas. Por favor, genera un par.", 'info', keyStatusElement);
    }
}

// Inicializar el estado de las claves al cargar la página
document.addEventListener('DOMContentLoaded', updateKeyStatus);


/**
 * Genera un par de claves RSA llamando al backend de Flask.
 */
async function generarRSA() {
    const passphrase = document.getElementById('passphrase_rsa').value;
    if (!passphrase) {
        displayStatus("⚠️ Introduce una Passphrase para proteger tu clave privada.", 'error', keyStatusElement);
        return;
    }
    
    displayStatus("Generando claves... (Puede tardar unos segundos)", 'info', keyStatusElement);

    try {
        const response = await fetch('/generar_rsa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passphrase: passphrase })
        });

        const result = await response.json();

        if (response.ok) {
            // Guardar claves en la variable local y localStorage
            RSA_KEYS.privateKey = result.private_key;
            RSA_KEYS.publicKey = result.public_key;
            localStorage.setItem('rsa_private_key_pem', result.private_key);
            localStorage.setItem('rsa_public_key_pem', result.public_key);
            
            displayStatus("✅ Claves RSA generadas y guardadas en localStorage.", 'success', keyStatusElement);

            // Opcional: Mostrar la clave pública para que el usuario la use
            // console.log("Clave Pública:", result.public_key); 
            // Podrías poner la clave pública en un textarea si fuera necesario compartirla inmediatamente.

        } else {
            displayStatus(`Error: ${result.error || 'Fallo al generar claves.'}`, 'error', keyStatusElement);
        }
    } catch (error) {
        displayStatus(`Error de conexión: ${error.message}`, 'error', keyStatusElement);
    }
}


/**
 * Cifra un mensaje usando la clave pública RSA.
 */
async function cifrarRSA() {
    const mensaje = document.getElementById('mensaje_rsa').value;
    const resultado = document.getElementById('resultado_rsa');
    
    if (!RSA_KEYS.publicKey) {
        resultado.value = "Error: Primero debes generar las claves RSA.";
        return;
    }
    if (!mensaje) {
        resultado.value = "Error: Introduce un mensaje a cifrar.";
        return;
    }

    resultado.value = "Cifrando...";

    try {
        const response = await fetch('/cifrar_rsa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                mensaje: mensaje, 
                public_key: RSA_KEYS.publicKey 
            })
        });

        const result = await response.json();

        if (response.ok) {
            resultado.value = result.cifrado;
        } else {
            resultado.value = `Error de cifrado: ${result.error}`;
        }
    } catch (error) {
        resultado.value = `Error de conexión: ${error.message}`;
    }
}

/**
 * Descifra un mensaje usando la clave privada RSA.
 */
async function descifrarRSA() {
    const cifrado = document.getElementById('cifrado_rsa_input').value;
    const passphrase = document.getElementById('passphrase_rsa').value;
    const resultado = document.getElementById('resultado_desc_rsa');

    if (!RSA_KEYS.privateKey) {
        resultado.value = "Error: Primero debes generar las claves RSA.";
        return;
    }
    if (!cifrado || !passphrase) {
        resultado.value = "Error: Asegúrate de introducir el mensaje cifrado y la Passphrase.";
        return;
    }

    resultado.value = "Descifrando...";

    try {
        const response = await fetch('/descifrar_rsa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                cifrado: cifrado, 
                private_key: RSA_KEYS.privateKey,
                passphrase: passphrase
            })
        });

        const result = await response.json();

        if (response.ok) {
            resultado.value = result.descifrado;
        } else {
            resultado.value = `Error de descifrado: ${result.error}`;
        }
    } catch (error) {
        resultado.value = `Error de conexión: ${error.message}`;
    }
}


// --- Funciones para Cifrado/Descifrado AES de Archivos ---

/**
 * Maneja la descarga de un blob/archivo.
 * @param {Blob} blob - El contenido del archivo.
 * @param {string} filename - El nombre para el archivo descargado.
 */
function downloadFile(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
}


/**
 * Sube un archivo para cifrarlo con AES y desencadena la descarga del archivo cifrado.
 */
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

/**
 * Sube un archivo cifrado para descifrarlo con AES y desencadena la descarga del archivo original.
 */
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