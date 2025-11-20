const RSA_KEYS = {
    privateKey: localStorage.getItem('rsa_private_key_pem'),
    publicKey: localStorage.getItem('rsa_public_key_pem')
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
    if (RSA_KEYS.privateKey && RSA_KEYS.publicKey) {
        displayStatus("Claves RSA cargadas correctamente.", 'success', keyStatusElement);
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

function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsText(file);
    });
}


async function generarRSADescargar() {
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
            RSA_KEYS.privateKey = result.private_key;
            RSA_KEYS.publicKey = result.public_key;
            localStorage.setItem('rsa_private_key_pem', result.private_key);
            localStorage.setItem('rsa_public_key_pem', result.public_key);
            
            downloadTextFile(result.private_key, 'private_key.pem');
            downloadTextFile(result.public_key, 'public_key.pem');
            
            displayStatus("✅ Claves RSA generadas, guardadas y descargadas.", 'success', keyStatusElement);
        } else {
            displayStatus(`Error: ${result.error || 'Fallo al generar claves.'}`, 'error', keyStatusElement);
        }
    } catch (error) {
        displayStatus(`Error de conexión: ${error.message}`, 'error', keyStatusElement);
    }
}


async function cifrarDatosRSA() {
    const nombre = document.getElementById('nombre').value;
    const correo = document.getElementById('correo').value;
    const clave = document.getElementById('clave').value;
    const frase = document.getElementById('frase').value;
    const publicKeyFile = document.getElementById('public_key_file').files[0];
    const resultado = document.getElementById('resultado_cifrar');
    
    if (!nombre || !correo || !clave || !frase) {
        resultado.textContent = "Error: Completa todos los campos de datos.";
        return;
    }
    if (!publicKeyFile) {
        resultado.textContent = "Error: Sube la clave pública.";
        return;
    }

    resultado.textContent = "Cifrando...";

    try {
        const publicKeyPem = await readFileAsText(publicKeyFile);
        const datos = JSON.stringify({ nombre, correo, clave, frase });

        const response = await fetch('/cifrar_datos_rsa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                datos: datos, 
                public_key: publicKeyPem 
            })
        });

        const result = await response.json();

        if (response.ok) {
            resultado.textContent = result.cifrado;
        } else {
            resultado.textContent = `Error de cifrado: ${result.error}`;
        }
    } catch (error) {
        resultado.textContent = `Error de conexión: ${error.message}`;
    }
}


async function descifrarDatosRSA() {
    const cifrado = document.getElementById('cifrado_input').value;
    const privateKeyPem = document.getElementById('private_key_text').value;
    const passphrase = document.getElementById('passphrase_desc').value;
    const resultado = document.getElementById('resultado_descifrar');

    if (!cifrado) {
        resultado.innerHTML = "Error: Pega los datos cifrados.";
        return;
    }
    if (!privateKeyPem) {
        resultado.innerHTML = "Error: Pega la clave privada.";
        return;
    }
    if (!passphrase) {
        resultado.innerHTML = "Error: Introduce la passphrase.";
        return;
    }

    resultado.innerHTML = "Descifrando...";

    try {
        const response = await fetch('/descifrar_datos_rsa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                cifrado: cifrado, 
                private_key: privateKeyPem,
                passphrase: passphrase
            })
        });

        const result = await response.json();

        if (response.ok) {
            const datos = result.datos;
            resultado.innerHTML = `
                <p><strong>Nombre:</strong> ${datos.nombre}</p>
                <p><strong>Correo:</strong> ${datos.correo}</p>
                <p><strong>Clave:</strong> ${datos.clave}</p>
                <p><strong>Frase:</strong> ${datos.frase}</p>
            `;
        } else {
            resultado.innerHTML = `Error de descifrado: ${result.error}`;
        }
    } catch (error) {
        resultado.innerHTML = `Error de conexión: ${error.message}`;
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