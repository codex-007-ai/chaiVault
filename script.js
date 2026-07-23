// =========================
// CHAI VAULT
// Future Image Capsule
// AES-GCM + PBKDF2
// =========================

const imageInput = document.getElementById("imageInput");
const vaultInput = document.getElementById("vaultInput");

const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");

const encryptStatus = document.getElementById("encryptStatus");
const decryptStatus = document.getElementById("decryptStatus");

const preview = document.getElementById("preview");

// =========================
// Helpers
// =========================

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

async function deriveKey(password, salt) {
    const encoder = new TextEncoder();

    const passwordKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 250000,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

// =========================
// Encrypt Image
// =========================

encryptBtn.addEventListener("click", async () => {

    try {

        const file = imageInput.files[0];
        const password =
            document.getElementById("encryptPassword").value.trim();

        const serial =
            document.getElementById("serial").value.trim() || "CHAI-VAULT";

        if (!file) {
            alert("Select an image first.");
            return;
        }

        if (!password) {
            alert("Enter a passphrase.");
            return;
        }

        encryptStatus.textContent = "Encrypting...";

        const imageBuffer = await file.arrayBuffer();

        const salt = crypto.getRandomValues(
            new Uint8Array(16)
        );

        const iv = crypto.getRandomValues(
            new Uint8Array(12)
        );

        const key = await deriveKey(password, salt);

        const encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            key,
            imageBuffer
        );

        const vault = {
            version: 1,
            serial,
            created: new Date().toISOString(),
            fileName: file.name,
            mimeType: file.type,
            salt: arrayBufferToBase64(salt),
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(encrypted)
        };

        const blob = new Blob(
            [JSON.stringify(vault, null, 2)],
            { type: "application/json" }
        );

        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");
        a.href = url;
        a.download = `${serial}.vault`;

        document.body.appendChild(a);
        a.click();
        a.remove();

        URL.revokeObjectURL(url);

        encryptStatus.textContent =
            "✅ Vault encrypted and downloaded.";

    } catch (err) {

        console.error(err);

        encryptStatus.textContent =
            "❌ Encryption failed.";

    }

});

// =========================
// Decrypt Vault
// =========================

decryptBtn.addEventListener("click", async () => {

    try {

        const vaultFile = vaultInput.files[0];

        const password =
            document.getElementById("decryptPassword").value.trim();

        if (!vaultFile) {
            alert("Select a .vault file.");
            return;
        }

        if (!password) {
            alert("Enter passphrase.");
            return;
        }

        decryptStatus.textContent = "Decrypting...";

        const text = await vaultFile.text();

        const vault = JSON.parse(text);

        const salt =
            new Uint8Array(
                base64ToArrayBuffer(vault.salt)
            );

        const iv =
            new Uint8Array(
                base64ToArrayBuffer(vault.iv)
            );

        const ciphertext =
            base64ToArrayBuffer(vault.ciphertext);

        const key =
            await deriveKey(password, salt);

        const decrypted =
            await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv
                },
                key,
                ciphertext
            );

        const imageBlob = new Blob(
            [decrypted],
            {
                type: vault.mimeType
            }
        );

        const imageUrl =
            URL.createObjectURL(imageBlob);

        preview.src = imageUrl;
        preview.style.display = "block";

        decryptStatus.textContent =
            `✅ Vault Opened (${vault.serial})`;

    } catch (err) {

        console.error(err);

        decryptStatus.textContent =
            "❌ Wrong passphrase or corrupted vault.";

    }

});
