// main.js

function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64Content = btoa(binary);
    return `-----BEGIN PRIVATE KEY-----\n${base64Content.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
}

function u8ToBase64(u8) {
    let binary = "";
    const bytes = new Uint8Array(u8);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

async function generateGhostKey() {
    const rsaKeys = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKey = await crypto.subtle.exportKey("spki", rsaKeys.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", rsaKeys.privateKey);

    const aesKey = await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
    const rawAES = await crypto.subtle.exportKey("raw", aesKey);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const vaultMessage = new TextEncoder().encode("Welcome to GhostVault v1");
    const encryptedVault = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        vaultMessage
    ); 

    const encryptedAESKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKeys.publicKey,
        rawAES
    );
    
    let walletAddress = document.getElementById("walletAddress")?.value || "0xGHOSTWALLET123";

    const ghostVault = {
        ghost_signature: crypto.randomUUID(),
        fuse_timer: 180,
        ignite_on: "first_access",
        frozen_key_block: true,
        rsa_pub: u8ToBase64(publicKey),
        aes_key_enc: u8ToBase64(encryptedAESKey),
        vault_enc: u8ToBase64(encryptedVault),
        vault_iv: u8ToBase64(iv),
        allowed_until: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
        ghostfade_at: new Date(Date.now() + 3600 * 1000).toISOString(),
        owner_wallet: walletAddress
    };

    const vaultContent = JSON.stringify(ghostVault, null, 2);
    const privatePem = bufferToBase64(privateKey);

    // Store in localStorage for re-download
    localStorage.setItem("lastPrivateKeyContent", privatePem);
    localStorage.setItem("lastGhostVaultContent", vaultContent);

    // Download vault.json
    const vaultBlob = new Blob([vaultContent], { type: "application/json" });
    const vaultURL = URL.createObjectURL(vaultBlob);
    const vaultLink = document.createElement("a");
    vaultLink.href = vaultURL;
    vaultLink.download = "ghostvault_custom.json";
    vaultLink.click();
    URL.revokeObjectURL(vaultURL);

    // Download private key .pem
    const keyBlob = new Blob([privatePem], { type: "application/x-pem-file" });
    const keyURL = URL.createObjectURL(keyBlob);
    const keyLink = document.createElement("a");
    keyLink.href = keyURL;
    keyLink.download = "ghostkey_private.pem";
    keyLink.click();
    URL.revokeObjectURL(keyURL);

    document.getElementById("output").textContent = "✅ GhostVault and Private Key downloaded successfully.";
    alert("✅ GhostVault and Private Key downloaded.");
}

// EXPOSE FUNCTION GLOBALLY
window.generateGhostKey = generateGhostKey; 

// SET UP ALL OTHER BUTTON LISTENERS
window.onload = function() {
    // Connect Wallet Button
    const walletKeyBtn = document.getElementById("walleyKey");
    if (walletKeyBtn) {
        walletKeyBtn.onclick = () => {
            const mockAddress = "0xGHOST" + Math.random().toString(36).substring(2, 15).toUpperCase();
            const walletInput = document.getElementById("walletAddress");
            if (walletInput) {
                walletInput.value = mockAddress;
            }
            alert("✅ Simulated wallet connected: " + mockAddress);
        };
    }

    // Download Key Button - RE-DOWNLOADS BOTH FILES
    const downloadKeyBtn = document.getElementById("downloadKey");
    if (downloadKeyBtn) {
        downloadKeyBtn.onclick = () => {
            const keyContent = localStorage.getItem("lastPrivateKeyContent");
            const vaultContent = localStorage.getItem("lastGhostVaultContent");

            if (!keyContent || !vaultContent) {
                alert("❌ No key or vault has been generated yet. Please click 'Create GhostKey' first.");
                return;
            }

            // 1. Re-download PEM Key
            let keyBlob = new Blob([keyContent], { type: "application/x-pem-file" });
            let keyURL = URL.createObjectURL(keyBlob);
            let link = document.createElement("a");
            link.href = keyURL;
            link.download = "ghostkey_private.pem";
            link.click();
            URL.revokeObjectURL(keyURL);
            
            // 2. Re-download JSON Vault
            let vaultBlob = new Blob([vaultContent], { type: "application/json" });
            let vaultURL = URL.createObjectURL(vaultBlob);
            link = document.createElement("a");
            link.href = vaultURL;
            link.download = "ghostvault_custom.json";
            link.click();
            URL.revokeObjectURL(vaultURL);

            document.getElementById("output").textContent = "✅ GhostVault (.json) and Private Key (.pem) re-downloaded successfully.";
        };
    }
};
