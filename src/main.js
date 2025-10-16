// main.js
function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    // We wrap the exported PKCS#8 key with PEM headers/footers for correct .pem file structure
    const base64Content = btoa(binary);
    return `-----BEGIN PRIVATE KEY-----\n${base64Content.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
}

// Existing helper function for going the other direction (U8 Array to Base64)
function u8ToBase64(u8) {
    let binary = "";
    const bytes = new Uint8Array(u8);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
// issue fix  for  HTML button that couldn't call the function.
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
    //  This placeholder message is what is retrieved upon successful unlock
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
    
    function u8ToBase64(u8) {
        let binary = "";
        const bytes = new Uint8Array(u8);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    let walletAddress = "0xGHOSTWALLET123";


    const ghostVault = {
        ghost_signature: crypto.randomUUID(),
        fuse_timer: 180,
        ignite_on: "first_access",
        frozen_key_block: true,
        rsa_pub: u8ToBase64(publicKey),
        aes_key_enc: u8ToBase64(encryptedAESKey),
        vault_enc: u8ToBase64(encryptedVault),
        vault_iv: u8ToBase64(iv),
        ghostfade_at: new Date(Date.now() + 3600 * 1000).toISOString(),
        owner_wallet: walletAddress
    };

    const vaultBlob = new Blob([JSON.stringify(ghostVault, null, 2)], { type: "application/json" });
    const vaultURL = URL.createObjectURL(vaultBlob);
    const vaultLink = document.createElement("a");
    vaultLink.href = vaultURL;
    vaultLink.download = "ghostvault_custom.json";
    vaultLink.click();
    URL.revokeObjectURL(vaultURL);

    localStorage.setItem("lastGhostVaultBlob", vaultURL);

    const keyBlob = new Blob([privateKey], { type: "application/octet-stream" });
    const keyURL = URL.createObjectURL(keyBlob);
    const keyLink = document.createElement("a");
    keyLink.href = keyURL;
    keyLink.download = "ghostkey_private.pem";
    keyLink.click();
    URL.revokeObjectURL(keyURL);

    localStorage.setItem("lastPrivateKeyBlob", keyURL);
    document.getElementById("output").textContent = "GhostVault and Private Key downloaded successfully.";
    alert("GhostVault and Private Key downloaded.");
}

// EXPOSE FUNCTION GLOBALLY
window.generateGhostKey = generateGhostKey; 

// SET UP ALL OTHER BUTTON LISTENERS AND UNLOCK LOGIC INSIDE WINDOW.ONLOAD
window.onload = function() {

    // Connect Wallet Button
    const walleyKeyBtn = document.getElementById("walleyKey");
    if (walleyKeyBtn) {
        walleyKeyBtn.onclick = () => {
            alert("Simulated wallet connected: 0xGHOSTWALLET123");
        };
    }
    // Download Key Button
    const downloadKeyBtn = document.getElementById("downloadKey");
    if (downloadKeyBtn) {
        downloadKeyBtn.onclick = () => {
            const keyContent = localStorage.getItem("lastPrivateKeyContent");
            const vaultContent = localStorage.getItem("lastGhostVaultContent"); // ✅ FIX 3: Get JSON content

            if (!keyContent || !vaultContent) { // ✅ Check if both are available
                alert("No key or vault has been generated yet. Please click 'Create GhostKey' first.");
                return;
            }
            // 1. Re-download PEM Key
            let keyBlob = new Blob([keyContent], { type: "application/x-pem-file" });
            let keyURL = URL.createObjectURL(keyBlob);
            let link = document.createElement("a");
            link.href = keyURL;
            link.download = "ghostkey_private.pem";
            link.click();
            URL.revokeObjectURL(keyURL); // Clean up temporary URL
            
            // 2. Re-download JSON Vault ✅
            let vaultBlob = new Blob([vaultContent], { type: "application/json" });
            let vaultURL = URL.createObjectURL(vaultBlob);
            link = document.createElement("a");
            link.href = vaultURL;
            link.download = "ghostvault_custom.json";
            link.click();
            URL.revokeObjectURL(vaultURL); // Clean up temporary URL

            document.getElementById("output").textContent = "GhostVault (.json) and Private Key (.pem) re-downloaded successfully.";
        };
    }
    
    // Check files on load logic from Index.html
    const vaultFileInput = document.getElementById("vaultFile");
    const privateKeyInput = document.getElementById("privateKeyFile");
};
