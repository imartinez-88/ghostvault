// main.js

async function generateGhostKey() {
    // Get pattern from user input
    const patternInput = document.getElementById("patternInput")?.value;
    if (!patternInput) {
        alert("❌ Please enter a pattern first!");
        return;
    }

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
    
    function u8ToBase64(u8) {
        let binary = "";
        const bytes = new Uint8Array(u8);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    // NEW: Hash the pattern
    async function hashPattern(pattern) {
        const encoder = new TextEncoder();
        const data = encoder.encode(pattern);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    const pattern_hash = await hashPattern(patternInput);
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
        pattern_hash: pattern_hash, // NEW: Store pattern hash
        ghostfade_at: new Date(Date.now() + 3600 * 1000).toISOString(),
        owner_wallet: walletAddress
    };

    // Download vault.json
    const vaultBlob = new Blob([JSON.stringify(ghostVault, null, 2)], { type: "application/json" });
    const vaultURL = URL.createObjectURL(vaultBlob);
    const vaultLink = document.createElement("a");
    vaultLink.href = vaultURL;
    vaultLink.download = "ghostvault_custom.json";
    vaultLink.click();
    URL.revokeObjectURL(vaultURL);

    // Download private key as .pem
    function bufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64Content = btoa(binary);
        return `-----BEGIN PRIVATE KEY-----\n${base64Content.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
    }

    const privatePem = bufferToBase64(privateKey);
    const keyBlob = new Blob([privatePem], { type: "text/plain" });
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
            const mockAddress = "0xGHOSTWALLET" + Math.random().toString(36).substring(7).toUpperCase();
            const walletInput = document.getElementById("walletAddress");
            if (walletInput) {
                walletInput.value = mockAddress;
            }
            alert("✅ Simulated wallet connected: " + mockAddress);
        };
    }
};
