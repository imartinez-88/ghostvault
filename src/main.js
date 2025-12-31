// main.js - Handles button clicks and file uploads

import { generateAndDownloadRSAKeys, generateVaultFile } from './VaultGenerator.js';
import { handleUnlockClick, handleRegisterClick, handleVaultFileUpload, handlePrivateKeyUpload } from './UnlockVault.js';

// ============================================
// WINDOW ONLOAD - SET UP ALL EVENT LISTENERS
// ============================================
window.onload = function() {
    
    // ==========================================
    // VAULT CREATION BUTTONS (index.html)
    // ==========================================
    
    // "Download Key" Button - Generates RSA keys
    const downloadKeyBtn = document.getElementById("downloadKeyBtn");
    if (downloadKeyBtn) {
        downloadKeyBtn.onclick = async () => {
            await generateAndDownloadRSAKeys();
        };
    }

    // "Create GhostKey (Encrypted)" Button - Creates vault file
    const createVaultBtn = document.getElementById("createVaultBtn");
    if (createVaultBtn) {
        createVaultBtn.onclick = async () => {
            const pattern = document.getElementById("patternInput")?.value || "2-5-8-7";
            const walletAddress = document.getElementById("walletAddress")?.value || "0x0000000000000000000000000000000000000000";
            const notes = document.getElementById("vaultNotes")?.value || "Welcome to your GhostVault";
            
            if (!pattern) {
                alert("❌ Please enter a pattern!");
                return;
            }
            
            await generateVaultFile(pattern, walletAddress, notes);
        };
    }

    // "Connect Wallet" Button - Simulated for now
    const connectWalletBtn = document.getElementById("connectWalletBtn");
    if (connectWalletBtn) {
        connectWalletBtn.onclick = async () => {
            // TODO: Add real Web3 wallet connection here
            const mockAddress = "0xGHOSTWALLET" + Math.random().toString(36).substring(7).toUpperCase();
            const walletAddressInput = document.getElementById("walletAddress");
            if (walletAddressInput) {
                walletAddressInput.value = mockAddress;
            }
            alert("✅ Wallet connected: " + mockAddress);
        };
    }

    // ==========================================
    // UNLOCK PAGE BUTTONS (unlock.html)
    // ==========================================
    
    // Vault File Upload
    const vaultFileInput = document.getElementById("vaultFile");
    if (vaultFileInput) {
        vaultFileInput.onchange = handleVaultFileUpload;
    }

    // Private Key File Upload
    const privateKeyInput = document.getElementById("privateKeyFile");
    if (privateKeyInput) {
        privateKeyInput.onchange = handlePrivateKeyUpload;
    }

    // "Enter Biometric + Pattern Access" Button
    const unlockBtn = document.getElementById("unlockBtn");
    if (unlockBtn) {
        unlockBtn.onclick = handleUnlockClick;
    }

    // Biometric Registration Button
    const registerBiometricBtn = document.getElementById("registerBiometricBtn");
    if (registerBiometricBtn) {
        registerBiometricBtn.onclick = handleRegisterClick;
    }

    // ==========================================
    // HELPER: Display uploaded file names
    // ==========================================
    
    if (vaultFileInput) {
        vaultFileInput.addEventListener('change', (e) => {
            const fileName = e.target.files[0]?.name || "No file chosen";
            console.log("📄 Vault file uploaded:", fileName);
        });
    }

    if (privateKeyInput) {
        privateKeyInput.addEventListener('change', (e) => {
            const fileName = e.target.files[0]?.name || "No file chosen";
            console.log("🔑 Private key uploaded:", fileName);
        });
    }
};

// ==========================================
// LEGACY FUNCTION (if you still need it)
// ==========================================

// Old generateGhostKey function - DEPRECATED, use generateAndDownloadRSAKeys() instead
async function generateGhostKey() {
    console.warn("⚠️ generateGhostKey() is deprecated. Use generateAndDownloadRSAKeys() instead.");
    
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

    const ghostVault = {
        ghost_signature: crypto.randomUUID(),
        fuse_timer: 180,
        ignite_on: "first_access",
        frozen_key_block: true,
        rsa_pub: arrayBufferToBase64(publicKey),
        aes_key_enc: arrayBufferToBase64(encryptedAESKey),
        vault_enc: arrayBufferToBase64(encryptedVault),
        vault_iv: arrayBufferToBase64(iv),
        ghostfade_at: new Date(Date.now() + 3600 * 1000).toISOString(),
        owner_wallet: "0xGHOSTWALLET123"
    };

    // Download vault
    const vaultBlob = new Blob([JSON.stringify(ghostVault, null, 2)], { type: "application/json" });
    const vaultURL = URL.createObjectURL(vaultBlob);
    const vaultLink = document.createElement("a");
    vaultLink.href = vaultURL;
    vaultLink.download = "ghostvault_custom.json";
    vaultLink.click();
    URL.revokeObjectURL(vaultURL);

    // Download private key as PEM
    const privatePem = bufferToBase64(privateKey);
    const keyBlob = new Blob([privatePem], { type: "text/plain" });
    const keyURL = URL.createObjectURL(keyBlob);
    const keyLink = document.createElement("a");
    keyLink.href = keyURL;
    keyLink.download = "ghostkey_private.pem";
    keyLink.click();
    URL.revokeObjectURL(keyURL);

    alert("✅ GhostVault and Private Key downloaded.");
}

// Helper functions
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64Content = btoa(binary);
    return `-----BEGIN PRIVATE KEY-----\n${base64Content.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
}

// Expose legacy function globally if needed
window.generateGhostKey = generateGhostKey;
