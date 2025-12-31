// UnlockVault.js
let failedAttempts = 0;
const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 5 * 60 * 1000;
let firstAttemptTime = null;

async function hashPattern(pattern) {
    const encoder = new TextEncoder();
    const data = encoder.encode(pattern);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function tryUnlockVault(patternInput, vaultData) {
    const now = Date.now();
    if (!firstAttemptTime) firstAttemptTime = now;
    if (now - firstAttemptTime > LOCKOUT_DURATION) {
        failedAttempts = 0;
        firstAttemptTime = now;
    }
    if (failedAttempts >= MAX_ATTEMPTS) {
        document.getElementById("output").textContent = "💥 Vault burned: too many failed attempts.";
        return false;
    }
  
    const privateKeyText = sessionStorage.getItem("privateKeyContent");
    const vaultEncBase64 = vaultData.aes_key_enc;
    const ivBase64 = vaultData.vault_iv;
    const encryptedVaultBase64 = vaultData.vault_enc;

    let privateKey;
    try {
        const pemHeader = "-----BEGIN PRIVATE KEY-----";
        const pemFooter = "-----END PRIVATE KEY-----";
        const base64Key = privateKeyText
            .replace(pemHeader, '')
            .replace(pemFooter, '')
            .replace(/\s/g, '');
        const pkcs8 = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));

        privateKey = await crypto.subtle.importKey(
            "pkcs8",
            pkcs8,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );
    } catch (e) {
        document.getElementById("output").textContent = "❌ Error: Invalid or corrupt Private Key File (.pem).";
        console.error("Private Key Import Error:", e);
        return false;
    }
  
    try {
        const encryptedAESKey = Uint8Array.from(atob(vaultEncBase64), c => c.charCodeAt(0));
        
        const decryptedAESKey = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedAESKey
        );
        
        const aesKey = await crypto.subtle.importKey(
            "raw",
            decryptedAESKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
        const encryptedVault = Uint8Array.from(atob(encryptedVaultBase64), c => c.charCodeAt(0));

        const decryptedVault = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            aesKey,
            encryptedVault
        );
        
        const message = new TextDecoder().decode(decryptedVault);
        sessionStorage.setItem("decryptedVault", message);
        
        // FIXED: Verify pattern hash instead of hardcoded
        const inputPatternHash = await hashPattern(patternInput);
        if (inputPatternHash !== vaultData.pattern_hash) { 
            failedAttempts++;
            return false;
        }

        return true;
     
    } catch (err) {
        failedAttempts++;
        document.getElementById("output").textContent = "❌ Decryption Failed. Key/Vault mismatch.";
        console.error("Decryption Error:", err);
        return false;
    }
}

// REST OF YOUR OLD CODE STAYS THE SAME...
// (performBiometricGate, handleUnlockClick, handleRegisterClick)
