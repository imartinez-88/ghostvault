// UnlockVault.js
let failedAttempts = 0;
const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 5 * 60 * 1000;
let firstAttemptTime = null;

async function tryUnlockVault(patternInput, vaultData) {
    // Lockout logic (Optional: you can move this back into the handler)
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
const vaultEncBase64 = vaultData.aes_key_enc; // Encrypted AES Key (RSA)
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
        
        // 1. Decrypt the raw AES key using the RSA Private Key
        const decryptedAESKey = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedAESKey
        );
        
        // 2. Import the decrypted raw AES key
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
        
        // Success: Store decrypted message
        const message = new TextDecoder().decode(decryptedVault);
        sessionStorage.setItem("decryptedVault", message);
        
        // 4. Pattern Lock Check (Used as a second factor now)
        if (patternInput !== "2-5-8-7") { 
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

async function performBiometricGate() {
  const storedId = localStorage.getItem("ghostCredentialId");
  if (!storedId) {
    alert("No biometric registered yet. Please register first.");
    return false;
  }

  const idBytes = Uint8Array.from(atob(storedId), c => c.charCodeAt(0));
  const publicKey = {
    challenge: new Uint8Array(32),
    allowCredentials: [{
      id: idBytes,
      type: "public-key",
      transports: ["internal"]
    }],
    userVerification: "required",
    timeout: 60000
  };

  try {
    await navigator.credentials.get({ publicKey });
    return true;
  } catch (e) {
    console.error("WebAuthn authentication failed:", e);
    return false;
  }
}

export async function handleUnlockClick() {
  const patternInput = document.getElementById("patternInput").value;
  const output = document.getElementById("output");
  const enterVaultBtn = document.getElementById("enterVaultBtn");

 const vaultText = sessionStorage.getItem("vaultFileContent")
 if (!vaultText) {
    output.textContent = " Vault data not loaded from session. Return to home page.";
    return;
}
  
let vaultData;
  try {
    vaultData = JSON.parse(vaultText);
  } catch (e) {
    output.textContent = " Failed to parse vault data. File corrupted.";
    return;
  }

const unlockedSuccessfully = await tryUnlockVault(patternInput, vaultData.vault_enc, vaultData.vault_iv, vaultData);
  
  if (!unlockedSuccessfully) {
        output.textContent = `❌ Decryption/Pattern Failed. Attempts remaining: ${MAX_ATTEMPTS - failedAttempts}`;
        return;
    }
// const biometricPassed = await performBiometricGate();
  // if (!biometricPassed) {
    //output.textContent = "Pattern Correct, but Biometric Authentication Failed.";
    //return;
  //}

const decryptedMessage = sessionStorage.getItem("decryptedVault"); 
  if (decryptedMessage) {
    output.textContent = " Two-Factor Access Granted. Decrypted Vault Message: \n\n" + decryptedMessage;
  } else {
    output.textContent = "Two-Factor Access Granted. Click 'Enter Vault Setup' to continue.";
  }
  enterVaultBtn.style.display = "inline-block";

  enterVaultBtn.onclick = () => {
    window.location.href = "vault.html";
  };
}

export async function handleRegisterClick() {
  const publicKey = {
    challenge: Uint8Array.from(window.crypto.getRandomValues(new Uint8Array(32))),
    rp: { name: "GhostVault" },
    user: {
      id: Uint8Array.from(window.crypto.getRandomValues(new Uint8Array(16))),
      name: "ghostuser@example.com",
      displayName: "Ghost User"
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 }
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required"
    },
    timeout: 60000,
    attestation: "none"
  };

  try {
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) {
      alert("No credential created.");
      return;
    }

    const rawId = new Uint8Array(credential.rawId);
    const base64Id = btoa(String.fromCharCode(...rawId));
    localStorage.setItem("ghostCredentialId", base64Id);
    alert("Biometric registered successfully.");
  } catch (err) {
    console.error("Registration error:", err);
    alert("Biometric registration failed: " + err.message);
  }
}
