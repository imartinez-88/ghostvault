// UnlockVault.js
let failedAttempts = 0;
const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 5 * 60 * 1000;
let firstAttemptTime = null;
const unlockSalt = "ghostvault_salt_value";

function hashPatternWithSalt(pattern, salt) {
  const combined = pattern + salt;
  const encoder = new TextEncoder();
  return crypto.subtle.digest("SHA-512", encoder.encode(combined));
}

async function createAESKeyFromPattern(pattern) {
  const rawHash = await hashPatternWithSalt(pattern, unlockSalt);
  const fullHash = new Uint8Array(rawHash);
  const aesKeyBytes = fullHash.slice(0, 32);  
  return crypto.subtle.importKey(
    "raw",
    aesKeyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
}

async function tryUnlockVault(patternInput, vaultEnc, iv, vaultData) {
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

const aesKey = await createAESKeyFromPattern(patternInput);
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0)) },
      aesKey,
      Uint8Array.from(atob(vaultEnc), c => c.charCodeAt(0))
    );
 const message = new TextDecoder().decode(decrypted);
    sessionStorage.setItem("decryptedVault", message);
    return true;
  } catch (err) {
    failedAttempts++;
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
    if (failedAttempts >= MAX_ATTEMPTS) {
      output.textContent = "Vault burned: too many failed attempts.";
    } else {
      output.textContent = `Pattern incorrect. Attempts remaining: ${MAX_ATTEMPTS - failedAttempts}`;
    }
    return;
  }
const biometricPassed = await performBiometricGate();
  if (!biometricPassed) {
    output.textContent = "Pattern Correct, but Biometric Authentication Failed.";
    return;
  }

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
