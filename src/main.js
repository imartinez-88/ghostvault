document.getElementById('createKey').onclick = async () => {
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
   for (let i = 0; i < u8.byteLength; i++) {
     binary += String.fromCharCode(u8[i]);
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

 const vaultBlob = new Blob([JSON.stringify(ghostVault)], { type: "application/json" });
 const vaultURL = URL.createObjectURL(vaultBlob);
 const vaultLink = document.createElement("a");
 vaultLink.href = vaultURL;
 vaultLink.download = "ghostvault_custom.json";
 vaultLink.click();
 URL.revokeObjectURL(vaultURL);


 const keyBlob = new Blob([privateKey], { type: "application/octet-stream" });
 const keyURL = URL.createObjectURL(keyBlob);
 const keyLink = document.createElement("a");
 keyLink.href = keyURL;
 keyLink.download = "ghostkey_private.pem";
 keyLink.click();
 URL.revokeObjectURL(keyURL);


 localStorage.setItem("lastPrivateKeyBlob", keyURL);
 alert("GhostVault and Private Key downloaded.");
};


document.getElementById("walleyKey").onclick = () => {
 alert("Simulated wallet connected: 0xGHOSTWALLET123");
};


document.getElementById("downloadKey").onclick = () => {
 const keyURL = localStorage.getItem("lastPrivateKeyBlob");
 if (!keyURL) {
   alert("No key generated yet.");
   return;
 }
 const link = document.createElement("a");
 link.href = keyURL;
 link.download = "ghostkey_private.pem";
 link.click();
};


// -------------------- UNLOCK PAGE (Biometric + Pattern Access) --------------------
if (
 window.location.pathname.includes("unlock.html") ||
 window.location.pathname.includes("index.html")
) {
 const MAX_ATTEMPTS = 3;
 let failedAttempts = 0;
 const unlockSalt = "ghostvault_salt_value";


 function hashPatternWithSalt(pattern, salt) {
   const combined = pattern + salt;
   const encoder = new TextEncoder();
   return crypto.subtle.digest("SHA-512", encoder.encode(combined));
 }


 async function createAESKeyFromPattern(pattern) {
   const rawHash = await hashPatternWithSalt(pattern, unlockSalt);
   return crypto.subtle.importKey(
     "raw",
     rawHash,
     { name: "AES-GCM" },
     false,
     ["encrypt", "decrypt"]
   );
 }


 async function tryUnlockVault(patternInput, vaultEnc, iv, vaultData) {
  const storedHash = atob(localStorage.getItem("ghostPatternHash") || "");
  const currentHash = await hashPatternWithSalt(patternInput, unlockSalt);
  const currentB64 = btoa(String.fromCharCode(...new Uint8Array(currentHash)));

  if (storedHash !== currentB64) {
    document.getElementById("output").textContent = "❌ Pattern doesn’t match registered user.";
    return;
  }

  const aesKey = await createAESKeyFromPattern(patternInput);

   try {
     const decrypted = await crypto.subtle.decrypt(
       { name: "AES-GCM", iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0)) },
       aesKey,
       Uint8Array.from(atob(vaultEnc), c => c.charCodeAt(0))
     );
     const message = new TextDecoder().decode(decrypted);
     document.getElementById("output").textContent = "Vault Unlocked:\n\n" + message;
     failedAttempts = 0;
   } catch (err) {
     failedAttempts++;
     if (failedAttempts >= MAX_ATTEMPTS) {
       document.getElementById("output").textContent = "Too many failed attempts. Vault self-erased.";
     } else {
       document.getElementById("output").textContent = `Incorrect pattern (${failedAttempts}/${MAX_ATTEMPTS})`;
     }
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


 window.onload = () => {
  const unlockBtn = document.getElementById("unlockBtn");
  if (unlockBtn) {
    unlockBtn.onclick = async () => {
      const biometricPassed = await performBiometricGate();
      if (!biometricPassed) {
        document.getElementById("output").textContent = "Biometric authentication failed.";
        return;
      }


      const vaultFile = document.getElementById("vaultFile").files[0];
      if (!vaultFile) {
        document.getElementById("output").textContent = "Please upload your GhostVault file.";
        return;
      }


      const vaultText = await vaultFile.text();
      const vaultData = JSON.parse(vaultText);
      const patternInput = document.getElementById("patternInput").value;

      tryUnlockVault(patternInput, vaultData.vault_enc, vaultData.vault_iv, vaultData);
     };
   }


   const registerBtn = document.getElementById("registerBio");
   if (registerBtn) {
     registerBtn.onclick = async () => {
       const publicKey = {
         challenge: Uint8Array.from(window.crypto.getRandomValues(new Uint8Array(32))),
         rp: {
           name: "GhostVault"},
         user: {
           id: Uint8Array.from(window.crypto.getRandomValues(new Uint8Array(16))),
           name: "ghostuser@example.com",
           displayName: "Ghost User"
         },
         pubKeyCredParams: [
           { type: "public-key", alg: -7 },   // ES256
           { type: "public-key", alg: -257 }  // RS256
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

         const pattern = document.getElementById("patternInput").value;
         const patternHash = await hashPatternWithSalt(pattern, unlockSalt);
         localStorage.setItem("ghostPatternHash", btoa(String.fromCharCode(...new Uint8Array(patternHash))));

         alert("Biometric registered. You can now unlock.");
       } catch (err) {
         console.error("Registration error:", err);
         alert("Biometric registration failed: " + err.message);
       }
     }
   };
 }
}
