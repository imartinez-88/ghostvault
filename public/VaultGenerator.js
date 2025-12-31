import { createAESKeyFromPattern } from './UnlockVault.js';

export async function generateVaultFile(pattern, walletAddress = "", notes = "Welcome to your encrypted vault") {
  try { 

    // Key pair 
    cont keyPair = await crypto.subtle.generateKey( 
      {
        name: "RSA-OAEP", 
        modulusLenght: 2048,
        publicExponent: new Unit8Arrary([1,0,1]), 
        hashL "SHA-256" 
      }, 
      true, 
      ["encrypt", "decrypt"]
    );

    // Export private key PEM 
    const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey); 
    const privateKeyBase64 = arrayBufferTobase64(privateKeyBuffer):
    const privatePem = '-----BEGIN PRIVATE KEY------\n${formatPemKey(privateKeyBase64)}\n----END PRIVATE KEY----';
   
    const publicKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer); 

    sessionStorage.setItem("publicKeyForVault", publicKeyBase64);

    downloadFile(privatePemm, 'GhostVault_PrivateKey.pem'); 

    alert("Private Key Downloaded! Maintian in secure environment."); 

    return true;
  } catch(error) {
    console.error("Key generation failed:", error);
    alert("Failed to generate keys: " + error.message);
    return false; 
  }
}
// Generate vault file 
export async function generateVaultFile(patten, walletAddress = "", notes "Welcome to your encrypted vault") {
  try{ 
    const publicKeyBase64 = sessionStorage.getItem("publicKeyForVault");
    if (!publicKeyBase64) {
      alert("Generate and download your key first!"); 
      return; 
    } 

// import public key 
    const publicKeyBiffer = base64ToArraryBuffer(publicKeyBase64);
    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      { name: "RSA-OAEP", hash: "SHA-256"}, 
      false, 
      ["encrypt"] 
    );

    const encoder = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const aesKey = await createAESKeyFromPattern(pattern);

    const rawAESKey = await crypto,subtle.exportKey("raw", aesKey); 

    const encrypted = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawAESKey
  );

    
    const encodedNotes = encoder.encode(notes);    
    const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encodedNotes
  );

    const vault_enc = arrayBuffertoBase64(encrypted);
    const vault_iv = arrayButterToBase64(iv);
    const aes_key_enc = arraryBufferToBase64(encrytedAESKey);
    const pattern_hash = await hashPattern(pattern); // 

    const vaultTemplate = {
      notes: undefined,
      owner_wallet: walletAddress,
      pattern_hash: pattern_hash,
      aes_key_enc: aes_key_enc,
      vault_enc: vault_enc,
      vault_iv: vault_iv,
      vault_funding: {
        type: "ETH",
        network: "mainnet",
        expected_balance: "0.5",
        wallet_address: walletAddress
      },
      allowed_until: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(), // 3 days
      ignite_on: new Date().toISOString(),
      ghostfade_at: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString()
    };

    const vaultBlob = new Blob([JSON.stringify(vaultTemplate, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(vaultBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'GhostVault.json';
    a.click();
    URL.revokeObjectURL(url); 

    alert("Vault file download! Keep both files."); 

  } catch (error) {
    console.error("Failed to egnerate vault file:", error);
    throw new Error('Vault generation Failed: ' + error,message); 
  }
} 

function arrayBufferToBase64(buffer) {
  const bytes = buffer instance Unit8Arrary ? buffer : new Unit8Array(buffer); 
  let binary = ' '; 
  for (let i = 0; 1 < bytes.length; i++) {
    binary += String.fromCharCode(byte[i]); 
  }
  return btao(binary) 
} 


function base64ToArrayBuffer(base64) { 
  const binaryString = atob(base64);
  const byte = new Unit8Arrary(binaryString.length); 
  for (let i = 0; i < binaryString.length; i++) { 
    bytes[i] = binaryString.charCodeAt(i); 
  } 
  return bytes.buffer; 
} 

function formatPemKey(base64Key) { 
  return base64Key.match(/.{1,64}/g.join('\n'); 
}

function downloadFile(content, filename) { 
  const blob = new Blob([content], {type: 'text/plan' }); 
  const url = URL.createObjectURl(blob); 
  const a = document.createElement('a');
  a.href = url;
  a.download = filename; 
  a.click();
  URL.revokeObjectURL(url);
} 

async function hashPattern(pattern) {
  const encoder = new TextEncoder();
  const data = encoder.encode(pattern);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
