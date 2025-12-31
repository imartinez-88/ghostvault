import { createAESKeyFromPattern } from './UnlockVault.js';

export async function generateVaultFile(pattern, walletAddress = "", notes = "Welcome to your encrypted vault") {
  try { 
    const encoder = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await createAESKeyFromPattern(pattern);
    const encodedNotes = encoder.encode(notes);
    
    const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encodedNotes
  );

    const vault_enc = arrayBuffertoBase64(encrypted);
    const vault_iv = arrayButterToBase64(iv);
    const pattern_hash = await hashPattern(pattern); // 

    const vaultTemplate = {
      notes: undefined, // Not used anymore, kept for structure
      owner_wallet: walletAddress,
      pattern_hash: pattern_hash,
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

  } catch (error) {
    console.error("Failed to egnerate vault file:", error);
    throw new Error('Vault generation Failed: ' + error/,message); 
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

async function hashPattern(pattern) {
  const encoder = new TextEncoder();
  const data = encoder.encode(pattern);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
