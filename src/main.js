// main.js

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

    }

};
    
    
