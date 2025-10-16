# GhostVault Prototype 
## Client-Side Zero-Trust Cryptographic Vault

© This project and all associated ideas, design, and implementation are the sole intellectual property of Isaac Martinez (imartinez-88). Not affiliated with or licensed to any employer or contractor.

This vault skeleton is a **browser-based secure access system** built with multi-layered client-side authentication, designed to demonstrate secure data handling for environments enabling high assurance for scaling dApp platfroms.

It simulates key components of a modern **zero-trust vault**, implementing cryptographic controls client-side to ensure the server never handles unencrypted data.

### Core Security Features
* **Zero-Trust Identity Flow:** Authentication is tied to multiple factors (Pattern, Biometric, Wallet Ownership).
* **Biometric Security (WebAuthn):** User-friendly, highly secure device-level authentication integrated into the access flow.
* **Cryptographic Primitives:** Implements robust standards:
    * **AES-GCM 256-bit** for file/content encryption (Data-at-Rest).
    * **SHA-256 Hashing** for secure pattern verification (no clear-text storage).
* **Data Structure:** Vault file (`.json`) and private key (`.pem`) are downloaded, enforcing user control and eliminating cloud-dependency for the primary secret.
* **Simulated Validation:** Includes **time-decay** (`allowed_until`) and **funding checks** (`vault_funding`) demonstrating dynamic access control policies.

---
### Technical Stack
* **Frontend:** JavaScript (Native), HTML/CSS (Vite build system)
* **Cryptography:** JavaScript **Web Crypto API** (AES-GCM, RSA-OAEP, SHA-256)
* **Authentication:** **WebAuthn** (Biometric), Pattern Hash
* **Wallet Integration:** Simulated **MetaMask/Ethereum** connectivity for ownership verification.

---
### Current Development Status

| Phase | Description | Status |
| :--- | :--- | :--- |
| **Phase 1.A** | Pattern & Biometric Registration and Access Flow | ** Complete** |
| **Phase 1.B** | Vault File Generation & Core AES Decryption Logic | ** Complete (Skeleton)** |
| **Phase 2** | **Foreign PKCS#12 Integration** with X.509 Certificate Signature (High-Assurance) | **In Progress** |
| **Phase 3** | Secure In-Browser Key Caching/Session Management | **Planned** |

---
### Next Steps
* Finalize vault decryption and secure display of arbitrary file types.
* Implement robust UI error handling and user feedback across all cryptographic steps.
* Replace simulated wallet checks with a clear mock-up function, or integrate a simple library (like Ethers.js) for true read-only connection.

> 🔒 **Disclaimer:** This project is for demonstration/educational purposes only and is not licensed for use in production environments.
> git add README.md
git commit -m "Refine repository description and access notes"
git push
