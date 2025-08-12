# Vault Prototype 🔐
© This project and all associated ideas, design, and implementation are the sole intellectual property of Isaac Martinez (imartinez-88). Not affiliated with or licensed to any employer or contractor.

GhostVault is a browser-based secure access system built with multi-layered client-side authentication. It simulates key components of a modern zero-trust vault, including biometric WebAuthn, RSA key encryption, and AES-GCM file protection.

## 🔧 Features
- Pattern-based user unlock system
- Biometric authentication via WebAuthn
- RSA-OAEP key pair generation (4096-bit)
- AES-GCM 256-bit encryption
- Vault `.json` + private key `.pem` upload
- Fully client-side encryption & decryption flow

## ⚙️ Current Status
**Phase 1.A – Pattern & Biometric Auth: ✅**  
**Phase 1.B – Vault Decryption Skeleton: ✅**  
Full decryption output and vault UI refinement in progress.

## 🧠 Built With
- JavaScript (Web Crypto API)
- HTML/CSS UI
- WebAuthn
- AES-GCM & RSA-OAEP encryption

## 🚀 Next Steps
- Finalize vault decryption display
- UI error handling & user feedback
- Implement secure in-browser key caching

> 🔒 For demonstration/educational purposes only.
> git add README.md
git commit -m "Refine repository description and access notes"
git push
