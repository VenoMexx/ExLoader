# Crypto Hooks

ExLoader captures cryptographic operations with full context including keys, IVs, and plaintext/ciphertext.

## Supported Modules

### BCrypt (`crypto.bcrypt`)

Modern Windows Cryptography API (CNG - Cryptography Next Generation).

**Hooked APIs:**

**Algorithm Providers:**
- `BCryptOpenAlgorithmProvider`
- `BCryptCloseAlgorithmProvider`
- `BCryptGetProperty`, `BCryptSetProperty`

**Key Management:**
- `BCryptGenerateSymmetricKey`
- `BCryptImportKey`, `BCryptExportKey`
- `BCryptDestroyKey`

**Encryption/Decryption:**
- `BCryptEncrypt`
- `BCryptDecrypt`

**Hashing:**
- `BCryptCreateHash`, `BCryptDestroyHash`
- `BCryptHashData`
- `BCryptFinishHash`

**Event Types:**
- `crypto.key.generate` - Key generation
- `crypto.encrypt` - Encryption operation
- `crypto.decrypt` - Decryption operation
- `crypto.hash.update` - Hash data added
- `crypto.hash.digest` - Hash finalization

**Sample Events:**

**AES Encryption:**
```json
{
  "ts": "2025-11-09T18:36:22.675Z",
  "type": "crypto.encrypt",
  "api": "BCryptEncrypt",
  "algorithm": "AES",
  "mode": "CBC",
  "key_handle": 12345678,
  "iv_hex": "000102030405060708090a0b0c0d0e0f",
  "plaintext_len": 128,
  "ciphertext_len": 144,
  "plaintext_hex": "7b22757365726e616d65223a...",
  "ciphertext_hex": "8f3a91c4d7e2b5f9...",
  "caller": {
    "module": "test_target.exe",
    "offset": 46250
  }
}
```

**SHA-256 Hash:**
```json
{
  "type": "crypto.hash.digest",
  "api": "BCryptFinishHash",
  "algorithm": "SHA256",
  "hash_hex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "hash_len": 32
}
```

### CryptoAPI (`crypto.cryptapi`)

Legacy Windows cryptographic API (still widely used).

**Hooked APIs:**

**Context Management:**
- `CryptAcquireContextA/W`
- `CryptReleaseContext`

**Key Management:**
- `CryptGenKey`
- `CryptDeriveKey`
- `CryptImportKey`, `CryptExportKey`
- `CryptDestroyKey`

**Encryption/Decryption:**
- `CryptEncrypt`
- `CryptDecrypt`

**Hashing:**
- `CryptCreateHash`, `CryptDestroyHash`
- `CryptHashData`
- `CryptGetHashParam`

**Sample Events:**

**MD5 Hash:**
```json
{
  "type": "crypto.hash.digest",
  "api": "CryptGetHashParam",
  "hash": {
    "algorithm": "MD5",
    "provider": "PROV_RSA_FULL"
  },
  "hash_handle": 17689720,
  "payload_hex": "58145d6f0269c3c4ac13611b9d30d68e",
  "caller": {
    "module": "test_target.exe",
    "offset": 48123
  }
}
```

**AES-256 Encryption (CryptoAPI):**
```json
{
  "type": "crypto.encrypt",
  "api": "CryptEncrypt",
  "algorithm": "AES-256",
  "key_handle": 89012345,
  "data_len_in": 100,
  "data_len_out": 112,
  "final": true,
  "success": true
}
```

## Supported Algorithms

### Symmetric Encryption
- **AES** (128, 192, 256-bit)
- **DES**, **3DES**
- **RC2**, **RC4**

### Hash Functions
- **MD5**
- **SHA-1**, **SHA-256**, **SHA-384**, **SHA-512**

### Key Derivation
- **PBKDF2**
- **HKDF**

## Configuration

Enable crypto modules:

```json
{
  "modules": [
    "crypto.bcrypt",
    "crypto.cryptapi"
  ]
}
```

### Payload Capture

Control how much plaintext/ciphertext to log:

```json
{
  "logging": {
    "max_bytes_per_entry": 131072
  }
}
```

**Security Warning:** Crypto logs contain sensitive data (keys, plaintexts, IVs). Handle logs securely!

## Analysis Patterns

### Detecting Encryption

Look for key generation followed by encrypt operations:

```bash
# Find key generation
jq 'select(.type=="crypto.key.generate")' logs/output.jsonl

# Find corresponding encryptions
jq 'select(.type=="crypto.encrypt" and .key_handle==12345678)' logs/output.jsonl
```

### Password Hashing

Sequential cipher + hash indicates password derivation:

```bash
# Find hash operations
jq 'select(.type=="crypto.hash.digest")' logs/output.jsonl
```

### Extracting Keys

```bash
# Extract AES keys (WARNING: sensitive!)
jq -r 'select(.api=="BCryptGenerateSymmetricKey") | .key_hex' logs/output.jsonl
```

## Real-World Examples

### Test Target - Stage 1 (Network Auth)

1. **Generate AES-256 key:**
   ```json
   {"api":"BCryptGenerateSymmetricKey","algorithm":"AES"}
   ```

2. **Encrypt credentials:**
   ```json
   {
     "api":"BCryptEncrypt",
     "plaintext_hex":"7b22757365726e616d65223a2261646d696e222c...",
     "ciphertext_hex":"8f3a91c4d7e2b5f9a3d8c1e7..."
   }
   ```

3. **Decrypt server response:**
   ```json
   {
     "api":"BCryptDecrypt",
     "ciphertext_hex":"5c2d8f9a...",
     "plaintext_hex":"7b22737563636573..."
   }
   ```

### Test Target - Stage 2 (License Validation)

1. **Apply sequential cipher** (custom XOR+rotate)
2. **Compute MD5 hash:**
   ```json
   {
     "api":"CryptGetHashParam",
     "hash":{"algorithm":"MD5"},
     "payload_hex":"58145d6f0269c3c4ac13611b9d30d68e"
   }
   ```

## Security Considerations

### Do:
- ✅ Encrypt log files containing crypto data
- ✅ Use secure deletion when done
- ✅ Limit access to logs
- ✅ Test in isolated environments

### Don't:
- ❌ Share logs with sensitive keys publicly
- ❌ Log production system crypto operations
- ❌ Leave logs on shared systems
- ❌ Use for malicious decryption

## Common Algorithms by Application

| Application Type | Typical Algorithms |
|------------------|-------------------|
| Web browsers | AES-GCM, SHA-256, TLS 1.2/1.3 |
| File encryption | AES-256-CBC, PBKDF2 |
| Password managers | AES-256, Argon2/PBKDF2 |
| VPNs | AES-GCM, ChaCha20-Poly1305 |
| Malware | RC4, XOR, Custom ciphers |

---

**Next:** [Filesystem Hooks](filesystem.md)
