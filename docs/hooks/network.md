# Network Hooks

ExLoader provides comprehensive coverage of Windows networking APIs.

## Supported Modules

### WinHTTP (`network.winhttp`, `network.winhttp.extended`)

**Hooked APIs:**
- `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`
- `WinHttpSendRequest`, `WinHttpReceiveResponse`
- `WinHttpReadData`, `WinHttpWriteData`
- `WinHttpSetOption`, `WinHttpQueryOption`
- `WinHttpQueryHeaders`, `WinHttpAddRequestHeaders`

**Event Types:**
- `network.request` - HTTP request initiated
- `network.response` - HTTP response received
- `network.data` - Data transfer events

**Sample Event:**
```json
{
  "ts": "2025-11-09T18:36:22.673Z",
  "type": "network.request",
  "api": "WinHttpSendRequest",
  "metadata": {
    "host": "localhost",
    "port": 5432,
    "path": "/api/user_login",
    "method": "POST"
  },
  "payload_hex": "7b22656e637279707465645f64...",
  "payload_len": 117,
  "caller": {
    "module": "test_target.exe",
    "offset": 29287
  }
}
```

### WinInet (`network.wininet`)

**Hooked APIs:**
- `InternetOpenA/W`, `InternetConnectA/W`
- `HttpOpenRequestA/W`, `HttpSendRequestA/W`
- `InternetReadFile`, `InternetWriteFile`
- `InternetQueryOptionA/W`, `InternetSetOptionA/W`

**Use Cases:**
- Legacy applications using WinInet
- FTP/HTTP transfers
- IE-based components

**Sample Event:**
```json
{
  "type": "network.request",
  "api": "HttpSendRequestA",
  "url": "http://example.com/api",
  "method": "GET",
  "headers": "User-Agent: Mozilla/5.0",
  "success": true
}
```

### Winsock (`network.winsock`)

**Hooked APIs:**
- `socket`, `connect`, `bind`, `listen`, `accept`
- `send`, `recv`, `sendto`, `recvfrom`
- `WSASend`, `WSARecv`, `WSAConnect`
- `closesocket`, `shutdown`
- `getaddrinfo`, `gethostbyname`

**Use Cases:**
- Raw socket communications
- Custom protocols
- Low-level network analysis

**Sample Events:**

**Connection:**
```json
{
  "type": "network.socket.connect",
  "api": "connect",
  "socket": 1844,
  "address": "192.168.1.100",
  "port": 443,
  "success": true
}
```

**Data Transfer:**
```json
{
  "type": "network.socket.send",
  "api": "send",
  "socket": 1844,
  "bytes_requested": 512,
  "bytes_transferred": 512,
  "payload_hex": "474554202f20485454502f312e31..."
}
```

### URLMon (`network.urlmon`)

**Hooked APIs:**
- `URLDownloadToFileA/W`
- `URLOpenStreamA/W`, `URLOpenPullStreamA/W`

**Use Cases:**
- File downloads
- COM-based web access

### HTTP.sys (`network.http_sys`)

**Hooked APIs:**
- `HttpInitialize`, `HttpTerminate`
- `HttpCreateServerSession`, `HttpCreateRequestQueue`
- `HttpReceiveHttpRequest`, `HttpSendHttpResponse`

**Use Cases:**
- Server-side HTTP handling
- IIS applications
- Windows HTTP Server API

### Schannel (`network.schannel`)

**Hooked APIs:**
- `AcquireCredentialsHandleA/W`
- `InitializeSecurityContextA/W`
- `AcceptSecurityContext`
- `EncryptMessage`, `DecryptMessage`

**Use Cases:**
- TLS/SSL traffic analysis
- Certificate handling
- Secure channel operations

**Sample Event:**
```json
{
  "type": "crypto.tls.encrypt",
  "api": "EncryptMessage",
  "plaintext_len": 1024,
  "ciphertext_len": 1056,
  "success": true
}
```

## Configuration

Enable network modules in your profile:

```json
{
  "modules": [
    "network.winhttp",
    "network.winhttp.extended",
    "network.wininet",
    "network.winsock",
    "network.urlmon",
    "network.schannel"
  ]
}
```

### Attach Mode Support

Some network modules support attach mode (hooking already-running processes):

```json
{
  "modules": [
    {
      "name": "network.winhttp",
      "enabled": true,
      "allow_in_attach": true
    }
  ]
}
```

## Filtering

Filter network events by host or port:

```json
{
  "filters": {
    "network": {
      "allowed_hosts": ["localhost", "api.example.com"],
      "blocked_ports": [25, 465, 587],
      "max_payload_bytes": 4096
    }
  }
}
```

## Analysis Tips

### Finding API Endpoints

```bash
# Extract unique URLs
jq -r 'select(.type=="network.request") | .metadata.path' logs/output.jsonl | sort -u
```

### Payload Inspection

```bash
# Decode hex payload
jq -r 'select(.api=="WinHttpSendRequest") | .payload_hex' logs/output.jsonl | xxd -r -p
```

### Traffic Volume

```bash
# Sum transferred bytes
jq -s 'map(select(.bytes_transferred)) | map(.bytes_transferred) | add' logs/output.jsonl
```

## Common Patterns

### Authentication Flow

1. `WinHttpConnect` - Establish connection
2. `WinHttpOpenRequest` - Create POST /api/login
3. `WinHttpSendRequest` - Send credentials (encrypted)
4. `WinHttpReceiveResponse` - Get token
5. `WinHttpReadData` - Read response body

### File Download

1. `URLDownloadToFileA` - Initiate download
2. Multiple `recv` calls - Stream chunks
3. `CloseHandle` - Complete

---

**Next:** [Crypto Hooks](crypto.md)
