# ExLoader Documentation

Welcome to the ExLoader documentation! ExLoader is a Windows-centric instrumentation toolkit for API hooking and behavioral analysis.

## 📚 Documentation Sections

### Getting Started
- [Installation & Building](building.md)
- [Quick Start Guide](getting-started.md)
- [Usage Guide](usage.md)

### Hook Modules
- [Network Hooks](hooks/network.md) - WinHTTP, WinInet, Winsock, URLMon
- [Crypto Hooks](hooks/crypto.md) - BCrypt, CryptoAPI
- [Filesystem Hooks](hooks/filesystem.md) - File and Registry operations
- [String Hooks](hooks/string.md) - String conversion and manipulation
- [Math Hooks](hooks/math.md) - Mathematical functions

### Advanced Topics
- [API Reference](api-reference.md)
- [Profile Configuration](profiles.md)
- [Custom Hook Development](custom-hooks.md)
- [Examples](examples.md)
- [Troubleshooting](troubleshooting.md)

## 🎯 What is ExLoader?

ExLoader is a dynamic instrumentation framework that:

- **Hooks Windows APIs** without modifying target binaries
- **Captures API calls** with full context (parameters, return values, caller information)
- **Logs structured events** as JSON Lines for easy analysis
- **Supports modular architecture** - enable only the hooks you need
- **Works in two modes**: Launch new processes or attach to existing ones

## 🚀 Quick Example

```powershell
# Build the project
cmake -S . -B build-mingw32 -G "MinGW Makefiles"
cmake --build build-mingw32

# Run with test target
build-mingw32\exloader.exe ^
  --profile profiles\templates\farmex-full-capture.json ^
  --log logs\output.jsonl
```

## 📊 Sample Output

```json
{
  "ts": "2025-11-09T18:36:22.673Z",
  "type": "filesystem.filemon",
  "operation": "get_attributes",
  "path": "C:\\target\\file.dat",
  "success": true,
  "caller": {
    "module": "target.exe",
    "offset": 46250
  }
}
```

## 🔗 Quick Links

- [GitHub Repository](https://github.com/VenoMexx/ExLoader)
- [Report Issues](https://github.com/VenoMexx/ExLoader/issues)
- [Contributing Guidelines](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)

## 📖 Table of Contents

### Core Concepts
1. [Architecture Overview](#architecture)
2. [Hook Modules](#hook-modules)
3. [Event Logging](#event-logging)
4. [Profiles & Configuration](#profiles)

### Hook Modules

ExLoader provides comprehensive coverage of Windows APIs:

| Module | Coverage | Use Case |
|--------|----------|----------|
| **Network** | WinHTTP, WinInet, Winsock | HTTP/HTTPS traffic, socket operations |
| **Crypto** | BCrypt, CryptoAPI | Encryption, hashing, key management |
| **Filesystem** | CreateFile, ReadFile, Registry | File access, registry operations |
| **String** | WideChar conversions | String manipulation tracking |
| **Math** | Standard math library | Mathematical operations |

### Event Logging

All events include:
- **Timestamp** (ISO 8601 format)
- **Event type** and API name
- **Parameters** and return values
- **Caller information** (module + offset)
- **Payload data** (hex-encoded when binary)

### Profiles

Profiles are JSON documents that configure:
- Which modules to enable
- Target process (launch or attach)
- Logging destination and format
- Optional filters (host, port, byte limits)

---

**Need help?** Check the [Troubleshooting Guide](troubleshooting.md) or [open an issue](https://github.com/VenoMexx/ExLoader/issues).
