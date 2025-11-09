# Getting Started with ExLoader

This guide will help you get ExLoader up and running in minutes.

## Prerequisites

### Required
- **Windows** 7 or later (32-bit or 64-bit)
- **MinGW-w64** (MSYS2) or **Visual Studio 2019+**
- **CMake** 3.15 or later
- **Git** for cloning the repository

### Optional
- **jq** for JSON log analysis
- **Python 3** for helper scripts

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/VenoMexx/ExLoader.git
cd ExLoader
```

### 2. Build with MinGW (Recommended)

Open an **MSYS2 MinGW 32-bit** shell:

```bash
# Configure
cmake -S . -B build-mingw32 -G "MinGW Makefiles"

# Build
cmake --build build-mingw32
```

**Output:**
- `build-mingw32/exloader.exe` - The injector
- `build-mingw32/libexadapter_core.dll` - Hook runtime
- `build-mingw32/examples/test_target_build/test_target.exe` - Demo application

### 3. Build with Visual Studio

Open PowerShell:

```powershell
# Configure for Visual Studio 2022
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A Win32

# Build Release
cmake --build build-msvc --config Release
```

## First Run

### Using the Test Target

The easiest way to test ExLoader is with the bundled GUI demo:

```powershell
# From repository root
.\build-mingw32\exloader.exe `
  --profile profiles\templates\farmex-full-capture.json `
  --log logs\demo.jsonl
```

This will:
1. Launch `test_target.exe` (GUI CrackMe)
2. Inject the hook runtime
3. Start logging all API calls to `logs\demo.jsonl`

### Interacting with Test Target

The GUI application has 3 stages:

1. **Authentication** - Test WinHTTP and BCrypt hooks
   - Click "Authenticate" with credentials: `admin` / `ExLoader2025`

2. **License Validation** - Test CryptoAPI hooks
   - Get your HWID from the GUI
   - Generate serial: Use the shown HWID to compute the correct serial

3. **File Validation** - Test Filesystem hooks
   - Create `test_target.licence.dat` with content: `EXLOADER-LICENSE`
   - Place it next to `test_target.exe`

### Viewing Logs

Tail the log file in real-time:

```powershell
# PowerShell
Get-Content logs\demo.jsonl -Wait

# With jq (prettier)
Get-Content logs\demo.jsonl -Wait | jq .
```

Sample log entry:
```json
{
  "ts": "2025-11-09T18:36:22.675Z",
  "type": "filesystem.filemon",
  "operation": "create",
  "path": "test_target.licence.dat",
  "desired_access": 2147483648,
  "result": "success",
  "caller": {
    "module": "test_target.exe",
    "offset": 46546
  }
}
```

## Attach to Existing Process

To hook an already-running process:

1. **Create a profile** with empty `launch` field:
   ```json
   {
     "target": {
       "pid": 1234
     }
   }
   ```

2. **Run with PID**:
   ```powershell
   .\build-mingw32\exloader.exe --profile your-profile.json --pid 1234
   ```

## Next Steps

- 📚 Read [Usage Guide](usage.md) for advanced options
- 🔧 Learn [Profile Configuration](profiles.md)
- 🎯 Check out [Examples](examples.md)
- 🐛 Having issues? See [Troubleshooting](troubleshooting.md)

## Common Issues

### "Plugin failed to initialize"

Some modules fail gracefully if the target doesn't use those APIs:
```
Plugin failed to initialize: network.win32web
```
This is **normal** and can be ignored if the target doesn't use that API family.

### "Access Denied"

Some processes require admin privileges:
```powershell
# Run as administrator
Start-Process powershell -Verb RunAs
```

### Antivirus Warnings

Process injection techniques are flagged by antivirus. Add ExLoader to exclusions or disable AV temporarily for testing.

---

**Ready to dive deeper?** Continue to the [Usage Guide](usage.md).
