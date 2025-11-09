# Troubleshooting

Common issues and solutions when using ExLoader.

## Build Issues

### CMake Configuration Failed

**Error:**
```
CMake Error: Could not find CMAKE_C_COMPILER
```

**Solution:**
- Ensure MinGW or Visual Studio is installed
- Add toolchain to PATH
- Use correct generator:
  ```bash
  cmake -G "MinGW Makefiles"  # For MinGW
  cmake -G "Visual Studio 17 2022"  # For VS2022
  ```

### Missing Dependencies

**Error:**
```
fatal error: nlohmann/json.hpp: No such file or directory
```

**Solution:**
Dependencies are in `third_party/`. Ensure submodules are initialized:
```bash
git submodule update --init --recursive
```

## Runtime Issues

### Plugin Initialization Failures

**Message:**
```
Plugin failed to initialize: network.win32web
Plugin failed to initialize: mathmon
```

**Explanation:**
This is **normal** and can be safely ignored. Plugins fail gracefully when:
- Target doesn't load required DLLs (e.g., WWSAPI.dll for win32web)
- Hooked functions unavailable (e.g., float math variants)

**Action:** None needed unless the module you specifically want isn't working.

### Access Denied Errors

**Error:**
```
Error: Could not inject into process (Access Denied)
```

**Causes:**
1. **Insufficient privileges** - Target is running as admin
2. **Protected process** - System process or anti-cheat
3. **Antivirus blocking** - AV prevents injection

**Solutions:**
```powershell
# Run as administrator
Start-Process powershell -Verb RunAs

# Temporarily disable AV (testing only!)
# Add ExLoader to AV exclusions
```

### DLL Not Found

**Error:**
```
The program can't start because libexadapter_core.dll is missing
```

**Solution:**
Ensure DLL is in same directory as `exloader.exe`:
```bash
build-mingw32/
├── exloader.exe
└── libexadapter_core.dll  # Must be here
```

## Logging Issues

### Empty Log Files

**Problem:** Log file created but no events logged.

**Checklist:**
1. **Profile enabled modules?**
   ```json
   {"modules": ["network.winhttp"]}
   ```

2. **Target uses those APIs?**
   - Use Process Monitor to verify API usage

3. **Permissions?**
   - Check log directory is writable

### Invalid JSON Errors

**Error:**
```
[json.exception.type_error.316] invalid UTF-8 byte at index 10
```

**Solution:**
Update to latest ExLoader. String payloads are now hex-encoded to prevent this.

**Workaround:**
Reduce `max_bytes_per_entry` in profile:
```json
{
  "logging": {
    "max_bytes_per_entry": 4096
  }
}
```

### Log File Too Large

**Problem:** Logs grow to gigabytes.

**Solutions:**

**1. Rotate logs:**
```powershell
# PowerShell log rotation
if ((Get-Item logs\output.jsonl).Length -gt 100MB) {
    Move-Item logs\output.jsonl logs\output-$(Get-Date -Format yyyyMMdd).jsonl
}
```

**2. Filter events:**
```json
{
  "filters": {
    "network": {
      "allowed_hosts": ["specific-host.com"]
    }
  }
}
```

**3. Reduce payload size:**
```json
{
  "logging": {
    "max_bytes_per_entry": 1024
  }
}
```

## Injection Issues

### Process Crashes on Inject

**Symptoms:** Target process terminates immediately after injection.

**Debugging:**

1. **Check target architecture:**
   ```powershell
   dumpbin /headers target.exe | findstr "machine"
   ```
   ExLoader runtime is 32-bit. Can't inject into 64-bit processes.

2. **Disable hooks incrementally:**
   ```json
   {
     "modules": ["network.winhttp"]  // Test one at a time
   }
   ```

3. **Check for anti-debugging:**
   Some applications detect injection and self-terminate.

### Attach Mode Not Working

**Problem:** Can't attach to running process.

**Solutions:**

1. **Use correct PID:**
   ```powershell
   # Find PID
   Get-Process target

   # Attach
   exloader.exe --profile profile.json --pid 1234
   ```

2. **Enable attach mode in modules:**
   ```json
   {
     "modules": [
       {
         "name": "filesystem.filemon",
         "allow_in_attach": true
       }
     ]
   }
   ```

3. **Process may be protected:**
   System processes or those with anti-cheat can't be attached.

## Performance Issues

### High CPU Usage

**Cause:** Logging overhead on high-frequency APIs.

**Solutions:**

1. **Reduce logged payloads:**
   ```json
   {"logging": {"max_bytes_per_entry": 512}}
   ```

2. **Disable stdout mirroring:**
   ```json
   {"logging": {"stdout": false}}
   ```

3. **Filter unnecessary events:**
   Only enable needed modules.

### Target Application Slowdown

**Cause:** Hook overhead on critical path.

**Solutions:**

1. **Disable verbose modules:**
   `stringmon` and `mathmon` can be high-frequency.

2. **Use attach mode sparingly:**
   Launch mode has lower overhead.

## Antivirus Issues

### Antivirus Quarantines ExLoader

**Cause:** Injection techniques flagged as malicious.

**Solutions:**

1. **Add exclusions:**
   ```
   C:\path\to\ExLoader\
   ```

2. **Disable real-time protection temporarily** (testing only).

3. **Submit false positive report** to AV vendor.

### Windows Defender SmartScreen

**Message:** "Windows protected your PC"

**Solution:**
Click "More info" → "Run anyway" (only if you trust the source).

## Profile Issues

### Profile Not Found

**Error:**
```
Error: Could not load profile: No such file or directory
```

**Solution:**
Use absolute path or correct relative path:
```powershell
# Absolute
exloader.exe --profile C:\full\path\profile.json

# Relative from repo root
exloader.exe --profile profiles\templates\farmex-full-capture.json
```

### Invalid Profile JSON

**Error:**
```
Error: Invalid profile: unexpected token at line 10
```

**Solution:**
Validate JSON:
```bash
# With jq
jq . profile.json

# Online validator
# https://jsonlint.com
```

## Analysis Issues

### Can't Parse Hex Payloads

**Problem:** Need to decode `payload_hex` fields.

**Solutions:**

**PowerShell:**
```powershell
function Decode-Hex($hex) {
    $bytes = [byte[]]::new($hex.Length / 2)
    for($i=0; $i -lt $hex.Length; $i+=2) {
        $bytes[$i/2] = [convert]::ToByte($hex.Substring($i, 2), 16)
    }
    [System.Text.Encoding]::UTF8.GetString($bytes)
}

Get-Content logs\output.jsonl | jq -r '.payload_hex' | ForEach-Object { Decode-Hex $_ }
```

**Bash:**
```bash
jq -r '.payload_hex' logs/output.jsonl | xxd -r -p
```

## Getting Help

If your issue isn't listed here:

1. **Check existing issues:** [GitHub Issues](https://github.com/VenoMexx/ExLoader/issues)
2. **Enable debug logging:** Check hook initialization in logs
3. **Collect information:**
   - Windows version
   - Build toolchain
   - Target application
   - Profile configuration
   - Log excerpts
4. **Open an issue:** Use [bug report template](https://github.com/VenoMexx/ExLoader/issues/new?template=bug_report.md)

---

**Still stuck?** [Open a discussion](https://github.com/VenoMexx/ExLoader/discussions)
