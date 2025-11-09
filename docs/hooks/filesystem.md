# Filesystem Hooks

ExLoader monitors file and registry operations with complete context.

## Module: `filesystem.filemon`

### File Operations

**Hooked APIs:**

**File Creation/Opening:**
- `CreateFileW`

**File I/O:**
- `ReadFile`
- `WriteFile`
- `CloseHandle`

**File Management:**
- `DeleteFileW`
- `MoveFileExW`
- `GetFileAttributesW`
- `GetFileAttributesExW`

**Directory Search:**
- `FindFirstFileW`
- `FindNextFileW`
- `FindClose`

**Module Info:**
- `GetModuleFileNameW`

### Registry Operations

**Hooked APIs:**

**Key Management:**
- `RegOpenKeyExW`
- `RegCreateKeyExW`
- `RegDeleteKeyW`
- `RegCloseKey`

**Value Operations:**
- `RegSetValueExW`
- `RegQueryValueExW`
- `RegDeleteValueW`

## Event Types

### File Events

**create** - File/handle creation:
```json
{
  "ts": "2025-11-09T18:36:22.675Z",
  "type": "filesystem.filemon",
  "operation": "create",
  "path": "C:\\target\\config.dat",
  "desired_access": 2147483648,
  "share_mode": 1,
  "disposition": 3,
  "flags": 128,
  "result": "success",
  "caller": {
    "module": "target.exe",
    "offset": 46546
  }
}
```

**Access Flags:**
- `GENERIC_READ` = 0x80000000 (2147483648)
- `GENERIC_WRITE` = 0x40000000 (1073741824)
- `GENERIC_EXECUTE` = 0x20000000 (536870912)

**read** - File read operation:
```json
{
  "type": "filesystem.filemon",
  "operation": "read",
  "handle": 844,
  "path": "C:\\data\\input.txt",
  "requested_bytes": 1024,
  "bytes_transferred": 1024,
  "success": true,
  "payload_preview": "4c6963656e7365206461746120..."
}
```

**write** - File write operation:
```json
{
  "type": "filesystem.filemon",
  "operation": "write",
  "handle": 848,
  "path": "C:\\output\\result.log",
  "requested_bytes": 512,
  "bytes_transferred": 512,
  "payload_preview": "5374617274656420617420..."
}
```

**close** - Handle close:
```json
{
  "type": "filesystem.filemon",
  "operation": "close",
  "handle": 844,
  "path": "C:\\data\\input.txt",
  "success": true
}
```

**delete** - File deletion:
```json
{
  "type": "filesystem.filemon",
  "operation": "delete",
  "path": "C:\\temp\\cache.tmp",
  "success": true
}
```

**move** - File move/rename:
```json
{
  "type": "filesystem.filemon",
  "operation": "move",
  "from": "C:\\temp\\file.tmp",
  "to": "C:\\data\\file.dat",
  "flags": 1,
  "success": true
}
```

**get_attributes** - File attribute query:
```json
{
  "type": "filesystem.filemon",
  "operation": "get_attributes",
  "path": "C:\\target\\file.dat",
  "success": true,
  "attributes": 32
}
```

**Attribute Flags:**
- `FILE_ATTRIBUTE_READONLY` = 0x01
- `FILE_ATTRIBUTE_HIDDEN` = 0x02
- `FILE_ATTRIBUTE_SYSTEM` = 0x04
- `FILE_ATTRIBUTE_DIRECTORY` = 0x10
- `FILE_ATTRIBUTE_ARCHIVE` = 0x20

**find_first** - Start directory search:
```json
{
  "type": "filesystem.filemon",
  "operation": "find_first",
  "pattern": "C:\\data\\*.txt",
  "success": true,
  "match": "file1.txt"
}
```

**get_module_filename** - Get module path:
```json
{
  "type": "filesystem.filemon",
  "operation": "get_module_filename",
  "module": 0,
  "path": "C:\\Program Files\\App\\target.exe",
  "result_length": 35,
  "success": true
}
```

### Registry Events

**reg.open** - Open registry key:
```json
{
  "type": "filesystem.filemon",
  "operation": "reg.open",
  "parent": "HKEY_CURRENT_USER",
  "sub_key": "Software\\MyApp",
  "success": true
}
```

**reg.create** - Create registry key:
```json
{
  "type": "filesystem.filemon",
  "operation": "reg.create",
  "parent": "HKEY_CURRENT_USER",
  "sub_key": "Software\\MyApp\\Config",
  "disposition": 1,
  "success": true
}
```

**reg.set** - Set registry value:
```json
{
  "type": "filesystem.filemon",
  "operation": "reg.set",
  "key": "HKEY_CURRENT_USER\\Software\\MyApp",
  "value_name": "InstallPath",
  "type": 1,
  "data_size": 50,
  "payload_preview": "C:\\Program Files\\MyApp",
  "success": true
}
```

**Registry Value Types:**
- `REG_SZ` = 1 (String)
- `REG_BINARY` = 3 (Binary data)
- `REG_DWORD` = 4 (32-bit number)
- `REG_QWORD` = 11 (64-bit number)

**reg.query** - Query registry value:
```json
{
  "type": "filesystem.filemon",
  "operation": "reg.query",
  "key": "HKEY_LOCAL_MACHINE\\Software\\Microsoft",
  "value_name": "ProgramFilesDir",
  "type": 1,
  "data_size": 40,
  "payload_preview": "C:\\Program Files",
  "success": true
}
```

**reg.delete_key** - Delete registry key:
```json
{
  "type": "filesystem.filemon",
  "operation": "reg.delete_key",
  "parent": "HKEY_CURRENT_USER",
  "sub_key": "Software\\TempApp",
  "success": true
}
```

## Configuration

Enable filesystem monitoring:

```json
{
  "modules": [
    {
      "name": "filesystem.filemon",
      "enabled": true,
      "allow_in_attach": true
    }
  ]
}
```

### Payload Limits

Control logged file content size:

```json
{
  "logging": {
    "max_bytes_per_entry": 4096
  }
}
```

## Analysis Patterns

### Track Configuration Files

```bash
# Find config file access
jq 'select(.path and (.path | contains(".ini") or contains(".cfg") or contains("config")))' logs/output.jsonl
```

### Monitor Specific Directory

```bash
# Watch C:\Users\* access
jq 'select(.path and (.path | contains("C:\\\\Users")))' logs/output.jsonl
```

### Registry Persistence

```bash
# Check Run key modifications
jq 'select(.operation=="reg.set" and (.key | contains("Run")))' logs/output.jsonl
```

### File Exfiltration Detection

```bash
# Find large writes
jq 'select(.operation=="write" and .bytes_transferred > 1048576)' logs/output.jsonl
```

## Real-World Example: Test Target Stage 3

**File Validation Flow:**

1. **Get module path:**
   ```json
   {"operation":"get_module_filename","path":"...\\test_target.exe"}
   ```

2. **Check file existence:**
   ```json
   {
     "operation":"get_attributes",
     "path":"...\\test_target.licence.dat",
     "success":true,
     "attributes":32
   }
   ```

3. **Open file:**
   ```json
   {
     "operation":"create",
     "path":"...\\test_target.licence.dat",
     "desired_access":2147483648,
     "result":"success"
   }
   ```

4. **Read content:**
   ```json
   {
     "operation":"read",
     "path":"...\\test_target.licence.dat",
     "bytes_transferred":16,
     "payload_preview":"45584c4f414445522d4c4943454e5345"
   }
   ```
   (Hex decodes to: "EXLOADER-LICENSE")

5. **Close handle:**
   ```json
   {"operation":"close","path":"...\\test_target.licence.dat"}
   ```

## Common Patterns

### Malware Indicators

- **Dropped files** in `%TEMP%` or `%APPDATA%`
- **Registry persistence**: `Run`, `RunOnce`, `Services`
- **File attribute manipulation**: Hidden, System flags
- **Rapid file creation/deletion**: Droppers

### Legitimate Applications

- **Config loading**: `.ini`, `.xml`, `.json` reads
- **Log writing**: Sequential writes to `.log` files
- **Cache management**: Temp directory operations

## Security Notes

- **Sensitive paths logged**: User documents, credentials
- **Payload preview**: May contain sensitive data
- **Registry values**: Can include passwords, API keys

**Recommendation:** Sanitize logs before sharing.

---

**Next:** [String Hooks](string.md)
