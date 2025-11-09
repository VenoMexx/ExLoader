# String Hooks

Monitor string conversions and manipulations.

## Module: `stringmon`

### Hooked APIs

**Character Conversion:**
- `WideCharToMultiByte` - UTF-16 → UTF-8/ANSI
- `MultiByteToWideChar` - UTF-8/ANSI → UTF-16

**String Manipulation:**
- `CharUpperBuffW` - Convert to uppercase
- `CharLowerBuffW` - Convert to lowercase
- `lstrcpyW` - String copy
- `lstrcatW` - String concatenation

## Event Type: `string.convert`

**Wide to Narrow:**
```json
{
  "ts": "2025-11-09T18:36:10.580Z",
  "type": "string.convert",
  "api": "WideCharToMultiByte",
  "wide_hex": "44003a005c00500072006f006a0065006c00",
  "narrow_hex": "443a5c50726f6a656c",
  "caller": {
    "module": "libexadapter_core.dll",
    "offset": 100918
  }
}
```

**Narrow to Wide:**
```json
{
  "type": "string.convert",
  "api": "MultiByteToWideChar",
  "narrow_hex": "48656c6c6f",
  "wide_hex": "480065006c006c006f00"
}
```

## Why Hex Encoding?

Strings are logged as **hex** to avoid:
- Invalid UTF-8 in JSON
- Binary data corruption
- Escaping issues

### Decoding Hex Strings

**Python:**
```python
import binascii
hex_str = "48656c6c6f"
decoded = binascii.unhexlify(hex_str).decode('ascii')
print(decoded)  # "Hello"
```

**PowerShell:**
```powershell
$hex = "48656c6c6f"
$bytes = [byte[]]::new($hex.Length / 2)
for($i=0; $i -lt $hex.Length; $i+=2) {
    $bytes[$i/2] = [convert]::ToByte($hex.Substring($i, 2), 16)
}
[System.Text.Encoding]::ASCII.GetString($bytes)
```

**jq + xxd:**
```bash
jq -r '.wide_hex' logs/output.jsonl | xxd -r -p | iconv -f UTF-16LE
```

## Configuration

```json
{
  "modules": ["stringmon"]
}
```

## Analysis Patterns

### Find Specific Strings

```bash
# Search for "password" in conversions
jq 'select(.type=="string.convert") | .wide_hex' logs/output.jsonl | \
  while read hex; do
    echo $hex | xxd -r -p | grep -i password && echo "Found!"
  done
```

### Track URL Conversions

```bash
# Decode all wide strings and grep for http
jq -r 'select(.type=="string.convert" and .wide_hex) | .wide_hex' logs/output.jsonl | \
  xxd -r -p | iconv -f UTF-16LE | grep http
```

## Common Patterns

### File Paths

Wide strings often represent file paths:
```
wide_hex: "44003a005c00..." → "D:\..."
```

### URLs

Network operations convert URLs:
```
wide_hex: "680074007400700073003a002f002f00..." → "https://..."
```

### User Input

GUI applications convert user input:
```
narrow_hex: "61646d696e" → "admin"
```

---

**Next:** [Math Hooks](math.md)
