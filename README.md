# ExLoader

ExLoader is a Windows‑centric instrumentation toolkit. The injector (`exloader.exe`) launches or attaches to any target process, injects a modular hook runtime (`libexadapter_core.dll`), and streams every captured event as JSON Lines. The runtime focuses on network, crypto, filesystem, string, and math APIs so that analysts can reconstruct a target application's behaviour without patching its binaries.

## Repository Layout

| Path | Description |
| --- | --- |
| `injector/` | CLI injector sources (`exloader.exe`). |
| `runtime/` | Hook runtime (`libexadapter_core.dll`) and all hook modules. |
| `examples/test_target/` | GUI “crackme” used to exercise every hook (WinHTTP/WinInet/Winsock, CryptoAPI/Bcrypt, licence/file validation, etc.). |
| `profiles/` | JSON profile schema plus ready‑made templates (see `profiles/templates/`). |
| `logs/` | Default log output location (empty by default). |
| `scripts/` | Helper scripts (`build_all.bat`, profiling helpers, etc.). |
| `third_party/` | Vendored dependencies (MinHook, nlohmann/json, CLI11, etc.). |

## Hook Runtime Modules

| Module | Events | Notes |
| --- | --- | --- |
| `network.winhttp`, `network.winhttp.extended` | `network.request/response`, headers, status, TLS data | Hooks WinHTTP send/receive and option APIs. |
| `network.wininet`, `network.winsock`, `network.http_sys`, `network.proxy`, `network.libcurl`, `network.win32web`, `network.urlmon` | Protocol specific coverage | Modules can fail gracefully if the process does not import the relevant DLLs. |
| `crypto.bcrypt`, `crypto.cryptapi` | `crypto.key`, `crypto.encrypt`, `crypto.decrypt`, `crypto.hash.*` | Captures plaintext/ciphertext, key handles, IVs, MD5/SHA digests, etc. |
| `filesystem.filemon` | File + registry events (`create`, `read`, `delete`, `get_attributes`, `find_first`, `reg.*`) | Covers CreateFile/ReadFile/MoveFile as well as attribute/FindFirst/Next calls and registry access. |
| `stringmon` | `string.convert`, `string.transform`, `string.copy` | Logs `WideCharToMultiByte`, `MultiByteToWideChar`, `CharUpperBuffW`, `lstrcpyW`, `lstrcatW`, etc. Payloads are reported as hex to avoid invalid UTF‑8. |
| `mathmon` | `math.call` | Hooks `pow/sqrt/sin/...` (double precision required; float variants are optional). |
| `plugins/filemon`, `plugins/stringmon`, etc. | | New modules can be added without modifying the injector; register them in `runtime/src/runtime.cpp`. |

All modules stream structured JSON. A single event typically includes:

```json
{
  "ts": "2025-11-09T17:14:58.261Z",
  "type": "network.request",
  "api": "WinHttpSendRequest",
  "metadata": {"host": "localhost", "path": "/api/user_login", "port": 5432},
  "payload_hex": "7b22656e63727970746564...",
  "payload_len": 117,
  "caller": {"module": "libexadapter_core.dll", "offset": 29287}
}
```

## Building

### MSYS2 / MinGW32 (recommended for quick iteration)

```bash
# inside an MSYS2 MinGW32 shell
cmake -S . -B build-mingw32 -G "MinGW Makefiles"
cmake --build build-mingw32
```

This produces:

* `build-mingw32/exloader.exe`
* `build-mingw32/libexadapter_core.dll`
* `build-mingw32/examples/test_target_build/test_target.exe`

A convenience script (`scripts/build_all.bat`) configures and builds both 32‑bit targets from a Windows shell if MinGW is on the PATH.

### Visual Studio

Visual Studio project files can be generated via:

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022"
cmake --build build-msvc --config Release
```

> **Note:** The runtime DLL is 32‑bit today. Building a 64‑bit injector/runtime pair will require adding `x64` toolchains plus 64‑bit MinHook libs.

## Running the Injector

The fastest way to see ExLoader in action is to run the bundled test target:

```powershell
cd D:\Projeler\ExLoader
build-mingw32\exloader.exe ^
  --profile profiles\templates\farmex-full-capture.json ^
  --log logs\afkbot-full.jsonl
```

* The profile launches `examples/test_target_build/test_target.exe` and enables **every** hook module (`network.*`, `crypto.*`, `filesystem.filemon`, `stringmon`, `mathmon`).
* Logs stream to `logs/afkbot-full.jsonl` (JSON Lines). Tail the file with `jq` or `Get-Content -Wait` to watch events live.
* When attaching to an existing PID use `--pid <id>` (leave `target.launch` empty in the profile).

## Profiles & Configuration

Profiles are JSON documents validated by `profiles/schema.json`. Important sections:

| Key | Description |
| --- | --- |
| `logging` | File path template, stdout mirroring, max bytes per entry. |
| `target` | `launch`, `arguments`, `working_directory`, or `pid` for attach mode. |
| `modules` | Array of module names or objects (`{ "name": "filesystem.filemon", "allow_in_attach": true }`). |
| `filters` | Optional host/port filters, byte caps. |

`profiles/templates/farmex-full-capture.json` demonstrates a full capture session. Duplicate it for your own scenarios.

## Sample Log Highlights

* **Crypto Hash Digest:**
  ```json
  {"type":"crypto.hash.digest","api":"CryptGetHashParam","hash":{"algorithm":"MD5"},"hash_handle":17689720,"payload_hex":"58145d6f0269c3c4ac13611b9d30d68e"}
  ```
* **Filesystem Attribute Query:**
  ```json
  {"type":"filesystem.filemon","operation":"get_attributes","path":"D:\\Projeler\\...\\test_target.licence.dat","success":false}
  ```
* **String Conversion:**
  ```json
  {"type":"string.convert","api":"WideCharToMultiByte","wide_hex":"3dd812dd20...","narrow_hex":"3d3a3a3d..."}
  ```
* **Math Call:**
  ```json
  {"type":"math.call","api":"pow","a":2.0,"b":10.0,"result":1024.0,"caller":{"module":"libexadapter_core.dll","offset":123456}}
  ```

## Test Target (“CrackMe”) Overview

The GUI test application (`examples/test_target`) exists purely to exercise hooks:

1. **Authentication** – AES‑256 encrypts credentials, posts to a local HTTP server, expects a JWT in response.
2. **Licence Validation** – Sequential XOR+rotate cipher + MD5 digest, compares against GUI input.
3. **File Validation** – Looks for a signed `test_target.licence.dat` next to the executable. The telemetry panel reports the exact path being checked.
4. **Integrity / Time Bomb** – (Placeholder logic) future work for PE integrity and time drift checks; currently debug buttons.

Follow the on‑screen tabs to generate network, crypto, string, filesystem, and math traffic. Every action is mirrored to the JSON log.

## Cleaning the Workspace

The repo does **not** track build artifacts. Before committing or packaging:

```
rm -rf build-mingw build-mingw32 logs/* examples/test_target/build
```

Add a `.gitignore` entry if you create new build directories.

## Troubleshooting

* `Plugin failed to initialize: network.win32web` – harmless; target does not load WWSAPI.
* `Plugin failed to initialize: mathmon` – ensure `msvcrt.dll` is available (MinGW32 builds expect it). The module now treats float hooks as optional but fails if mandatory functions cannot be hooked.
* JSON crashes with `[json.exception.type_error.316]` – upgrade to the latest runtime; string payloads are hex‑encoded to avoid invalid UTF‑8.

## Roadmap

See `ROADMAP.md` and `TODO.md` for upcoming work (Frida gadget bridge, x64 runtime, advanced filters, etc.). Contributions and bug reports are welcome—open an issue or start a discussion.
