# Changelog

All notable changes to ExLoader will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public release
- Comprehensive hook coverage for Windows APIs
  - Network: WinHTTP, WinInet, Winsock, URLMon, Proxy, HTTP.sys, Schannel
  - Crypto: BCrypt, CryptoAPI (AES, MD5, SHA-256, etc.)
  - Filesystem: CreateFile, ReadFile, WriteFile, GetFileAttributes, Registry operations
  - String: WideCharToMultiByte, MultiByteToWideChar, string manipulation APIs
  - Math: pow, sqrt, sin, cos, and other math functions
- Modular plugin architecture
- JSON Lines logging format
- Profile-based configuration system
- Interactive GUI CrackMe demo (test_target.exe)
  - Stage 1: Network Authentication with AES-256 encryption
  - Stage 2: License Validation with sequential cipher + MD5
  - Stage 3: File Validation with signature checking
- Live telemetry panel in GUI
- Caller module tracking (shows which DLL/module triggered each hook)
- Support for both launch and attach modes
- Example profiles in `profiles/templates/`

### Changed
- Optimized caller module logging to show only DLL name (not full path)
- Improved hook stability with proper error handling
- Enhanced telemetry display with scroll position preservation

### Fixed
- CloseHandle hook now only logs tracked file handles
- Fixed missing `append_caller()` in multiple hook functions
- Fixed Stage 3 file validation to use hookable Win32 APIs

### Security
- Added security policy documentation
- Included responsible disclosure guidelines
- Documented intended use cases and security considerations

## [1.0.0] - 2025-11-09

### Added
- Initial import of ExLoader codebase
- Core runtime and injector
- Basic hook modules
- Build system (CMake)
- MinGW and MSVC build support

---

## Release Notes Template

### [Version] - YYYY-MM-DD

#### Added
- New features

#### Changed
- Changes to existing functionality

#### Deprecated
- Features that will be removed in future versions

#### Removed
- Features that were removed

#### Fixed
- Bug fixes

#### Security
- Security patches and vulnerability fixes

[Unreleased]: https://github.com/VenoMexx/ExLoader/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/VenoMexx/ExLoader/releases/tag/v1.0.0
