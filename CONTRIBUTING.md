# Contributing to ExLoader

Thank you for your interest in contributing to ExLoader! This document provides guidelines and instructions for contributing.

## 🤝 How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear description** of the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details**: Windows version, MinGW/MSVC version, target application
- **Log excerpts** from `logs/*.jsonl` if relevant
- **Screenshots** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Use case description** - what problem does it solve?
- **Proposed solution** - how should it work?
- **Alternatives considered** - what other approaches did you think about?

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**:
   - Follow the existing code style (see Code Style section)
   - Add tests if applicable
   - Update documentation
4. **Test thoroughly**:
   - Build on MinGW32
   - Run test_target and verify hooks work
   - Check JSON logs are valid
5. **Commit** with clear messages:
   ```
   Add GetFileSize hook to filemon module

   - Hook GetFileSize in filemon_hook.cpp
   - Log file size and success status
   - Add caller information
   ```
6. **Push** to your fork
7. **Create a Pull Request**

## 📋 Code Style

### C++ Guidelines

- **Naming**:
  - Classes/Structs: `PascalCase` (e.g., `FileMonHook`)
  - Functions: `snake_case` (e.g., `resolve_caller`)
  - Variables: `snake_case` with descriptive names
  - Constants: `kPascalCase` or `MACRO_CASE`

- **Formatting**:
  - Indentation: 4 spaces (no tabs)
  - Braces: Opening brace on same line for functions
  - Line length: Prefer < 100 characters

- **Comments**:
  - Use `//` for single-line comments
  - Document non-obvious behavior
  - Explain *why*, not *what*

### Hook Module Development

When adding a new hook module:

1. **Create files**:
   - `runtime/src/hooks/modules/yourmodule_hook.cpp`
   - `runtime/include/exloader/runtime/hooks/modules/yourmodule_hook.hpp`

2. **Implement required interface**:
   ```cpp
   class YourModuleHook : public HookModule {
   public:
       bool initialize(const PluginContext& ctx) override;
       void shutdown() override;
   };
   ```

3. **Add caller information**:
   ```cpp
   hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
   ```

4. **Log structured events**:
   ```cpp
   nlohmann::json event;
   event["type"] = "yourmodule.operation";
   event["api"] = "WinApiFunction";
   event["success"] = true;
   log_event("operation_name", std::move(event));
   ```

5. **Register in runtime**:
   - Add to `runtime/src/runtime.cpp`
   - Update profile templates in `profiles/templates/`

### Testing

- Test with the bundled `test_target.exe`
- Verify JSON output is valid
- Check hooks don't crash target process
- Test both launch and attach modes

## 📦 Building

See [Building](README.md#building) section in README.md.

Quick reference:
```bash
# MinGW32
cmake -S . -B build-mingw32 -G "MinGW Makefiles"
cmake --build build-mingw32

# Test
build-mingw32/exloader.exe --profile profiles/templates/afkbot-full-capture.json
```

## 🔍 Code Review Process

1. All submissions require review
2. Reviewers will check:
   - Code quality and style
   - Test coverage
   - Documentation updates
   - Performance impact
3. Address feedback in new commits
4. Once approved, maintainers will merge

## 📝 Documentation

- Update `README.md` for user-facing changes
- Add inline documentation for complex code
- Update profile templates if adding new modules
- Consider adding examples to `examples/`

## ⚖️ License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🎯 Good First Issues

Look for issues labeled [`good first issue`](https://github.com/VenoMexx/ExLoader/labels/good%20first%20issue) - these are great starting points!

## 💬 Questions?

Feel free to open a discussion or issue if you have questions about contributing.

---

Thank you for contributing to ExLoader! 🚀
