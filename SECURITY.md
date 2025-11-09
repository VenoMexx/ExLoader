# Security Policy

## 🔒 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## 🛡️ Security Context

ExLoader is a **dynamic instrumentation toolkit** designed for security research, malware analysis, and reverse engineering. By design, it hooks Windows APIs and injects code into target processes.

### Intended Use Cases

- ✅ Malware analysis and behavior monitoring
- ✅ Legacy application debugging
- ✅ Security research and penetration testing
- ✅ Reverse engineering educational purposes
- ✅ Incident response and forensics

### Important Security Considerations

1. **Process Injection**: ExLoader injects DLLs into target processes. This is a privileged operation that can be flagged by antivirus software.

2. **API Hooking**: The tool modifies process memory to intercept API calls. Use only on systems where you have explicit authorization.

3. **Data Logging**: All intercepted API calls are logged to JSON files. These logs may contain sensitive information (passwords, encryption keys, file paths, etc.). Handle logs securely.

4. **Elevated Privileges**: Some hooking scenarios may require administrator privileges. ExLoader does not implement privilege escalation.

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability in ExLoader itself (not in target applications), please report it responsibly:

### How to Report

1. **Do NOT** open a public GitHub issue
2. **Email** security concerns to: [Create a security advisory](https://github.com/VenoMexx/ExLoader/security/advisories/new)
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Updates**: We'll keep you informed of progress
- **Credit**: Security researchers will be credited (unless you prefer anonymity)

### Disclosure Timeline

- We aim to patch critical vulnerabilities within 30 days
- We'll coordinate disclosure timing with you
- Public disclosure after patch is released

## 🔐 Security Best Practices

### For Users

1. **Verify Sources**: Only download ExLoader from official repository
2. **Sandbox Testing**: Test in isolated VMs or sandboxed environments
3. **Secure Logs**: Encrypt or securely delete log files containing sensitive data
4. **Authorization**: Ensure you have permission to analyze target applications
5. **Update Regularly**: Keep ExLoader updated for latest security fixes

### For Developers

1. **Input Validation**: Validate all profile JSON inputs
2. **Memory Safety**: Use RAII and smart pointers to prevent leaks
3. **Error Handling**: Gracefully handle hook failures without crashing target
4. **Least Privilege**: Don't request unnecessary permissions
5. **Code Review**: All changes require peer review before merge

## ⚠️ Known Limitations

- **Antivirus Detection**: Process injection techniques are commonly flagged
- **32-bit Only**: Current version supports 32-bit processes only
- **Windows Only**: No Linux/macOS support
- **No Anti-Analysis Bypass**: Does not attempt to evade anti-debugging/anti-hooking mechanisms

## 📚 Responsible Disclosure

We follow coordinated vulnerability disclosure principles. We appreciate the security community's help in keeping ExLoader secure.

---

**Remember**: Use ExLoader ethically and legally. Unauthorized system access or analysis is illegal.
