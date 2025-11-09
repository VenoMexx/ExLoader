## 📝 Description

<!-- Provide a clear description of what this PR does -->

## 🔗 Related Issues

<!-- Link to related issues using #issue_number -->

Fixes #
Relates to #

## 🎯 Type of Change

<!-- Mark the relevant option with an 'x' -->

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🧹 Code refactoring
- [ ] ⚡ Performance improvement
- [ ] ✅ Test addition/update

## 🧪 Testing

<!-- Describe how you tested your changes -->

- [ ] Tested with `test_target.exe`
- [ ] Verified JSON log output
- [ ] Tested in attach mode
- [ ] Tested in launch mode
- [ ] No crashes in target process
- [ ] Cross-checked with existing profiles

**Test Environment:**
- Windows Version:
- Build Toolchain:
- Target Application(s):

## 📸 Screenshots/Logs

<!-- If applicable, add screenshots or log excerpts -->

```json
{
  "type": "new.event",
  "api": "ExampleAPI"
}
```

## ✅ Checklist

<!-- Ensure all items are checked before submitting -->

- [ ] My code follows the project's [code style](../CONTRIBUTING.md#code-style)
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## 📋 Additional Context

<!-- Add any other context about the PR here -->

### For New Hook Modules

- [ ] Added to `runtime/src/runtime.cpp`
- [ ] Updated profile templates in `profiles/templates/`
- [ ] Added caller information with `append_caller()`
- [ ] Tested graceful failure when API not available
- [ ] Documented in README.md

### For API Changes

- [ ] Updated profile schema if needed
- [ ] Backward compatible with existing profiles (or documented breaking changes)
- [ ] Updated example profiles

---

**Reviewer Notes:**

<!-- Space for reviewers to add comments -->
