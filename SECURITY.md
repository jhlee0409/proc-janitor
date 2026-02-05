# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in proc-janitor, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **jhlee0409@users.noreply.github.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Security Measures

proc-janitor implements the following security controls:

- **System PID protection**: PIDs 0, 1, 2 are never targeted
- **PID reuse mitigation**: Process identity verified via `start_time` before sending signals
- **Symlink attack prevention**: `O_NOFOLLOW` flag prevents writing through symlinks
- **TOCTOU race prevention**: Exclusive file locks across read-modify-write cycles
- **Path traversal protection**: Log paths validated against directory traversal and system paths
- **Input validation**: Environment variables and configuration values are bounds-checked
- **Directory permissions**: Data directory created with `0o700` (owner-only)
- **XSS protection**: HTML dashboard escapes all user-controlled content
- **SRI verification**: CDN scripts verified with Subresource Integrity hashes

## Scope

The following are considered security-relevant:
- Process signal delivery to unintended targets
- Privilege escalation
- Arbitrary file write/overwrite
- Configuration injection
- Dashboard XSS or injection attacks
