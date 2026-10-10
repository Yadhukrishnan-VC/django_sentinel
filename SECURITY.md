# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active  |

## Reporting a Vulnerability

If you discover a security vulnerability in DjangoSentinel itself, please **do not** open a public GitHub issue.

Instead, report it privately:

1. **Email**: security@yourdomain.com
2. **GitHub**: Use [GitHub Private Security Advisories](https://github.com/yourusername/django-sentinel/security/advisories/new)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix and disclosure**: within 30 days for critical issues

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure) principles.

## Security Best Practices for DjangoSentinel Users

- Do not commit `.sentinel_backups/` to version control
- Keep DjangoSentinel updated to get the latest CVE signatures
- Review all ⚠️ manual-review findings — the scanner flags, humans decide
- DjangoSentinel is a SAST tool; combine it with DAST and manual pen-testing
