# CI/CD Integration Guide

DjangoSentinel integrates into any CI/CD pipeline that can run Python.

---

## GitHub Actions (Recommended)

The included `.github/workflows/security.yml` provides:
- Full security scan on every push and PR
- SARIF upload to GitHub Code Scanning (inline PR annotations)
- HTML report as a downloadable artifact
- Separate dependency-only check job
- Matrix testing across Python versions

### Minimal setup (copy-paste)

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: { python-version: '3.11' }
      - run: pip install django-sentinel
      - run: sentinel scan . --format sarif -o results.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
      - run: sentinel scan . --fail-on critical --no-color
```

---

## GitLab CI

```yaml
# .gitlab-ci.yml
security-scan:
  image: python:3.11
  stage: test
  script:
    - pip install django-sentinel
    - sentinel scan . --fail-on high --no-color
    - sentinel scan . --format json -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    when: always
```

---

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        name: Security Scan
        image: python:3.11
        script:
          - pip install django-sentinel
          - sentinel scan . --fail-on critical --no-color
          - sentinel scan . --format html -o security-report.html
        artifacts:
          - security-report.html
```

---

## Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent { docker { image 'python:3.11' } }
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install django-sentinel'
                sh 'sentinel scan . --format json -o sentinel-report.json --no-color'
                sh 'sentinel scan . --fail-on critical --no-color'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'sentinel-report.json'
                }
            }
        }
    }
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan passed (no violations at `--fail-on` threshold) |
| `1` | Vulnerabilities found at or above `--fail-on` severity |
| `2` | Scanner error (file not found, permission denied, etc.) |

---

## Recommended CI Strategy

| Stage | Scan type | `--fail-on` | Action on failure |
|-------|-----------|-------------|-------------------|
| Pre-commit (local) | Staged files | `critical` | Block commit |
| PR check | Full project | `high` | Block merge |
| Main branch push | Full project | `medium` | Alert security team |
| Nightly | Full project + deps | `low` | Ticket backlog |

---

## Suppressing False Positives

Add a `sentinel.ignore` file at your project root:

```
# sentinel.ignore
# Format: <file_path>:<line_number>:<vuln_title_substring>
# Lines starting with # are comments

# This redirect is safe — URL is from our allowlist config
myapp/views.py:142:Open Redirect

# This CSRF exempt endpoint uses HMAC webhook verification
webhooks/views.py:28:CSRF Protection Explicitly Disabled
```

> **Note**: The ignore file feature is planned for v1.1. Until then, use inline comments
> like `# sentinel: ignore` on the line to document intentional suppressions.

---

## JSON Report Schema

The JSON reporter output follows this schema:

```json
{
  "sentinel_version": "1.0.0",
  "generated_at": "2024-01-01T12:00:00",
  "summary": {
    "scan_id": "abc123",
    "project": "/path/to/project",
    "files_scanned": 42,
    "total_vulnerabilities": 7,
    "by_severity": {
      "critical": 1,
      "high": 3,
      "medium": 2,
      "low": 1
    },
    "fixable": 4,
    "fixed": 2,
    "duration_seconds": 1.23
  },
  "vulnerabilities": [
    {
      "id": "a1b2c3d4",
      "title": "DEBUG=True in Production Settings",
      "category": "Security Misconfiguration",
      "severity": "CRITICAL",
      "location": {
        "file": "config/settings.py",
        "line": 12,
        "snippet": "DEBUG = True"
      },
      "description": "...",
      "owasp": "A05:2021 – Security Misconfiguration",
      "cwe": "CWE-94",
      "cve": "",
      "fix_available": true,
      "fix_applied": true,
      "references": []
    }
  ],
  "errors": []
}
```
