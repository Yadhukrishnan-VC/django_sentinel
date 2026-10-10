# CI/CD Integration Guide

DjangoSentinel integrates into any CI/CD pipeline. The key decision is which scan mode to use:

| Mode | When to use | Speed |
|------|-------------|-------|
| `--diff --staged` | Pre-commit hook | < 1s |
| `--diff --base main` | PR check | 1–5s |
| Full scan | Nightly / main branch | 5–60s |
| `--ai-deep` | Weekly / security audits | minutes |

---

## GitHub Actions (Recommended)

The included `.github/workflows/security.yml` has four jobs. Here is a minimal standalone version:

### Minimal — just SARIF upload

```yaml
name: Security
on: [push, pull_request]
permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: { python-version: "3.11" }
      - run: pip install django-sentinel
      - run: sentinel scan . --format sarif -o results.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
      - run: sentinel scan . --fail-on critical --no-color
```

### Full — PR comment + inline + check run + AI

```yaml
name: DjangoSentinel Security
on: [push, pull_request]
permissions:
  security-events: write
  pull-requests: write
  checks: write
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }  # needed for --diff --base

      - uses: actions/setup-python@v4
        with: { python-version: "3.11" }

      - run: pip install django-sentinel

      # Diff scan only (fast, targets PR changes)
      - name: Diff scan
        if: github.event_name == 'pull_request'
        run: |
          sentinel scan . \
            --diff --base ${{ github.base_ref }} \
            --pr-comment --pr-inline --pr-check \
            --ai \
            --format sarif -o results.sarif \
            --fail-on high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

      # Full scan on push to main
      - name: Full scan
        if: github.event_name == 'push'
        run: |
          sentinel scan . \
            --format sarif -o results.sarif \
            --fail-on critical
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: results.sarif }
```

### Repository secrets to set

Go to repo → Settings → Secrets → Actions:

| Secret | Value | Required |
|--------|-------|----------|
| `GITHUB_TOKEN` | auto-provided | Yes (for PR features) |
| `ANTHROPIC_API_KEY` | `sk-ant-...` | Optional (for AI features) |

---

## GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

sentinel-diff:
  stage: security
  image: python:3.11
  script:
    - pip install django-sentinel
    # Diff scan on MRs
    - sentinel scan . --diff --base $CI_MERGE_REQUEST_TARGET_BRANCH_NAME --fail-on high --no-color
    # Full scan output
    - sentinel scan . --format json -o gl-sast-report.json --no-color
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths: [gl-sast-report.json]
    when: always

sentinel-full:
  stage: security
  image: python:3.11
  script:
    - pip install django-sentinel
    - sentinel scan . --fail-on critical --no-color
    - sentinel scan . --format html -o security-report.html --no-color
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  artifacts:
    paths: [security-report.html]
    expire_in: 30 days
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
```

---

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: python:3.11

pipelines:
  pull-requests:
    '**':
      - step:
          name: Security Scan (Diff)
          script:
            - pip install django-sentinel
            - sentinel scan . --diff --staged --fail-on high --no-color
            - sentinel scan . --format html -o security-report.html --no-color
          artifacts:
            - security-report.html

  branches:
    main:
      - step:
          name: Full Security Scan
          script:
            - pip install django-sentinel
            - sentinel scan . --fail-on critical --no-color
            - sentinel scan . --format json -o report.json --no-color
          artifacts:
            - report.json
```

---

## Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent { docker { image 'python:3.11' } }

    environment {
        ANTHROPIC_API_KEY = credentials('anthropic-api-key')
    }

    stages {
        stage('Security Scan') {
            parallel {
                stage('Diff Scan') {
                    when { changeRequest() }
                    steps {
                        sh '''
                            pip install django-sentinel
                            sentinel scan . \
                                --diff --base origin/main \
                                --fail-on high \
                                --format json -o diff-report.json \
                                --no-color
                        '''
                    }
                }
                stage('Full Scan') {
                    when { branch 'main' }
                    steps {
                        sh '''
                            pip install django-sentinel
                            sentinel scan . \
                                --fail-on critical \
                                --format html -o security-report.html \
                                --no-color
                        '''
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: '*-report.*', allowEmptyArchive: true
                }
            }
        }
    }
}
```

---

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install DjangoSentinel
          command: pip install django-sentinel
      - run:
          name: Diff scan
          command: |
            sentinel scan . \
              --diff --base main \
              --format json -o results.json \
              --fail-on high \
              --no-color
      - store_artifacts:
          path: results.json

workflows:
  main:
    jobs:
      - security-scan
```

---

## Pre-commit Framework Integration

If you use the [pre-commit](https://pre-commit.com/) framework (separate from `sentinel install-hooks`):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: djangosentinel
        name: DjangoSentinel Security Scan
        language: python
        entry: sentinel
        args: [scan, ., --diff, --staged, --fail-on, critical, --no-color]
        pass_filenames: false
        types: [python]
```

Install: `pre-commit install`

---

## Recommended CI Strategy

| Stage | Scan | `--fail-on` | Blocks | Runs in |
|-------|------|-------------|--------|---------|
| Pre-commit | `--diff --staged` | `critical` | commit | < 1s |
| PR check | `--diff --base main` | `high` | merge | 2–5s |
| Main branch | full scan | `critical` | deploy | 5–30s |
| Nightly | full + `--ai-deep` | `medium` | alert only | 1–5m |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan passed — no violations at `--fail-on` threshold |
| `1` | Violations found at or above `--fail-on` severity |
| `2` | Scanner error (file not found, permission denied) |

---

## Output Format Quick Reference

```bash
# Terminal — developer UX, grouped by severity
sentinel scan . --format terminal

# Diff terminal — compact, shows only changed files
sentinel scan . --diff --format terminal

# JSON — machine-readable, for dashboards / custom tooling
sentinel scan . --format json -o report.json

# HTML — browser dashboard with code snippets and fix blocks
sentinel scan . --format html -o report.html

# SARIF — GitHub Code Scanning, VS Code, other SARIF consumers
sentinel scan . --format sarif -o results.sarif
# Then upload:
# gh api repos/{owner}/{repo}/code-scanning/sarifs --input results.sarif
```

---

## Suppressing False Positives

DjangoSentinel does not yet read `.sentinel.yml` suppressions at runtime (planned for v1.1). For now, document suppressions as comments:

```python
# sentinel: ignore — this redirect is validated against our internal allowlist
return redirect(next_url)
```

Or use `--skip-*` flags for entire scanner categories:

```bash
sentinel scan . --skip-logic    # skip business logic scanner
sentinel scan . --skip-deps     # skip dependency CVE check
sentinel scan . --skip-ast      # skip AST structural scanner
```
