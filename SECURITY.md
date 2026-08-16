# Security Policy

## Supported Versions

We currently provide security updates for the active major version of the Mailjet Python Wrapper.

| Version | Supported          |
| ------- | ------------------ |
| 1.8.x   | :white_check_mark: |
| < 1.8.0 | :x:                |

# Vulnerability Disclosure

Please **do not** report security vulnerabilities through public GitHub issues.

If you believe you have found a potential security vulnerability in `mailjet-rest`, please open a [draft Security Advisory](https://github.com/mailjet/mailjet-apiv3-python/security/advisories/new) via GitHub. We will coordinate verification and next steps through that secure medium.

Please include the following details:

- A description of the vulnerability.
- Steps to reproduce the issue.
- Possible impact and proof-of-concept code.

If English is not your first language, please try to describe the problem and its impact to the best of your ability. For greater detail, please use your native language, and we will try our best to translate it using online services.

Please do not disclose this to anyone else. We will retrieve a CVE identifier if necessary and give you full credit under whatever name or alias you provide. We will only request an identifier when we have a fix and can publish it in a release.

We will respect your privacy and will only publicize your involvement if you grant us permission.

## Process

This following information discusses the process the project follows in response to vulnerability disclosures.

### Timeline

- **Initial Response:** When you report an issue, one of the project members will respond to you within **3 business days** at the outside.
- **Triage & Severity Decision:** Within **7 business days**.
- **Fix & Coordinated Disclosure:** Our goal is to have a fix for any vulnerability released within **two weeks** of initial disclosure, and fully coordinated within a standard 90-day embargo window (shorter for active exploitation).

Throughout the fix process, we will keep you up to speed with progress and notify you once a candidate patch is ready for verification.

On release day, we will push the patch to our public repository, publish a GitHub Security Advisory (GHSA), obtain a CVE identifier, and issue an updated release on PyPI. We will explicitly mention which commits contain the fix to make downstream patching straightforward.
