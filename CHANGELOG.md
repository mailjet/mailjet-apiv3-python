# CHANGELOG

We [keep a changelog.](http://keepachangelog.com/)

## [Unreleased]

## [1.6.0] - 2026-04-XX

### Security

- **CWE-22 (Prevented Path Traversal):** Prevented vulnerabilities by enforcing strict URL encoding (`urllib.parse.quote`) on all dynamically injected path parameters (`id` and `action_id`).
- **CWE-113 (CRLF Injection):** Added strict header validation to block HTTP Request Smuggling.
- **CWE-117 (Log Forging):** Implemented mandatory sanitization of telemetry data.
- **CWE-316 (Secret Leakage):** Enhanced `__repr__` and `__str__` to prevent sensitive data from appearing in stack traces.
- **CWE-319 (Cleartext transmission):** Prevented by enforcing strict `api_url` scheme validation (`https`) and hostname presence during `Config` initialization.
- **CWE-601 (Open Redirect):** Hard-disabled automatic redirects (`allow_redirects=False`) for all API calls.
- **CWE-918 (SSRF):** Added hostname validation to prevent credential exfiltration to non-Mailjet domains.
- Added comprehensive security scanning to the CI/CD pipeline (`bandit`, `semgrep`, `gitleaks`, `detect-secrets`).
- Updated `SECURITY.md` policy to clarify supported active branches.

### Added

- Official support for Python 3.14 (added to CI test matrix and PyPI classifiers).
- Runtime dependency `typing-extensions>=4.7.1` for Python versions `<3.11` to support modern type hinting.
- Context Managers (Resource Management): The `Client` now supports the `with` statement (`__enter__` / `__exit__`) for automatic TCP connection pooling and socket cleanup, preventing resource leaks.
- New `mailjet_rest.utils.guardrails` module for centralized security and routing validation.
- `sanitize_log_trace` utility to protect against Log Forging attacks.
- Proactive `UserWarning` for insecure TLS configurations and unencrypted HTTP proxies.
- Smart Telemetry: The SDK now automatically extracts Mailjet Trace IDs (`CustomID`, `Campaign`, `TemplateID`) from payloads and headers, injecting them into debug logs for easier correlation with the Mailjet Dashboard.
- Executable Documentation: Added `samples/smoke_readme_runner.py` as a dynamic test suite to guarantee all `README.md` examples are continuously validated and functional against the live API.
- Developer Experience (DX) Guardrails: The SDK now logs explicit warnings when encountering ambiguous routing configurations (e.g., using the singular `template` resource on Content API `v1`, or attempting to route the Send API outside of `v3`/`v3.1`).
- Content API (v1): Native `multipart/form-data` upload support using the `requests` `files` kwarg for the `data_images` endpoint.
- Safe Exceptions: Network errors are now safely encapsulated in custom `mailjet_rest` exceptions (`TimeoutError`, `CriticalApiError`, `ApiError`).
- Native Logging: Centralized HTTP status and debug logging in `api_call` using standard Python `logging`.
- IDE Autocompletion: Overrode `__dir__` in the core `Client` to expose high-traffic dynamic endpoints (e.g., `.contact`, `.send`, `.campaigndraft`) directly to IDE autocompletion engines (VS Code, PyCharm).
- Validated and added explicit test coverage for Issue #97, proving `TemplateLanguage` and `Variables` are correctly serialized by the SDK.

### Changed

- **Performance:** Optimized dynamic routing by introducing an instance-level `_endpoint_cache`, resulting in a ~47x speedup for endpoint resolution.
- **Performance:** Reduced RAM footprint and garbage collection overhead by implementing `__slots__` across core `Client`, `Config`, and `Endpoint` classes.
- **Performance:** Optimized API call overhead by replacing dynamic header generation with `types.MappingProxyType` (`_JSON_HEADERS`, `_TEXT_HEADERS`) and moving the retry configuration to a `ClassVar`.
- **Performance:** Improved cold boot initialization time by replacing regex (`re.match`) with native string manipulation (`.split()`) in `mailjet_rest/utils/version.py`.
- Test Suite Modernization: Migrated from legacy `unittest` monolith to `pytest`, segregated into `tests/unit/` (offline) and `tests/integration/` (live network), adhering to the AAA (Arrange, Act, Assert) pattern.
- CI/CD Optimization: Drastically improved GitHub Actions speed and reliability by implementing native pip dependency caching (`cache: 'pip'`) and isolated wheel installation tests.
- Refactored `Client` and `Config` using `@dataclass` and `requests.Session` for robust connection pooling on multiple sequential requests.
- Refactored `Endpoint._build_url` cyclomatic complexity by extracting pure `@staticmethod` helpers (`_build_csv_url`, `_check_dx_guardrails`) to satisfy strict static analysis.
- Expanded `pre-commit` hooks for robust security and formatting (ruff, mypy, pyright, typos, bandit, semgrep).
- Defined explicit public module interfaces using `__all__` to prevent namespace pollution.
- Cleaned up local development environments (`environment-dev.yaml`) and pinned sub-dependencies for stable CI pipelines.
- Tooling Consolidation: Completely migrated to Ruff as the single source of truth for linting and formatting, purging legacy tools (Black, Flake8, Pylint, Pydocstyle) from `pyproject.toml` and Conda environments.
- Documentation: Rewrote `README.md` to highlight modern DX configurations, including Context Managers, robust Error Handling, and Smart Telemetry.

### Deprecated

- Passing `timeout=None` to allow infinite socket blocking is deprecated to mitigate CWE-400. Explicit timeouts will be strictly enforced in v2.0.
- Legacy HTTP exception classes (`AuthorizationError`, `ApiRateLimitError`, `DoesNotExistError`, `ValidationError`, `ActionDeniedError`). The SDK natively returns the `requests.Response` object for standard HTTP status codes.
- The legacy `ensure_ascii` and `data_encoding` arguments in the `create` and `update` method signatures. The underlying `requests` library handles UTF-8 serialization natively.
- The `parse_response` and `logging_handler` utility functions. Logging is now integrated cleanly and automatically via Python's standard `logging` library. See the `README` for the new 2-line setup.

### Removed

- Root `test.py` monolith (replaced by a modular `test/` directory structure).
- Redundant class constants (`API_REF`, `DEFAULT_API_URL`).

### Fixed

- Fixed `statcounters` required filters (explicitly added the `CounterTiming` parameter).

### Pull Requests Merged

- [PR_125](https://github.com/mailjet/mailjet-apiv3-python/pull/125) - Refactor client.
- [PR_126](https://github.com/mailjet/mailjet-apiv3-python/pull/126) - build(deps): bump conda-incubator/setup-miniconda from 3.3.0 to 4.0.1
- [PR_128](https://github.com/mailjet/mailjet-apiv3-python/pull/128) - Release 1.6.0.
- [PR_129](https://github.com/mailjet/mailjet-apiv3-python/pull/129) - Use hyphen in the package name in readme.

## [1.5.1] - 2025-07-14

### Removed

- Remove `*/_version.py` from `.gitignore`

### Changed

- Improve a conda recipe

### Pull Requests Merged

- [PR_124](https://github.com/mailjet/mailjet-apiv3-python/pull/124) - Release 1.5.1

## [1.5.0] - 2025-07-11

### Added

- Add class `TestCsvImpor` with a test suite for testing CSV import functionality to `test.py`
- Add `types-requests` to `mypy`'s `additional_dependencies` in `pre-commit` hooks
- Add `pydocstyle` pre-commit's hook
- Add `*/_version.py` to `.gitignore`

### Fixed

- Fix a csvimport error 'List index (0) out of bounds': renamed `json_data` back to `data`. Corrected behavior broken since v1.4.0

### Changed

- Update pre-commit hooks to the latest versions
- Breaking changes: drop support for Python 3.9
- Import Callable from collections.abc
- Improve a conda recipe
- Update `README.md`

### Security

- Add the Security Policy file `SECURITY.md`
- Use `permissions: contents: read` in all CI workflow files explicitly
- Use commit hashes to ensure reproducible builds
- Update pinning for runtime dependency `requests >=2.32.4`

### Pull Requests Merged

- [PR_120](https://github.com/mailjet/mailjet-apiv3-python/pull/120) - Fix a csvimport error 'List index (0) out of bounds'
- [PR_123](https://github.com/mailjet/mailjet-apiv3-python/pull/123) - Release 1.5.0

## [1.4.0] - 2025-05-07

### Added

- Enabled debug logging
- Support for Python >=3.9,\<3.14
- CI Automation (commit checks, issue-triage, PR validation, publish)
- Issue templates for bug report, feature request, documentation
- Type hinting
- Docstrings
- A conda recipe (meta.yaml)
- Package management stuff: pyproject.toml, .editorconfig, .gitattributes, .gitignore, .pre-commit-config.yaml, Makefile, environment-dev.yaml, environment.yaml
- Linting: py.typed
- New samples
- New tests

### Changed

- Update README.md
- Improved tests

### Removed

- requirements.txt and setup.py are replaced by pyproject.toml
- .travis.yml was obsolete

### Pull Requests Merged

- [PR_105](https://github.com/mailjet/mailjet-apiv3-python/pull/105) - Update README.md, fix the license name in setup.py
- [PR_107](https://github.com/mailjet/mailjet-apiv3-python/pull/107) - PEP8 enabled
- [PR_108](https://github.com/mailjet/mailjet-apiv3-python/pull/108) - Support py>=39,\<py313
- [PR_109](https://github.com/mailjet/mailjet-apiv3-python/pull/109) - PEP 484 enabled
- [PR_110](https://github.com/mailjet/mailjet-apiv3-python/pull/110) - PEP 257 enabled
- [PR_111](https://github.com/mailjet/mailjet-apiv3-python/pull/111) - Enable debug logging
- [PR_114](https://github.com/mailjet/mailjet-apiv3-python/pull/114) - Update README
- [PR_115](https://github.com/mailjet/mailjet-apiv3-python/pull/115) - Add a conda recipe
- [PR_116](https://github.com/mailjet/mailjet-apiv3-python/pull/116) - Improve CI Automation and package management
- [PR_117](https://github.com/mailjet/mailjet-apiv3-python/pull/117) - Release 1.4.0

## Version 1.3.4 (2020-10-20) - Public Release

**Closed issues:**

- Response 400 error [#59](https://github.com/mailjet/mailjet-apiv3-python/issues/59)
- Lib expected to work on py3.7? [#48](https://github.com/mailjet/mailjet-apiv3-python/issues/48)
- FromTS-ToTS filter does not work for GET /message [#47](https://github.com/mailjet/mailjet-apiv3-python/issues/47)
- import name Client [#33](https://github.com/mailjet/mailjet-apiv3-python/issues/33)
- proxy dict [#23](https://github.com/mailjet/mailjet-apiv3-python/issues/23)
- Too many 500 [#19](https://github.com/mailjet/mailjet-apiv3-python/issues/19)
- ImportError: cannot import name Client [#16](https://github.com/mailjet/mailjet-apiv3-python/issues/16)
- Add a "date" property on pypi [#15](https://github.com/mailjet/mailjet-apiv3-python/issues/15)
- Django support [#9](https://github.com/mailjet/mailjet-apiv3-python/issues/9)

**Merged pull requests:**

- Update README.md [#44](https://github.com/mailjet/mailjet-apiv3-python/pull/44) ([Hyask](https://github.com/Hyask))
- new readme version with standardized content [#42](https://github.com/mailjet/mailjet-apiv3-python/pull/42) ([adamyanliev](https://github.com/adamyanliev))
- fix page [#41](https://github.com/mailjet/mailjet-apiv3-python/pull/41) ([adamyanliev](https://github.com/adamyanliev))
- Fix unit tests for new API address [#37](https://github.com/mailjet/mailjet-apiv3-python/pull/37) ([todorDim](https://github.com/todorDim))
- Fix URL slicing, update version in unit test [#36](https://github.com/mailjet/mailjet-apiv3-python/pull/36) ([todorDim](https://github.com/todorDim))
- Add support for domain specific api url, update requests module, remove python 2.6 support [#34](https://github.com/mailjet/mailjet-apiv3-python/pull/34) ([todorDim](https://github.com/todorDim))
- add versioning section [#32](https://github.com/mailjet/mailjet-apiv3-python/pull/32) ([adamyanliev](https://github.com/adamyanliev))
- Update README.md [#31](https://github.com/mailjet/mailjet-apiv3-python/pull/31) ([mskochev](https://github.com/mskochev))
- Fix README.md [#30](https://github.com/mailjet/mailjet-apiv3-python/pull/30) ([MichalMartinek](https://github.com/MichalMartinek))

## [v1.3.2](https://github.com/mailjet/mailjet-apiv3-python/tree/v1.3.2) (2018-11-19)

[Full Changelog](https://github.com/mailjet/mailjet-apiv3-python/compare/v1.3.1...v1.3.2)

**Merged pull requests:**

- Add action_id to get [#29](https://github.com/mailjet/mailjet-apiv3-python/pull/29) ([mskochev](https://github.com/mskochev))
- Add action_id to get, increase minor version [#28](https://github.com/mailjet/mailjet-apiv3-python/pull/28) ([todorDim](https://github.com/todorDim))

## [v1.3.1](https://github.com/mailjet/mailjet-apiv3-python/tree/v1.3.1) (2018-11-13)

[Full Changelog](https://github.com/mailjet/mailjet-apiv3-python/compare/v1.3.0...v1.3.1)

**Closed issues:**

- How to add a contact to a list [#22](https://github.com/mailjet/mailjet-apiv3-python/issues/22)
- Impossible to know what is wrong [#20](https://github.com/mailjet/mailjet-apiv3-python/issues/20)
- wrong version number [#13](https://github.com/mailjet/mailjet-apiv3-python/issues/13)
- example missing / not working [#11](https://github.com/mailjet/mailjet-apiv3-python/issues/11)
- Remove 'Programming Language :: Python :: 3.2', from setup.py [#10](https://github.com/mailjet/mailjet-apiv3-python/issues/10)

**Merged pull requests:**

- Features/add action [#27](https://github.com/mailjet/mailjet-apiv3-python/pull/27) ([todorDim](https://github.com/todorDim))
- Fix action_id [#26](https://github.com/mailjet/mailjet-apiv3-python/pull/26) ([mskochev](https://github.com/mskochev))
- Pass action id, change build_url to accept both number and string [#25](https://github.com/mailjet/mailjet-apiv3-python/pull/25) ([todorDim](https://github.com/todorDim))
- README: Fix grammar [#18](https://github.com/mailjet/mailjet-apiv3-python/pull/18) ([bfontaine](https://github.com/bfontaine))
- Fix issue #13 [#14](https://github.com/mailjet/mailjet-apiv3-python/pull/14) ([latanasov](https://github.com/latanasov))
- Improve Package version [#12](https://github.com/mailjet/mailjet-apiv3-python/pull/12) ([jorgii](https://github.com/jorgii))

## [v1.3.0](https://github.com/mailjet/mailjet-apiv3-python/tree/v1.3.0) (2017-05-31)

[Full Changelog](https://github.com/mailjet/mailjet-apiv3-python/compare/v1.2.2...v1.3.0)

**Closed issues:**

- SSL certificate validation disabled [#7](https://github.com/mailjet/mailjet-apiv3-python/issues/7)
- No license? [#6](https://github.com/mailjet/mailjet-apiv3-python/issues/6)

**Merged pull requests:**

- Api version kwargs [#8](https://github.com/mailjet/mailjet-apiv3-python/pull/8) ([jorgii](https://github.com/jorgii))
- fix unresolved variable inside build_headers [#4](https://github.com/mailjet/mailjet-apiv3-python/pull/4) ([vparitskiy](https://github.com/vparitskiy))

## [v1.2.2](https://github.com/mailjet/mailjet-apiv3-python/tree/v1.2.2) (2016-06-21)

[Full Changelog](https://github.com/mailjet/mailjet-apiv3-python/compare/v1.0.6...v1.2.2)

**Merged pull requests:**

- Fix mixed indent type [#3](https://github.com/mailjet/mailjet-apiv3-python/pull/3) ([Malimediagroup](https://github.com/Malimediagroup))

## [v1.0.6](https://github.com/mailjet/mailjet-apiv3-python/tree/v1.0.6) (2016-06-20)

[Full Changelog](https://github.com/mailjet/mailjet-apiv3-python/compare/v1.0.4...v1.0.6)

**Merged pull requests:**

- Fix bug in delete method [#2](https://github.com/mailjet/mailjet-apiv3-python/pull/2) ([kidig](https://github.com/kidig))
- Include packages in setup.py [#1](https://github.com/mailjet/mailjet-apiv3-python/pull/1) ([cheungpat](https://github.com/cheungpat))

## [v1.0.4](https://github.com/mailjet/mailjet-apiv3-python/tree/v1.0.4) (2015-11-19)

[Full Changelog](https://github.com/mailjet/mailjet-apiv3-python/compare/v1.0.3...v1.0.4)

## [v1.0.3](https://github.com/mailjet/mailjet-apiv3-python/tree/v1.0.3) (2015-10-13)

[Full Changelog](https://github.com/mailjet/mailjet-apiv3-python/compare/19cf9a00a948e84de4842b51b0336e978f7a849f...v1.0.3)

\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*

[1.4.0]: https://github.com/mailjet/mailjet-apiv3-python/releases/tag/v1.4.0
[1.5.0]: https://github.com/mailjet/mailjet-apiv3-python/releases/tag/v1.5.0
[1.5.1]: https://github.com/mailjet/mailjet-apiv3-python/releases/tag/v1.5.1
[1.6.0]: https://github.com/mailjet/mailjet-apiv3-python/releases/tag/v1.6.0
[unreleased]: https://github.com/mailjet/mailjet-apiv3-python/releases/tag/v1.6.0...HEAD
