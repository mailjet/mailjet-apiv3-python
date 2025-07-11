# CHANGELOG

We [keep a changelog.](http://keepachangelog.com/)

## [Unreleased]

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
[unreleased]: https://github.com/mailjet/mailjet-apiv3-python/releases/tag/v1.5.0...HEAD
