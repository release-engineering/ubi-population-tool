# **ubi-population-tool**
[![Build Status](https://github.com/release-engineering/ubi-population-tool/actions/workflows/tox-test.yml/badge.svg)](https://github.com/release-engineering/ubi-population-tool/actions/workflows/tox-test.yml)
[![codecov](https://codecov.io/gh/release-engineering/ubi-population-tool/branch/master/graph/badge.svg?token=APniN2wa2U)](https://codecov.io/gh/release-engineering/ubi-population-tool)
[![Source](https://badgen.net/badge/icon/source?icon=github&label)](https://github.com/release-engineering/ubi-population-tool/)
[![Documentation](https://github.com/release-engineering/ubi-population-tool/actions/workflows/docs.yml/badge.svg)](https://release-engineering.github.io/ubi-population-tool/)
[![PyPI version](https://badgen.net/pypi/v/ubi-population-tool?color=blue)](https://pypi.org/project/ubi-population-tool/)

A command-line tool for populating ubi repositories.

# Cli usage

Cli can be run by *ubipop* with arguments:

- positional arguments:
  - content_sets: list of content sets to be processed

- optional arguments:
  - -h, --help: show this help message and exit
  - --pulp-hostname HOSTNAME: hostname of Pulp server
  - --user USER: username for authentication to Pulp
  - --password PASSWORD: password for authentication to Pulp
  - --dry-run: if True, print pulp actions only, do not execute

# Development
-----------

Patches may be contributed via pull requests to
https://github.com/release-engineering/ubi-population-tool

All changes must pass the automated test suite, along with various static
checks.

The [Black](https://black.readthedocs.io/) code style is enforced.
Enabling autoformatting via a pre-commit hook is recommended:

```
pip install -r requirements-dev.txt
pre-commit install
```