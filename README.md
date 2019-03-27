# **ubi-population-tool**
[![Build Status](https://travis-ci.org/release-engineering/ubi-population-tool.svg?branch=master)](https://travis-ci.org/release-engineering/ubi-population-tool)
[![Coverage Status](https://coveralls.io/repos/github/release-engineering/ubi-population-tool/badge.svg?branch=master)](https://coveralls.io/github/release-engineering/ubi-population-tool?branch=master)


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
