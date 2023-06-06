# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- n/a

## [0.14.0] - 2023-06-01

### Added

- Authentication to pulp server by certificate and key
- Purging CDN cache by ARLs

### Removed

- Python 2 support

## [0.13.0] - 2023-01-20

### Added

- Improved logging for various actions

### Changed

- Usage of ubi-manifest service is mandatory

## [0.12.0] - 2022-09-06

### Added

- Flush cache of mutable URLs of repositories

## [0.11.0] - 2022-05-25

### Fixed

- Fixed python packages lookup in setup.py

## [0.10.0] - 2022-05-24

### Added

- New optional cli option --ubi-manifest-url that enables usage of ubi-manifest service
- Added support for using data from ubi-manifest service

## [0.9.0] - 2021-09-29

### Changed
- Publishing UBI repositories is now non-blocking

## [0.8.0]

### Added
- New cli options --version and --content-set-regex

### Changed
- Queries for current content use Matcher class now
- Matching modulemd_defaults units now use the Matcher class as well

## [0.7.0]

### Added
- Customizable timeout for requests

### Fixed
- Creation of SRPM output set

## [0.6.0] - 2021-09-06
### Changed
- Queries for rpm units reimplemented in more efficient way

## [0.5.0] - 2021-08-09

### Added

- Setup for pubtools.pulplib logger

## [0.4.0] - 2021-08-09

### Changed
- Queries for modulemd units reimplemented in more efficient way

### Added
- Partial usage of pubtools-pulplib client

## [0.3.1] - 2021-06-04

### Fixed
- Associating only those modular rpms that are referenced by modulemd in ubi repo

## [0.3.0] - 2019-11-27
### Added
- Support for using population_source repository note
- Repositories are populated on config files based on version

## [0.2.0] - 2019-10-08
### Added
- Accepts content set labels and repo IDs for content calculation
- Skips population of repositories not marked for population 

### Fixed
- Duplicated associations of S/RPMs
- Checking for canceled pulp task status

## [0.1.19] - 2019-06-25

### Fixed 
- py26 compatibility issue on travis
- rpm-py-installer requirement was made conditional  

[Unreleased]: https://github.com/release-engineering/ubi-population-tool/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.13.0...0.14.0
[0.13.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.12.0...0.13.0
[0.12.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.11.0...0.12.0
[0.11.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.10.0...0.11.0
[0.10.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.9.0...0.10.0
[0.9.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.8.0...0.9.0
[0.8.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.7.0...0.8.0
[0.7.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.6.0...0.7.0
[0.6.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.5.0...0.6.0
[0.5.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.4.0...0.5.0
[0.4.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.3.1...0.4.0
[0.3.1]: https://github.com/release-engineering/ubi-population-tool/compare/v0.3.0...0.3.1
[0.3.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.2.0...0.3.0
[0.2.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.1.19...v0.2.0 
[0.1.19]: https://github.com/release-engineering/ubi-population-tool/compare/v0.1.18...v0.1.19
