# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- n/a

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

[Unreleased]: https://github.com/release-engineering/ubi-population-tool/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.3.1...0.4.0
[0.3.1]: https://github.com/release-engineering/ubi-population-tool/compare/v0.3.0...0.3.1
[0.3.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.2.0...0.3.0
[0.2.0]: https://github.com/release-engineering/ubi-population-tool/compare/v0.1.19...v0.2.0 
[0.1.19]: https://github.com/release-engineering/ubi-population-tool/compare/v0.1.18...v0.1.19
