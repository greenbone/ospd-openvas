# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.1] (unreleased)

### Changed
- Exit with exit code 1 if it was not possible to connect to redis. [#133](https://github.com/greenbone/ospd-openvas/pull/133)
- Return None if the scan finished successfully. [#137](https://github.com/greenbone/ospd-openvas/pull/137)

### Added
- Check the vt's preference value for type 'file'. [#130](https://github.com/greenbone/ospd-openvas/pull/130).

### Fixed
- Improve redis clean out when stopping a scan. [#128](https://github.com/greenbone/ospd-openvas/pull/128)
- Improve error handling when creating vts xml elements. [#139](https://github.com/greenbone/ospd-openvas/pull/139)
- Init the superclass with kwargs. [#141](https://github.com/greenbone/ospd-openvas/pull/141)
- Avoid ospd-openvas to crash if redis is flushed during vt dictionary creation. [#146](https://github.com/greenbone/ospd-openvas/pull/146)

[1.0.1]: https://github.com/greenbone/ospd-openvas/commits/v1.0.0...ospd-openvas-1.0

## [1.0.0] (2019-10-11)

This is the first release of the ospd-openvas module for the Greenbone
Vulnerability Management (GVM) framework.

[1.0.0]: https://github.com/greenbone/ospd-openvas/commits/v1.0.0
