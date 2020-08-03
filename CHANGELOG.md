# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [21.4] (unreleased)
- Get all results from main kb. [#285](https://github.com/greenbone/ospd-openvas/pull/285)

[unreleased]: https://github.com/greenbone/ospd-openvas/compare/ospd-openvas-20.08...master


## [20.8] (unreleased)

### Added
- Add solution method to solution of vt object. [#131](https://github.com/greenbone/ospd-openvas/pull/131)
- Add typing to daemon.py, nvticache.py and db.py. [#161](https://github.com/greenbone/ospd-openvas/pull/161)[#162](https://github.com/greenbone/ospd-openvas/pull/162)[#163](https://github.com/greenbone/ospd-openvas/pull/163)
- Add support for alive test settings. [#182](https://github.com/greenbone/ospd-openvas/pull/182)
- Add missing scan preferences expand_vhosts and test_empty_vhost. [#184](https://github.com/greenbone/ospd-openvas/pull/184)
- Set reverse lookup options. [#185](https://github.com/greenbone/ospd-openvas/pull/185)
- Check if the amount of vts in redis is coherent.
  [#195](https://github.com/greenbone/ospd-openvas/pull/195)
  [#197](https://github.com/greenbone/ospd-openvas/pull/197)
- Add support for test_alive_hosts_only feature of openvas. [#204](https://github.com/greenbone/ospd-openvas/pull/204)
- Use lock file during feed update to avoid corrupted cache. [#207](https://github.com/greenbone/ospd-openvas/pull/207)
- Add details parameter to get_vt_iterator(). [#215](https://github.com/greenbone/ospd-openvas/pull/215)
- Add [pontos](https://github.com/greenbone/pontos) as dev dependency for
  managing the version information in ospd-openvas [#238](https://github.com/greenbone/ospd-openvas/pull/238)
- Pass store directory to OSPDaemon init [#266](https://github.com/greenbone/ospd-openvas/pull/266)
- Add URI field to results for file path or webservice URL [#271](https://github.com/greenbone/ospd-openvas/pull/271)
- Add element to OSPD_PARAMS entries to indicate visibility for client. [#293](https://github.com/greenbone/ospd-openvas/pull/293)

### Changed
- Less strict checks for the nvti cache version
  [#150](https://github.com/greenbone/ospd-openvas/pull/150)
  [#165](https://github.com/greenbone/ospd-openvas/pull/165)
  [#166](https://github.com/greenbone/ospd-openvas/pull/166)
- Set self.vts to None if there is a pending feed. [#172](https://github.com/greenbone/ospd-openvas/pull/172)
- Use the new method clear() from Vts class. [#193](https://github.com/greenbone/ospd-openvas/pull/193)
- Start server before initialize the vts. [#196](https://github.com/greenbone/ospd-openvas/pull/196)
- Get vts metadata from redis and reduce stored data in cache. [#205](https://github.com/greenbone/ospd-openvas/pull/205)
- Update license to AGPL-3.0+ [#228](https://github.com/greenbone/ospd-openvas/pull/228)
- Replaced pipenv with poetry for dependency management. `poetry install` works
  a bit different then `pipenv install`. It installs dev packages by default and
  also ospd in editable mode. This means after running poetry install ospd will
  directly be importable in the virtual python environment. [#235](https://github.com/greenbone/ospd-openvas/pull/235)
- Don't send host details and log messages to the client when Boreas is enabled. [#252](https://github.com/greenbone/ospd-openvas/pull/252)
- Progress bar calculation do not takes in account dead hosts. [#252](https://github.com/greenbone/ospd-openvas/pull/252)
- Host progress is stored as integer. [#256](https://github.com/greenbone/ospd-openvas/pull/256)
- Use flock for the feed lock file. [#257](https://github.com/greenbone/ospd-openvas/pull/257)
- Improvements for fetching results from redis. [#282](https://github.com/greenbone/ospd-openvas/pull/282)
- Add RW permission to the group on the feed lock file.
  [#300](https://github.com/greenbone/ospd-openvas/pull/300)
  [#301](https://github.com/greenbone/ospd-openvas/pull/301)

### Fixed
- Check vt_aux for None before trying to access it. [#177](https://github.com/greenbone/ospd-openvas/pull/177)
- Fix snmp credentials. [#186](https://github.com/greenbone/ospd-openvas/pull/186)
- Escape script name before adding the result in an xml entity. [#188](https://github.com/greenbone/ospd-openvas/pull/188)
- Fix handling of denied hosts. [#263](https://github.com/greenbone/ospd-openvas/pull/263)
- Fix handling of special chars in credentials. [#294](https://github.com/greenbone/ospd-openvas/pull/294)
- Fix type and default value of optimize_test preference. [#302](https://github.com/greenbone/ospd-openvas/pull/302)

### Removed
- Remove use_mac_addr, vhost_ip and vhost scan preferences. [#184](https://github.com/greenbone/ospd-openvas/pull/184)
- Handling of finished host for resume task. [#252](https://github.com/greenbone/ospd-openvas/pull/252)
- Don't release vts explicitly. [#261](https://github.com/greenbone/ospd-openvas/pull/261)
- Drop handling of network_scan. [#265](https://github.com/greenbone/ospd-openvas/pull/265)

## [1.0.1] (unreleased)

### Added
- Check the vt's preference value for type 'file'. [#130](https://github.com/greenbone/ospd-openvas/pull/130).
- Check for malformed credentials. [#160](https://github.com/greenbone/ospd-openvas/pull/160).
- Send messages generated by the scannner main process. [#171](https://github.com/greenbone/ospd-openvas/pull/171).

### Changed
- Exit with exit code 1 if it was not possible to connect to redis. [#133](https://github.com/greenbone/ospd-openvas/pull/133)
- Return None if the scan finished successfully. [#137](https://github.com/greenbone/ospd-openvas/pull/137)

### Fixed
- Improve redis clean out when stopping a scan. [#128](https://github.com/greenbone/ospd-openvas/pull/128)
- Improve error handling when creating vts xml elements. [#139](https://github.com/greenbone/ospd-openvas/pull/139)
- Init the superclass with kwargs. [#141](https://github.com/greenbone/ospd-openvas/pull/141)
- Avoid ospd-openvas to crash if redis is flushed during vt dictionary creation. [#146](https://github.com/greenbone/ospd-openvas/pull/146)

[1.0.1]: https://github.com/greenbone/ospd-openvas/compare/v1.0.0...ospd-openvas-1.0

## [1.0.0] (2019-10-11)

This is the first release of the ospd-openvas module for the Greenbone
Vulnerability Management (GVM) framework.

[1.0.0]: https://github.com/greenbone/ospd-openvas/compare/v1.0.0
