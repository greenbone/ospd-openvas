# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [20.8.0] (2020-08-11)

### Added
- Add solution method to solution of vt object. [#166](https://github.com/greenbone/ospd/pull/166)
- Add wait_for_children(). [#167](https://github.com/greenbone/ospd/pull/167)
- Extend osp to accept target options. [#194](https://github.com/greenbone/ospd/pull/194)
- Accept reverse_lookup_only and reverse_lookup_unify target's options. [#195](https://github.com/greenbone/ospd/pull/195)
- Add 'total' and 'sent' attributes to <vts> element for <get_vts> cmd response. [#206](https://github.com/greenbone/ospd/pull/206)
- Add new get_memory_usage command. [#207](https://github.com/greenbone/ospd/pull/207)
- Add lock-file-dir configuration option. [#218](https://github.com/greenbone/ospd/pull/218)
- Add details attribute to get_vts command. [#222](https://github.com/greenbone/ospd/pull/222)
- Add [pontos](https://github.com/greenbone/pontos) as dev dependency for
  managing the version information in ospd [#254](https://github.com/greenbone/ospd/pull/254)
- Add more info about scan progress with progress attribute in get_scans cmd. [#266](https://github.com/greenbone/ospd/pull/266)
- Add support for scan queuing
  [#278](https://github.com/greenbone/ospd/pull/278)
  [#279](https://github.com/greenbone/ospd/pull/279)
  [#281](https://github.com/greenbone/ospd/pull/281)
- Extend results with optional argument URI [#282](https://github.com/greenbone/ospd/pull/282)
- Add new scan status INTERRUPTED.
  [#288](https://github.com/greenbone/ospd/pull/288)
  [#289](https://github.com/greenbone/ospd/pull/289)
- Extend get_vts with attribute version_only and return the version [#291](https://github.com/greenbone/ospd/pull/291)
- Allow to set all openvas parameters which are not strict openvas only parameters via osp. [#301](https://github.com/greenbone/ospd/pull/301)

### Changes
- Modify __init__() method and use new syntax for super(). [#186](https://github.com/greenbone/ospd/pull/186)
- Create data manager and spawn new process to keep the vts dictionary. [#191](https://github.com/greenbone/ospd/pull/191)
- Update daemon start sequence. Run daemon.check before daemon.init now. [#197](https://github.com/greenbone/ospd/pull/197)
- Improve get_vts cmd response, sending the vts piece by piece.[#201](https://github.com/greenbone/ospd/pull/201)
- Start the server before initialize to respond to the client.[#209](https://github.com/greenbone/ospd/pull/209)
- Use an iterator to get the vts when get_vts cmd is called. [#216](https://github.com/greenbone/ospd/pull/216)
- Update license to AGPL-3.0+ [#241](https://github.com/greenbone/ospd/pull/241)
- Replaced pipenv with poetry for dependency management. `poetry install` works
  a bit different then `pipenv install`. It installs dev packages by default and
  also ospd in editable mode. This means after running poetry install ospd will
  directly be importable in the virtual python environment. [#252](https://github.com/greenbone/ospd/pull/252)
- Progress bar calculation does not take in account the dead hosts. [#266](https://github.com/greenbone/ospd/pull/266)
- Show progress as integer for get_scans. [#269](https://github.com/greenbone/ospd/pull/269)
- Make scan_id attribute mandatory for get_scans. [#270](https://github.com/greenbone/ospd/pull/270)
- Ignore subsequent SIGINT once inside exit_cleanup(). [#273](https://github.com/greenbone/ospd/pull/273)
- Simplify start_scan() [#275](https://github.com/greenbone/ospd/pull/275)
- Make ospd-openvas to shut down gracefully
  [#302](https://github.com/greenbone/ospd/pull/302)
  [#307](https://github.com/greenbone/ospd/pull/307)
- Do not add all params which are in the OSPD_PARAMS dict to the params which are set as scan preferences. [#305](https://github.com/greenbone/ospd/pull/305)

### Fixed
- Fix stop scan. Wait for the scan process to be stopped before delete it from the process table. [#204](https://github.com/greenbone/ospd/pull/204)
- Fix get_scanner_details(). [#210](https://github.com/greenbone/ospd/pull/210)
- Fix thread lib leak using daemon mode for python 3.7. [#272](https://github.com/greenbone/ospd/pull/272)
- Fix scan progress in which all hosts are dead or excluded. [#295](https://github.com/greenbone/ospd/pull/295)
- Stop all running scans before exiting [#303](https://github.com/greenbone/ospd/pull/303)
- Fix start of parallel queued task. [#304](https://github.com/greenbone/ospd/pull/304)
- Strip trailing commas from the target list. [#306](https://github.com/greenbone/ospd/pull/306)

### Removed
- Remove support for resume task. [#266](https://github.com/greenbone/ospd/pull/266)

[20.8.0]: https://github.com/greenbone/ospd/compare/ospd-2.0...ospd-20.08

## [2.0.1] (unreleased)

### Added
- Add clean_forgotten_scans(). [#171](https://github.com/greenbone/ospd/pull/171)
- Extend OSP with finished_hosts to improve resume task.  [#177](https://github.com/greenbone/ospd/pull/177)

### Changed
- Set loglevel to debug for some message. [#159](https://github.com/greenbone/ospd/pull/159)
- Improve error handling when stop a scan. [#163](https://github.com/greenbone/ospd/pull/163)
- Check the existence and status of an scan_id. [#179](https://github.com/greenbone/ospd/pull/179)

### Fixed
- Fix set permission in unix socket. [#157](https://github.com/greenbone/ospd/pull/157)
- Fix VT filter.  [#165](https://github.com/greenbone/ospd/pull/165)
- Remove from exclude_host list the hosts passed as finished too. [#183](https://github.com/greenbone/ospd/pull/183)

[2.0.1]: https://github.com/greenbone/ospd/compare/v2.0.0...ospd-2.0

## [2.0.0] (2019-10-11)

### Added
- Add OSP command get_vts and the vts dictionary. [#12](https://github.com/greenbone/ospd/pull/12) [#60](https://github.com/greenbone/ospd/pull/60) [#72](https://github.com/greenbone/ospd/pull/72) [#73](https://github.com/greenbone/ospd/pull/73) [#93](https://github.com/greenbone/ospd/pull/93)
- Add optional custom elements for VT information. [#15](https://github.com/greenbone/ospd/pull/15)
- Allow clients to choose TLS versions > 1.0. [#18](https://github.com/greenbone/ospd/pull/18)
- Add element "vts" to parameters for starting scans. [#19](https://github.com/greenbone/ospd/pull/19) [#26](https://github.com/greenbone/ospd/pull/26)
- Add dummy stop_scan method to be implemented in the wrapper. [#24](https://github.com/greenbone/ospd/pull/24) [#53](https://github.com/greenbone/ospd/pull/53) [#129](https://github.com/greenbone/ospd/pull/129)
- Extend OSP command get_vts with vt_params. [#28](https://github.com/greenbone/ospd/pull/28)
- Add vt_selection to start_scan command. [#31](https://github.com/greenbone/ospd/pull/31) [#58](https://github.com/greenbone/ospd/pull/58) [#105](https://github.com/greenbone/ospd/pull/105)
- Add support for multi-target task adding targets with their own port list, credentials and host list to start_scan command. [#34](https://github.com/greenbone/ospd/pull/34) [#38](https://github.com/greenbone/ospd/pull/38) [#39](https://github.com/greenbone/ospd/pull/39) [#41](https://github.com/greenbone/ospd/pull/41)) [#127](https://github.com/greenbone/ospd/pull/127) [#134](https://github.com/greenbone/ospd/pull/134)
- Add support for parallel scans. [#42](https://github.com/greenbone/ospd/pull/42) [#142](https://github.com/greenbone/ospd/pull/142)
- Add functions for port manipulation. [#44](https://github.com/greenbone/ospd/pull/44)
- Add <vtgroup> as subelement of <vts> in <start_scan>. [#45](https://github.com/greenbone/ospd/pull/45)
- Add pop_results attribute to <get_scans>. [#46](https://github.com/greenbone/ospd/pull/46)
- Add methods to set and get the vts feed version. [#79](https://github.com/greenbone/ospd/pull/79)
- Add cvss module. [#88](https://github.com/greenbone/ospd/pull/88)
- Add filter option to OSP get_vts command. [#94](https://github.com/greenbone/ospd/pull/94)
- Allows to set the logging domain from the wrapper. [#97](https://github.com/greenbone/ospd/pull/97)
- Add option for logging into a specified log file. [#98](https://github.com/greenbone/ospd/pull/98)
- Add option for logging into a specified log file. [#98](https://github.com/greenbone/ospd/pull/98)
- Add scans status to improve the progress and add support to resume tasks. [#100](https://github.com/greenbone/ospd/pull/) [#101](https://github.com/greenbone/ospd/pull/101) [#102](https://github.com/greenbone/ospd/pull/102) [#103](https://github.com/greenbone/ospd/pull/103)
- Add support for exclude hosts. [#107](https://github.com/greenbone/ospd/pull/107)
- Add hostname attribute to results. [#108](https://github.com/greenbone/ospd/pull/108)
- Add the --niceness option. [#109](https://github.com/greenbone/ospd/pull/109)
- Add support for configuration file. [#122](https://github.com/greenbone/ospd/pull/122)
- Add option to set unix socket mode permission. [#123](https://github.com/greenbone/ospd/pull/123)
- Add pid file creation to avoid having two daemons. [#126](https://github.com/greenbone/ospd/pull/126) [#128](https://github.com/greenbone/ospd/pull/128)
- Add OSP <get_performance> command. [#131](https://github.com/greenbone/ospd/pull/131) [#137](https://github.com/greenbone/ospd/pull/137)
- Add method to check if a target finished cleanly or crashed. [#133](https://github.com/greenbone/ospd/pull/133)
- Add the --stream-timeout option to configure the socket timeout. [#136](https://github.com/greenbone/ospd/pull/136)
- Add support to handle multiple requests simultaneously.
  [#136](https://github.com/greenbone/ospd/pull/136), [#139](https://github.com/greenbone/ospd/pull/139)

### Changed
- Improve documentation.
- Improve Unittest.
- Send the response data in block of given length instead of sending all at once. [#35](https://github.com/greenbone/ospd/pull/35)
- Makes the socket a non-blocking socket. [#78](https://github.com/greenbone/ospd/pull/78)
- Refactor misc. [#111](https://github.com/greenbone/ospd/pull/111)
- Refactor error module. [#95](https://github.com/greenbone/ospd/pull/95) [#112](https://github.com/greenbone/ospd/pull/112)
- Refactor ospd connection handling. [#114](https://github.com/greenbone/ospd/pull/114)
- Use ordered dictionary to maintain the results order. [#119](https://github.com/greenbone/ospd/pull/119)
- Refactor ospd. [#120](https://github.com/greenbone/ospd/pull/120)
- Set default unix socket path to /var/run/ospd/ospd.sock and default pid file path to /var/run/ospd.pid. [#140](https://github.com/greenbone/ospd/pull/140)
- Do not add a host detail result with the host status. [#145](https://github.com/greenbone/ospd/pull/145)
- Do not log the received command. [#151](https://github.com/greenbone/ospd/pull/151)

### Fixed
- Fix scan progress. [#47](https://github.com/greenbone/ospd/pull/47)
- Documentation has been improved.
- Improve connection handling. [#80](https://github.com/greenbone/ospd/pull/80)
- Fix target_to_ipv4_short(). [#99](https://github.com/greenbone/ospd/pull/99)
- Handle write error if the client disconnects abruptly. [#135](https://github.com/greenbone/ospd/pull/135)
- Improve error handling when sending data. [#147](https://github.com/greenbone/ospd/pull/147)
- Fix classifier in setup.py. [#154](https://github.com/greenbone/ospd/pull/154)

[2.0]: https://github.com/greenbone/ospd/compare/ospd-1.3...master


## [1.3] (2018-06-05)

### Added
- Support for unix sockets has been added.

### Removed
- OSP has been renamed to Open Scanner Protocol.

### Changed
- Support Python 3 only.
- Documentation has been updated.
