![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# ospd <!-- omit in toc -->

[![GitHub releases](https://img.shields.io/github/release/greenbone/ospd.svg)](https://github.com/greenbone/ospd/releases)
[![PyPI](https://img.shields.io/pypi/v/ospd.svg)](https://pypi.org/project/ospd/)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/greenbone/ospd/badges/quality-score.png?b=ospd-20.08)](https://scrutinizer-ci.com/g/greenbone/ospd/?branch=ospd-20.08)
[![code test coverage](https://codecov.io/gh/greenbone/ospd/branch/ospd-20.08/graphs/badge.svg)](https://codecov.io/gh/greenbone/ospd)
[![CircleCI](https://circleci.com/gh/greenbone/ospd/tree/ospd-20.08.svg?style=svg)](https://circleci.com/gh/greenbone/ospd/tree/ospd-20.08)

ospd is a base class for scanner wrappers which share the same communication
protocol: OSP (Open Scanner Protocol). OSP creates a unified interface for
different security scanners and makes their control flow and scan results
consistently available under the central Greenbone Vulnerability Manager service.

OSP is similar in many ways to GMP (Greenbone Management Protocol): XML-based,
stateless and non-permanent connection.

The design supports wrapping arbitrary scanners with same protocol OSP,
sharing the core daemon options while adding scanner specific parameters and
options.

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Releases](#releases)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Install using pip](#install-using-pip)
- [How to write your own OSP Scanner Wrapper](#how-to-write-your-own-osp-scanner-wrapper)
- [Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)

## Releases
￼
All [release files](https://github.com/greenbone/ospd/releases) are signed with
the [Greenbone Community Feed integrity key](https://community.greenbone.net/t/gcf-managing-the-digital-signatures/101).
This gpg key can be downloaded at https://www.greenbone.net/GBCommunitySigningKey.asc
and the fingerprint is `8AE4 BE42 9B60 A59B 311C  2E73 9823 FAA6 0ED1 E580`.

## Installation

### Requirements

ospd requires Python >= 3.5 along with the following libraries:

    - python3-paramiko

    - python3-lxml

    - python3-defusedxml

### Install using pip

You can install ospd from the Python Package Index using [pip](https://pip.pypa.io/):

    python3 -m pip install ospd

Alternatively download or clone this repository and install the latest development version:

    python3 -m pip install .

## How to write your own OSP Scanner Wrapper

As a core you need to derive from the class OSPDaemon from ospd.py.
See the documentation there for the single steps to establish the
full wrapper.

See the file [doc/INSTALL-ospd-scanner.md](doc/INSTALL-ospd-scanner.md) about how to register a OSP scanner at
the Greenbone Vulnerability Manager which will automatically establish a full
GUI integration for the Greenbone Security Assistant (GSA).

There are some online resources about this topic:
<https://docs.greenbone.net/GSM-Manual/gos-3.1/en/osp.html#how-to-write-your-own-osp-wrapper>

## Support

For any question on the usage of OSPD please use the [Greenbone Community Portal](https://community.greenbone.net/c/osp). If you found a problem with the software, please [create an issue](https://github.com/greenbone/ospd/issues) on GitHub.

## Maintainer

This project is maintained by [Greenbone Networks GmbH](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull request](https://github.com/greenbone/ospd/pulls) on GitHub. For bigger changes, please discuss it first in the [issues](https://github.com/greenbone/ospd/issues).

For development you should use [poetry](https://python-poetry.org)
to keep you python packages separated in different environments. First install
poetry via pip

    python3 -m pip install --user poetry

Afterwards run

    poetry install

in the checkout directory of ospd (the directory containing the
`pyproject.toml` file) to install all dependencies including the packages only
required for development.

The ospd repository uses [autohooks](https://github.com/greenbone/autohooks)
to apply linting and auto formatting via git hooks. Please ensure the git hooks
are active.

    poetry install
    poetry run autohooks activate --force

## License

Copyright (C) 2009-2020 [Greenbone Networks GmbH](https://www.greenbone.net/)

Licensed under the [GNU Affero General Public License v3.0 or later](COPYING).
