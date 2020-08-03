![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# ospd-openvas

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/greenbone/ospd-openvas/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/greenbone/ospd-openvas/?branch=master)

This is an OSP server implementation to allow GVM to remotely control
OpenVAS, see <https://github.com/greenbone/openvas>.

Once running, you need to configure OpenVAS for the Greenbone Vulnerability
Manager, for example via the web interface Greenbone Security Assistant. Then
you can create scan tasks to use OpenVAS.

## Installation

### Requirements

Python 3.5 and later is supported.

Beyond the [ospd base library](https://github.com/greenbone/ospd),
`ospd-openvas` has dependencies on the following Python packages:

- `redis`
- `psutil`
- `packaging`

There are no special installation aspects for this module beyond the general
installation guide for ospd-based scanners.

Please follow the general installation guide for ospd-based scanners:

  <https://github.com/greenbone/ospd/blob/master/doc/INSTALL-ospd-scanner.md>

### Optional configuration

Please note that although you can run `openvas` (launched from an `ospd-openvas`
process) as a user without elevated privileges, it is recommended that you start
`openvas` as `root` since a number of Network Vulnerability Tests (NVTs) require
root privileges to perform certain operations like packet forgery. If you run
`openvas` as a user without permission to perform these operations, your scan
results are likely to be incomplete.

As `openvas` will be launched from an `ospd-openvas` process with sudo,
the next configuration is required in the sudoers file:

    sudo visudo

add this line to allow the user running `ospd-openvas`, to launch `openvas`
with root permissions

    <user> ALL = NOPASSWD: <install prefix>/sbin/openvas

If you set an install prefix, you have to update the path in the sudoers
file too:

    Defaults        secure_path=<existing paths...>:<install prefix>/sbin

## Usage

There are no special usage aspects for this module beyond the generic usage
guide.

Please follow the general usage guide for ospd-based scanners:

  <https://github.com/greenbone/ospd/blob/master/doc/USAGE-ospd-scanner.md>

## Support

For any question on the usage of ospd-openvas please use the [Greenbone
Community Portal](https://community.greenbone.net/c/gse). If you found a problem
with the software, please [create an
issue](https://github.com/greenbone/ospd-openvas/issues) on GitHub. If you are a
Greenbone customer you may alternatively or additionally forward your issue to
the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone Networks
GmbH](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/ospd-openvas/pulls) on GitHub. Bigger
changes need to be discussed with the development team via the [issues section
at GitHub](https://github.com/greenbone/ospd-openvas/issues) first.

For development you should use [poetry](https://python-poetry.org)
to keep you python packages separated in different environments. First install
poetry via pip

    python3 -m pip install --user poetry

Afterwards run

    poetry install

in the checkout directory of ospd-openvas (the directory containing the
`pyproject.toml` file) to install all dependencies including the packages only
required for development.

The ospd-openvas repository uses [autohooks](https://github.com/greenbone/autohooks)
to apply linting and auto formatting via git hooks. Please ensure the git hooks
are active.

    poetry install
    poetry run autohooks activate --force

## License

Copyright (C) 2018-2019 [Greenbone Networks GmbH](https://www.greenbone.net/)

Licensed under the [GNU General Public License v2.0 or later](COPYING).
