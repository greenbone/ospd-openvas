![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# ospd-openvas

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/greenbone/ospd-openvas/badges/quality-score.png?b=ospd-openvas-1.0)](https://scrutinizer-ci.com/g/greenbone/ospd-openvas/?branch=ospd-openvas-1.0)

This is an OSP server implementation to allow GVM to remotely control
OpenVAS, see <https://github.com/greenbone/openvas>.

Once running, you need to configure the Scanner for the Greenbone Vulnerability
Manager, for example via the web interface Greenbone Security Assistant. Then
you can create scan tasks to use this scanner.

## Releases
￼
All [release files](https://github.com/greenbone/ospd-openvas/releases) are signed with
the [Greenbone Community Feed integrity key](https://community.greenbone.net/t/gcf-managing-the-digital-signatures/101).
This gpg key can be downloaded at https://www.greenbone.net/GBCommunitySigningKey.asc
and the fingerprint is `8AE4 BE42 9B60 A59B 311C  2E73 9823 FAA6 0ED1 E580`.

## Installation

### Requirements

Python 3.5 and later is supported.

Beyond the [ospd base library](https://github.com/greenbone/ospd),
`ospd-openvas` has dependencies on the following Python packages:

- `redis`
- `psutil`

There are no special installation aspects for this module beyond the general
installation guide for ospd-based scanners.

Please follow the general installation guide for ospd-based scanners:

  <https://github.com/greenbone/ospd/blob/master/doc/INSTALL-ospd-scanner.md>

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

For development you should use [pipenv](https://pipenv.readthedocs.io/en/latest/)
to keep you python packages separated in different environments. First install
pipenv via pip

    pip install --user pipenv

Afterwards run

    pipenv install --dev

in the checkout directory of ospd-openvas (the directory containing the Pipfile)
to install all dependencies including the packages only required for
development.

## License

Copyright (C) 2019 [Greenbone Networks GmbH](https://www.greenbone.net/)

Licensed under the [GNU General Public License v2.0 or later](COPYING).
