# -*- coding: utf-8 -*-
# Copyright (C) 2018-2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

from setuptools import setup
from codecs import open # To use a consistent encoding
from os import path

from ospd_openvas import __version__

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ospd-openvas',
    version=__version__,

    description=('This is an OSP server implementation to allow GVM '
                 'to remotely control OpenVAS'),
    long_description=long_description,
    long_description_content_type='text/markdown',

    packages=['ospd_openvas'],
    url='https://github.com/greenbone/ospd-openvas',
    author='Greenbone Networks GmbH',
    author_email='info@greenbone.net',
    license='GPLV2+',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        # 3 - Alpha
        # 4 - Beta
        # 5 - Production/Stable
        'Development Status :: 5 - Production/Stable',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.5',
    ],

    python_requires='>=3.5',
    install_requires=[
        'ospd>=2.0.0',
        'redis>=3.0.1',
        'psutil'
    ],

    entry_points={'console_scripts': ['ospd-openvas=ospd_openvas.daemon:main']},
    test_suite="tests",
)
