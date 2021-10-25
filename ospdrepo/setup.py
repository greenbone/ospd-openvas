# Copyright (C) 2014-2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# pylint: disable=invalid-name

""" Setup configuration and management for module ospd
Standard Python setup configuration, including support for PyPI.
"""

from os import path

from setuptools import (
    setup,
    find_packages,
)  # Always prefer setuptools over distutils

from ospd import __version__

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ospd',
    # Versions should comply with PEP440. For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # http://packaging.python.org/en/latest/tutorial.html#version
    version=__version__,
    description=(
        'OSPD is a base for scanner wrappers which share the '
        'same communication protocol: OSP (Open Scanner '
        'Protocol)'
    ),
    long_description=long_description,
    long_description_content_type='text/markdown',
    # The project's main homepage.
    url='http://www.openvas.org',
    # Author
    author='Greenbone Networks GmbH',
    author_email='info@greenbone.net',
    # License
    license='GPLv2+',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        # 3 - Alpha
        # 4 - Beta
        # 5 - Production/Stable
        'Development Status :: 4 - Beta',
        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',  # pylint: disable=line-too-long
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    # What does your project relate to?
    keywords=['Greenbone Vulnerability Manager OSP'],
    python_requires='>=3.7',
    # List run-time dependencies here. These will be installed by pip when your
    # project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/technical.html#install-requires-vs-requirements-files
    install_requires=['paramiko', 'defusedxml', 'lxml', 'deprecated', 'psutil'],
    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=['tests*']),
    # If there are data files included in your packages that need to be
    # installed, specify them here.
    include_package_data=True,
    package_data={'': []},
    # Scripts. Define scripts here which should be installed in the
    # sys.prefix/bin directory. You can define an alternative place for
    # installation by setting the --install-scripts option of setup.py
    # scripts = [''],
    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    # entry_points={
    #    'console_scripts': [
    #        'sample=sample:main',
    #    ],
    # },
    test_suite="tests",
)
