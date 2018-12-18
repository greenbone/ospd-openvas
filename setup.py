# -*- coding: utf-8 -*-
# Description:
# Setup for the OSP openvas Server
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

from ospd_openvas import __version__

setup(
    name='ospd-openvas',
    version=__version__,

    packages=['ospd_openvas'],

    url='http://www.openvas.org',
    author='Greenbone Networks GmbH',
    author_email='info@greenbone.net',

    license='GPLV2+',
    python_requires='>=3.5',
    install_requires=['ospd>=1.4b1', 'ospd<=1.5.0', 'redis', 'psutil'],

    entry_points={
        'console_scripts': ['ospd-openvas=ospd_openvas.wrapper:main'],
    },

    test_suite="tests",
)
