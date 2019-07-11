#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# CTForge: Forge your own CTF.

# Copyright (C) 2016-2019  Marco Squarcina
# Copyright (C) 2016-2019  Mauro Tempesta
# Copyright (C) 2016-2019  Lorenzo Veronese

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


from setuptools import setup, find_packages

setup(
    name='CTForge',
    version='0.8',
    description='Forge you own CTF',
    long_description=__doc__,
    license='MIT',
    author='Marco Squarcina',
    author_email='squarcina AT unive.it',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points = {
        'console_scripts': [
            'ctforge = ctforge.scripts.ctforge:main',
            'ctfbot = ctforge.scripts.ctfbot:main'
        ]
    },
    install_requires=[
        'Flask>=0.10.1',
        'Flask-Login>=0.3.2',
        'Flask-WTF>=0.12',
        'Flask-Cache>=0.13.1',
        'Flask-Misaka>=0.4.1',
        'py-bcrypt>=0.4',
        'psycopg2>=2.6.1'
    ],
    classifiers=[
        'Private :: Do Not Upload'
    ]
)
