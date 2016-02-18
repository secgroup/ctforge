#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name='CTForge',
    version='0.1',
    description='Forge you own CTF',
    long_description=__doc__,
    license='MIT',
    author='Marco Squarcina',
    author_email='squarcina AT unive.it',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points = {
        'console_scripts': ['ctforge = ctforge.scripts.ctforge:main']
    },
    install_requires=[
        'Flask>=0.10.1',
        'Flask-Login>=0.3.2',
        'Flask-WTF>=0.12',
        'Flask-Cache>=0.13.1',
        'py-bcrypt>=0.4',
        'psycopg2>=2.6.1'
    ],
    classifiers=[
        'Private :: Do Not Upload'
    ]
)