#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import string
import configparser

from flask import flash

def parse_conf(fname):
    # load default config
    try:
        # parse the configuration file
        config = configparser.ConfigParser()
        config.read(fname)
        return dict(
            DB_HOST = config.get('database', 'host', fallback='127.0.0.1'),
            DB_PORT = config.getint('database', 'port', fallback=5432),
            DB_NAME = config.get('database', 'name', fallback='ctforge'),
            DB_USER = config.get('database', 'user', fallback='ctforge'),
            DB_PASSWORD = config.get('database', 'password', fallback='ctforge'),

            JEOPARDY_ACTIVE = config.getboolean('mode_jeopardy', 'active', fallback=True),

            ATTACKDEFENSE_ACTIVE = config.getboolean('mode_attackdefense', 'active', fallback=False),
            ROUND_DURATION = config.getint('mode_attackdefense', 'round_duration', fallback=300),
            FLAG_PREFIX = config.get('mode_attackdefense', 'flag_prefix', fallback='flg{'),
            FLAG_SUFFIX = config.get('mode_attackdefense', 'flag_suffix', fallback='}'),
            FLAG_CHARS = config.get('mode_attackdefense', 'flag_chars', fallback=string.ascii_letters + string.digits),
            FLAG_LENGTH = config.getint('mode_attackdefense', 'flag_length', fallback=25),
            FLAG_REGEXP = config.get('mode_attackdefense', 'flag_regexp', fallback='flg\{[a-zA-Z0-9]{25}\}'),

            STATIC_FOLDER = config.get('website', 'static_folder', fallback='static'),
            TEMPLATE_FOLDER = config.get('website', 'template_folder', fallback='templates'),
            URL = config.get('website', 'url', fallback='http://localhost:5000/'),
            DATE_START = config.get('website', 'date_start', fallback='2016-01-01 00:00:00.0'),
            DEBUG = config.getboolean('website', 'debug', fallback=False),
            SESSION_COOKIE_SECURE = config.getboolean('website', 'secure_cookie', fallback=False),
            LOG_FILE = config.get('website', 'log_file', fallback=None),
            SECRET_KEY = config.get('website', 'secret_key', fallback='ChengeMeWithRandomStuffASAP')
        )
    except (configparser.NoOptionError, configparser.NoSectionError) as e:
        sys.stderr.write('Malformed configuration file, aborting: {}\n'.format(e))
        sys.exit(1)

def flash_errors(form):
    """Handle form errors via flash messages."""

    for field, errors in form.errors.items():
        for error in errors:
            msg = 'Error in the {} field: {}'.format(
                  getattr(form, field).label.text, error)
            flash(msg, 'error')
