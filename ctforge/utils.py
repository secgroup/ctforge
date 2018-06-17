#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import string
import random
import datetime
import configparser
import os.path

from flask import flash

def parse_conf(fname):
    # load default config
    try:
        # parse the configuration file
        config = configparser.ConfigParser()
        config.read(fname)
        conf = dict(
            DB_HOST = config.get('database', 'host', fallback='127.0.0.1'),
            DB_PORT = config.getint('database', 'port', fallback=5432),
            DB_NAME = config.get('database', 'name', fallback='ctforge'),
            DB_USER = config.get('database', 'user', fallback='ctforge'),
            DB_PASSWORD = config.get('database', 'password', fallback='ctforge'),

            SHOW_NAMES = config.getboolean('DEFAULT', 'show_names', fallback=True),

            JEOPARDY_ACTIVE = config.getboolean('mode_jeopardy', 'active', fallback=True),
            JEOPARDY_BONUS = config.getboolean('mode_jeopardy', 'bonus', fallback=True),

            ATTACKDEFENSE_ACTIVE = config.getboolean('mode_attackdefense', 'active', fallback=False),
            ROUND_DURATION = config.getint('mode_attackdefense', 'round_duration', fallback=300),
            FLAG_PREFIX = config.get('mode_attackdefense', 'flag_prefix', fallback='flg{'),
            FLAG_SUFFIX = config.get('mode_attackdefense', 'flag_suffix', fallback='}'),
            FLAG_CHARS = config.get('mode_attackdefense', 'flag_chars', fallback=string.ascii_letters + string.digits),
            FLAG_LENGTH = config.getint('mode_attackdefense', 'flag_length', fallback=25),
            FLAG_REGEXP = config.get('mode_attackdefense', 'flag_regexp', fallback='flg\{[a-zA-Z0-9]{25}\}'),

            STATIC_FOLDER = config.get('website', 'static_folder', fallback='themes/dctf2017/static'),
            TEMPLATE_FOLDER = config.get('website', 'template_folder', fallback='themes/dctf2017/templates'),
            URL = config.get('website', 'url', fallback='http://localhost:5000/'),
            DATE_START = datetime.datetime.strptime(config.get('website', 'date_start', fallback='2017-02-15 00:00:00.0'), "%Y-%m-%d %H:%M:%S.%f"),
            DEBUG = config.getboolean('website', 'debug', fallback=False),
            SESSION_COOKIE_SECURE = config.getboolean('website', 'secure_cookie', fallback=False),
            LOG_FILE = config.get('website', 'log_file', fallback=None),
            SECRET_KEY = config.get('website', 'secret_key', fallback='ChengeMeWithRandomStuffASAP'),
            BOT_LOG_FILE = config.get('flagbot', 'log_file', fallback=None),
            FLAGID_SCRIPT_PATH = config.get('flagbot', 'flagid_script_path', fallback='~/.ctforge/bot/flagid/'),
            DISPATCH_SCRIPT_PATH = config.get('flagbot', 'dispatch_script_path', fallback='~/.ctforge/bot/dispatch/'),
            CHECK_SCRIPT_PATH = config.get('flagbot', 'check_script_path', fallback='~/.ctforge/bot/check/')
        )
    except (configparser.NoOptionError, configparser.NoSectionError) as e:
        sys.stderr.write('Malformed configuration file, aborting: {}\n'.format(e))
        sys.exit(1)
    # expand home
    for k in ['LOG_FILE', 'BOT_LOG_FILE', 'DISPATCH_SCRIPT_PATH',
              'CHECK_SCRIPT_PATH', 'FLAGID_SCRIPT_PATH']:
        if conf[k] is not None:
            conf[k] = os.path.expanduser(conf[k])

    return conf

def flash_errors(form):
    """Handle form errors via flash messages."""

    for field, errors in form.errors.items():
        for error in errors:
            msg = 'Error in the {} field: {}'.format(
                  getattr(form, field).label.text, error)
            flash(msg, 'error')

def generate_flag(prefix, suffix, charset, length):
    """Generate a random flag according to the provided config."""

    return prefix + ''.join(random.choice(charset) for _ in range(length)) + suffix
