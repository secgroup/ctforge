#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_cache import Cache

from ctforge import utils


__author__      = "Marco Squarcina"
__credits__     = ["Francesco Palmarini", "Marco Squarcina", "Mauro Tempesta"]
__license__     = "MIT"
__copyright__   = "Copyright 2014-16, University of Venice"
__maintainer__  = "Marco Squarcina"
__email__       = "squarcina@unive.it"

# parse the configuration file
try:
    user_config_file = os.path.expanduser('~/.ctforge/ctforge.conf')
    config_file = user_config_file if os.path.isfile(user_config_file) else 'ctforge.conf'
    config = utils.parse_conf(config_file)
except Exception:
    pass

app = Flask(__name__, static_folder=config['STATIC_FOLDER'], 
                     template_folder=config['TEMPLATE_FOLDER'])
app.config.update(config)

login_manager = LoginManager()
login_manager.init_app(app)

csrf = CSRFProtect()
csrf.init_app(app)

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# initialize the logging system
if app.config['LOG_FILE'] is not None:
    try:
        logfile = app.config['LOG_FILE']
        file_handler = logging.FileHandler(logfile)
        file_handler.setFormatter(logging.Formatter((
            '-'*90,
            'Message type:       %(levelname)s',
            'Location:           %(pathname)s:%(lineno)d',
            'Module:             %(module)s',
            'Function:           %(funcName)s',
            'Time:               %(asctime)s',
            'Message: %(message)s')))
        file_handler.setLevel(logging.WARNING)
        app.logger.addHandler(file_handler)
    except (FileNotFoundError, PermissionError) as e:
        sys.stderr.write('[!] Unable to access the log file {}\n'.format(logfile))

import ctforge.views
