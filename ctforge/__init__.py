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


import os
import sys
import logging
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_misaka import Misaka
from flask_cache import Cache
from flask_behind_proxy import FlaskBehindProxy

from ctforge import utils


__author__      = "Marco Squarcina"
__credits__     = ["Francesco Palmarini", "Marco Squarcina", "Mauro Tempesta", "Lorenzo Veronese"]
__license__     = "MIT"
__copyright__   = "Copyright 2014-17, University of Venice"
__maintainer__  = "Marco Squarcina"
__email__       = "squarcina@unive.it"

# parse the configuration file
try:
    user_config_file = os.path.expanduser('~/.ctforge/ctforge.conf')
    config_file = user_config_file if os.path.isfile(user_config_file) else 'ctforge.conf'
    config = utils.parse_conf(config_file)
except Exception:
    import traceback
    traceback.print_exc()
    pass

app = Flask(__name__, static_folder=config['STATIC_FOLDER'], 
                     template_folder=config['TEMPLATE_FOLDER'])
app.config.update(config)
app = FlaskBehindProxy(app)

login_manager = LoginManager()
login_manager.init_app(app)

csrf = CSRFProtect()
csrf.init_app(app)

md = Misaka(html=False, fenced_code=True)
md.init_app(app)

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
