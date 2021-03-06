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


import sys
import psycopg2
from flask import g, flash

from ctforge import app


def get_db_connection():
    """Initialize a connection to the database."""

    db_conn = getattr(g, 'db_conn', None)
    if db_conn is None:
        try:
            g.db_conn = db_connect()
            g.db_conn.autocommit = True
            db_conn = g.db_conn
        except psycopg2.Error as e:
            app.logger.critical('Unable to connect to the database: {}'.format(e))
            sys.exit(1)
    return db_conn

def db_connect(database=None, logger=app.logger):
    try:
        db_conn = psycopg2.connect(
            host=app.config['DB_HOST'],
            user=app.config['DB_USER'],
            password=app.config['DB_PASSWORD'],
            database=app.config['DB_NAME'] if database is None else database,
            port=app.config['DB_PORT'],
            cursor_factory=psycopg2.extras.RealDictCursor)
    except psycopg2.Error as e:
        logger.critical('Unable to connect to the database: {}'.format(e))
        sys.exit(1)
    return db_conn

@app.teardown_appcontext
def db_disconnect(exception=None, logger=app.logger):
    """Disconnect from the database."""

    try:
        db_conn = getattr(g, 'db_conn', None)
        if db_conn is not None:
            db_conn.close()
    except Exception as e:
        logger.critical('Unable to close the database connection: {}'.format(e))
        sys.exit(1)

def query_handler(query, data):
    """Handle UPDATE and INSERT queries in the admin panel."""

    try:
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute(query, data)
        flash('Operation successfully completed', 'success')
    except psycopg2.Error as e:
        db_conn.rollback()
        flash('Error: {}'.format(e), 'error')
