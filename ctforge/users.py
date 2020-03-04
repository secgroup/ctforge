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


import time
from flask_login import UserMixin
from jose import jwt

from ctforge import app
from ctforge.database import get_db_connection

class User(UserMixin):
    def __init__(self, id, team_id, name, surname, nickname, mail, affiliation, password, admin, hidden):
        self.id = id
        self.team_id = team_id
        self.name = name
        self.surname = surname
        self.nickname = nickname
        self.mail = mail
        self.affiliation = affiliation
        self.password = password
        self.admin = admin
        self.hidden = hidden

    def get_id(self):
        return self.mail
 
    @staticmethod
    def get(mail):
        """Return a User instance by querying the database."""

        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute('SELECT * FROM users WHERE mail = %s', [mail])
            res = cur.fetchone()
            return User(**res) if res else None

    def generate_token(self):
        now = time.time()
        # standard claims from the JWT specification (https://tools.ietf.org/html/rfc7519)
        token = {
            'sub': self.mail,
            'exp': now + app.config['TOKEN_LIFESPAN'] * 3600,
            'iat': now
        }
        return jwt.encode(token, app.config['TOKEN_KEY'])

    @staticmethod
    def get_from_token(token):
        try:
            claims = jwt.decode(token, app.config['TOKEN_KEY'])
            return User.get(claims['sub'])
        except (jwt.JWTError, jwt.JWTClaimsError, jwt.ExpiredSignatureError):
            return None
