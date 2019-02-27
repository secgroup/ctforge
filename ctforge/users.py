#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask_login import UserMixin

from ctforge.database import get_db_connection

class User(UserMixin):
    def __init__(self, id, team_id, name, surname, token, nickname, mail, affiliation, password, active, admin, hidden):
        self.id = id
        self.team_id = team_id
        self.name = name
        self.surname = surname
        self.nickname = nickname
        self.token = token
        self.mail = mail
        self.affiliation = affiliation
        self.password = password
        self.active = active
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
