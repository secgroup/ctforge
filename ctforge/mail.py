#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# CTForge: Forge your own CTF.

# Copyright (C) 2016-2020  Marco Squarcina
# Copyright (C) 2016-2020  Mauro Tempesta
# Copyright (C) 2016-2020  Lorenzo Veronese

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

import smtplib
import unicodedata
import urllib.parse

from ctforge import app
from ctforge.exceptions import MailFailure

def send_email(from_email, from_password, to_email, email_text):
    if from_email is None or from_password is None:
        raise MailFailure('Email is not properly configured')
    email_text = unicodedata.normalize('NFKD', email_text).encode('ascii', 'ignore')
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, email_text)
        server.close()
        print('Email to {} has been successfully sent!'.format(to_email))
    except Exception as e:
        raise MailFailure('Error while sending email to {}: {}'.format(to_email, e))

def send_password_reset_link(user):
    link = urllib.parse.urljoin(app.config['URL'], '/reset/'+user.generate_token())
    email_text = (
        'From: {sender}+noreply\n'
        'To: {receiver}\n'
        'Subject: Password reset requested\n\n'
        'Hi {name},\n'
        'Please click on the link below to reset the password of your account:\n\n{link}\n\n'
        'Please ignore this email if you did not request to reset your password.\n\n'
        'Cheers,\nThe WUTCTF organizers'
    ).format(sender=app.config['MAIL_ADDRESS'], receiver=user.mail, name=user.name, link=link)
    send_email(app.config['MAIL_ADDRESS'], app.config['MAIL_PASSWORD'], user.mail, email_text)

def send_activation_link(user):
    link = urllib.parse.urljoin(app.config['URL'], '/activate/'+user.generate_token())
    email_text = (
        'From: {sender}+noreply\n'
        'To: {receiver}\n'
        'Subject: Account activation\n\n'
        'Hi {name},\n'
        'Welcome to WUTCTF! Please click on the link below to activate your account:\n\n{link}\n\n'
        'Keep in mind that your nickname is public! Choose wisely and avoid bad words ;)\n'
        'In case of problems, don\'t hesitate to contact us.\n\n'
        'Cheers,\nThe WUTCTF organizers'
    ).format(sender=app.config['MAIL_ADDRESS'], receiver=user.mail, name=user.name, link=link)
    send_email(app.config['MAIL_ADDRESS'], app.config['MAIL_PASSWORD'], user.mail, email_text)
