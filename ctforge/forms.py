#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask_wtf import Form
from wtforms import StringField, PasswordField, HiddenField, IntegerField, BooleanField, TextAreaField, validators

class LoginForm(Form):
    mail = StringField('mail', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])

class ServiceFlagForm(Form):
    team_token = HiddenField('team_token', validators=[validators.DataRequired()])
    flag = StringField('flag', validators=[validators.DataRequired()])

class ChallengeFlagForm(Form):
    flag = StringField('flag', validators=[validators.DataRequired()])

class ServiceForm(Form):
    name = StringField('name', validators=[validators.DataRequired()])
    description = TextAreaField('description', validators=[validators.DataRequired()])
    active = BooleanField('active')

class ChallengeForm(Form):
    name = StringField('name', validators=[validators.DataRequired()])
    description = TextAreaField('description', validators=[validators.DataRequired()])
    flag = StringField('flag', validators=[validators.DataRequired()])
    points = IntegerField('points', validators=[validators.NumberRange(message='Challenge points should be between 0 and 1000.', min=0, max=1000)])
    active = BooleanField('active')
    writeup = BooleanField('writeup')
    writeup_template = TextAreaField('writeup_template')

class ChallengeWriteupForm(Form):
    writeup = TextAreaField('writeup', validators=[validators.DataRequired()])

class AdminWriteupForm(Form):
    user = StringField('user', render_kw={'disabled': True})
    challenge = StringField('challenge', render_kw={'disabled': True})
    timestamp = StringField('timestamp', render_kw={'disabled': True})
    writeup = TextAreaField('writeup', render_kw={'disabled': True})
    grade = IntegerField('grade', validators=[validators.NumberRange(message='Grade should be between 0 and 10.', min=0, max=10)])
    feedback = TextAreaField('feedback')

class UserForm(Form):
    team_id = IntegerField('team_id', validators=[validators.Optional()])
    name = StringField('name', validators=[validators.DataRequired()])
    surname = StringField('surname', validators=[validators.DataRequired()])
    mail = StringField('mail', validators=[validators.DataRequired()])
    password = StringField('password')
    admin = BooleanField('admin')
    hidden = BooleanField('hidden')

class TeamForm(Form):
    ip = StringField('ip', validators=[validators.DataRequired()])
    name = StringField('name', validators=[validators.DataRequired()])
    token = StringField('token', validators=[validators.DataRequired()])
    poc = IntegerField('poc', validators=[validators.Optional()])