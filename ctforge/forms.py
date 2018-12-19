#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, HiddenField, IntegerField, FloatField, BooleanField, TextAreaField, DateTimeField, validators

class LoginForm(FlaskForm):
    mail = StringField('mail', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])

class RegistrationForm(FlaskForm):
    regkey = StringField('Registration Token', validators=[validators.DataRequired()])
    name = StringField('Name', validators=[validators.DataRequired()])
    surname = StringField('Surname', validators=[validators.DataRequired()])
    nickname = StringField('Nickname', validators=[validators.Optional()])
    mail = StringField('Mail', validators=[validators.DataRequired()])
    # affiliation = StringField('affiliation', validators=[validators.Optional()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    password_ver = PasswordField('Password (Verification)', validators=[validators.DataRequired()])


class ServiceFlagForm(FlaskForm):
    team_token = HiddenField('team_token', validators=[validators.DataRequired()])
    flag = StringField('flag', validators=[validators.DataRequired()])

class ChallengeFlagForm(FlaskForm):
    flag = StringField('flag', validators=[validators.DataRequired()])

class ServiceForm(FlaskForm):
    name = StringField('name', validators=[validators.DataRequired()])
    flag_lifespan = IntegerField('flag_lifespan', validators=[validators.DataRequired(), validators.NumberRange(message='Flag lifespan should be at least 1.', min=1)])
    flag_id = BooleanField('flag_id')
    description = TextAreaField('description', validators=[validators.DataRequired()])
    active = BooleanField('active')

class ChallengeForm(FlaskForm):
    name = StringField('name', validators=[validators.DataRequired()])
    description = TextAreaField('description', validators=[validators.DataRequired()])
    flag = StringField('flag', validators=[validators.DataRequired()])
    points = FloatField('points')
    tags = StringField('tags', validators=[validators.DataRequired()])
    active = BooleanField('active')
    hidden = BooleanField('hidden', default=True)
    writeup = BooleanField('writeup')
    writeup_template = TextAreaField('writeup_template')

class ChallengeWriteupForm(FlaskForm):
    writeup = TextAreaField('writeup', validators=[validators.DataRequired()])

class AdminWriteupForm(FlaskForm):
    mail = StringField('mail', render_kw={'disabled': True})
    name = StringField('name', render_kw={'disabled': True})
    surname = StringField('surname', render_kw={'disabled': True})
    nickname = StringField('nickname', render_kw={'disabled': True})
    challenge = StringField('challenge', render_kw={'disabled': True})
    timestamp = StringField('timestamp', render_kw={'disabled': True})
    writeup = TextAreaField('writeup', render_kw={'disabled': True})
    grade = FloatField('grade', validators=[validators.Optional()]) #, validators.NumberRange(message='Grade should be between 0 and 10.', min=0, max=10)])
    feedback = TextAreaField('feedback')

class UserForm(FlaskForm):
    team_id = IntegerField('team_id', validators=[validators.Optional()])
    name = StringField('name', validators=[validators.DataRequired()])
    surname = StringField('surname', validators=[validators.DataRequired()])
    nickname = StringField('nickname', validators=[validators.DataRequired()])
    mail = StringField('mail', validators=[validators.DataRequired()])
    affiliation = StringField('affiliation', validators=[validators.Optional()])
    password = StringField('password')
    admin = BooleanField('admin')
    hidden = BooleanField('hidden')

class TeamForm(FlaskForm):
    ip = StringField('ip', validators=[validators.DataRequired()])
    name = StringField('name', validators=[validators.DataRequired()])
    token = StringField('token', validators=[validators.DataRequired()])
    poc = IntegerField('poc', validators=[validators.Optional()])

class JeopardyForm(FlaskForm):
    time_enabled = BooleanField('time_enabled', validators=[validators.Optional()])
    start_time = DateTimeField('start_time', validators=[validators.Optional()])
    end_time = DateTimeField('end_time', validators=[validators.Optional()])
    ctf_running = BooleanField('ctf_running', validators=[validators.Optional()])
