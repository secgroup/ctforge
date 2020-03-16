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


import re
import bcrypt
import time
import json
import math
import base64
import psycopg2
import psycopg2.extras
from flask import request, render_template, redirect, url_for, flash, abort, jsonify
from flask_login import current_user, login_required, login_user, logout_user
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta

from ctforge import app, csrf, login_manager, cache
from ctforge.users import User
from ctforge.database import db_connect, get_db_connection, query_handler
from ctforge.utils import flash_errors
import ctforge.forms
import ctforge.exceptions
import ctforge.mail


@login_manager.user_loader
def load_user(mail):
    return User.get(mail)

def jeopardy_mode_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app.config['JEOPARDY_ACTIVE']:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

def attackdefense_mode_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app.config['ATTACKDEFENSE_ACTIVE']:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

def team_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.team_id is None:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.admin:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

# errors

@app.errorhandler(403)
def page_not_found(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500

@login_manager.unauthorized_handler
def unauthorized():
    abort(403)


# views

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = ctforge.forms.LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.get(form.mail.data)
            if user is not None and user.password is not None and bcrypt.checkpw(form.password.data, user.password):
                if login_user(user):
                    return redirect(url_for('index'))
                else:
                    flash('Could not log in', 'error')
            flash('Invalid mail or password', 'error')
            return redirect(url_for('login'))
        else:
            flash_errors(form)

    return render_template('login.html', form=form)

@app.route('/reset', methods=['POST', 'GET'])
def send_reset_token():
    form = ctforge.forms.PasswordResetEmailForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            # Get the user associated to the email
            user = User.get(form.mail.data)
            if user is None:
                flash('No user with the provided email address', 'error')
            else:
                try:
                    # send the link for activation or password reset depending on whether the
                    # account has already been activated or not
                    if user.password is None:
                        ctforge.mail.send_activation_link(user)
                    else:
                        ctforge.mail.send_password_reset_link(user)
                    flash('Mail sent!', 'success')
                    return redirect(url_for('index'))
                except ctforge.exceptions.MailFailure:
                    flash('A failure occurred when sending the email', 'error')
        else:
            flash_errors(form)

    return render_template('reset_mail.html', form=form)

@app.route('/reset/<token>', methods=['POST', 'GET'])
def pwd_reset(token=None):
    # get the user corresponding to the provided token
    # returns None when validation fails or the email does not exist
    user = User.get_from_token(token)
    if user is None:
        flash('Token invalid or expired', 'error')
        return redirect(url_for('index'))
    # redirect to the activation endpoint if the user is not active (i.e., no password is set)
    if user.password is None:
        return redirect(url_for('activate', token=token))

    # initialize the form
    form = ctforge.forms.PasswordResetForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            if form.password.data != form.password_ver.data:
                flash('Password mismatch, try again', 'error')
            else:
                db_conn = get_db_connection()
                try:
                    with db_conn.cursor() as cur:
                        cur.execute((
                            'UPDATE users SET password = %s WHERE id = %s'),
                            (bcrypt.hashpw(form.password.data, bcrypt.gensalt()), user.id))
                        flash('Password reset!', 'success')
                        return redirect(url_for('login'))
                except psycopg2.Error:
                    db_conn.rollback()
                    flash('Password reset failed, try again', 'error')
        else:
            flash_errors(form)

    return render_template('reset.html', form=form, token=token, mail=user.mail)

@app.route('/activate/<token>', methods=['POST', 'GET'])
def activate(token=None):
    # get the user corresponding to the provided token
    # returns None when validation fails or the email does not exist
    user = User.get_from_token(token)
    if user is None:
        flash('Token invalid or expired', 'error')
        return redirect(url_for('index'))
    # Error if the user is already active
    if user.password is not None:
        flash('Your account is already active', 'error')
        return redirect(url_for('index'))
    # initialize the form
    form = ctforge.forms.ActivateUserForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            if form.password.data != form.password_ver.data:
                flash('Password mismatch, try again', 'error')
            elif re.search('admin|r00t|root', form.nickname.data, flags=re.IGNORECASE):
                flash('Invalid nickname', 'error')
            else:
                db_conn = get_db_connection()
                try:
                    with db_conn.cursor() as cur:
                        cur.execute((
                            'UPDATE users SET nickname = %s, password = %s WHERE id = %s'),
                            (form.nickname.data, bcrypt.hashpw(form.password.data, bcrypt.gensalt()), user.id))
                        flash('User activated!', 'success')
                        return redirect(url_for('login'))
                except psycopg2.Error:
                    db_conn.rollback()
                    flash('Activation failed, try a different nickname', 'error')
        else:
            flash_errors(form)

    return render_template('activate.html', form=form, token=token, mail=user.mail)

# @app.route('/register', methods=['POST', 'GET'])
# def register():
#     form = ctforge.forms.RegistrationForm()
#     if request.method == 'POST':
#         if form.validate_on_submit():
#             if app.config['REGISTRATION_KEY'] != form.regkey.data:
#                 flash('Invalid registration token!', 'error')
#                 return redirect(url_for('register'))
#             if form.password.data != form.password_ver.data:
#                 flash('Wrong password!', 'error')
#                 return redirect(url_for('register'))
#
#             query_handler((
#                 'INSERT INTO users (name, surname, nickname, mail, password) '
#                 'VALUES (%s, %s, %s, %s, %s)'),
#                 (form.name.data, form.surname.data, form.nickname.data, form.mail.data,
#                  bcrypt.hashpw(form.password.data, bcrypt.gensalt())))
#             return redirect(url_for('index'))

#     return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out!', 'success')
    return redirect(url_for('index'))

@app.route('/api/flag_id')
@app.route('/api/flag_id/<service>')
@cache.cached(timeout=5)
def flag_id(service=None):
    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        cur.execute(
            'SELECT S.name as sname, T.ip as ip, F.flag_id as flag_id, F.round as round '
            'FROM  teams T, services S, flags F '
            'WHERE S.flag_id AND F.flag_id IS NOT NULL '
            'AND T.id = F.team_id AND S.id = F.service_id AND '
            'get_current_round() - F.round <= S.flag_lifespan - 1 '
            'ORDER BY S.name, T.ip, F.round DESC'
        )
        flag_ids = cur.fetchall()

    data = defaultdict(lambda: defaultdict(list))
    for row in flag_ids:
        if (service and row['sname'] == service) or not service:
            data[row['sname']][row['ip']].append(row['flag_id'])

    return jsonify(data)

@app.route('/admin')
@app.route('/admin/<tab>')
@admin_required
def admin(tab='users'):
    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        # get the users
        cur.execute('SELECT * FROM users')
        users = cur.fetchall()
    with db_conn.cursor() as cur:
        # get the teams
        cur.execute('SELECT * FROM teams')
        teams = cur.fetchall()
    with db_conn.cursor() as cur:
        # get the services
        cur.execute('SELECT * FROM services')
        services = cur.fetchall()
    with db_conn.cursor() as cur:
        # get the challenges
        cur.execute('SELECT * FROM challenges')
        challenges = cur.fetchall()
    with db_conn.cursor() as cur:
        # get the challenge writeups
        cur.execute((
            'SELECT W.id AS id, C.id AS challenge_id, U.id AS user_id, U.mail AS mail, '
            '       U.name AS name, U.surname AS surname, U.nickname AS nickname, C.name AS challenge, '
            '       W.timestamp AS timestamp, E.feedback IS NOT NULL AS feedback, '
            '       E.grade AS grade, W.timestamp > E.timestamp AS updated '
            'FROM (SELECT user_id, challenge_id, MAX(id) AS id'
            '      FROM writeups GROUP BY user_id, challenge_id) AS WT '
            'JOIN writeups AS W ON WT.id = W.id '
            'JOIN users AS U ON W.user_id = U.id '
            'JOIN challenges AS C ON W.challenge_id = C.id '
            'LEFT JOIN challenges_evaluations AS E ON U.id = E.user_id AND C.id = E.challenge_id'))
        evaluations = cur.fetchall()

    return render_template('admin/index.html',
                            users=users, teams=teams, services=services,
                            challenges=challenges, evaluations=evaluations,
                            tab=tab)

@app.route('/admin/user/new', methods=['GET', 'POST'])
@admin_required
def add_user():
    form = ctforge.forms.UserForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            nickname = form.nickname.data if form.nickname.data else None
            password = bcrypt.hashpw(form.password.data, bcrypt.gensalt()) if form.password.data else None
            query_handler((
                'INSERT INTO users (team_id, name, surname, nickname, mail, '
                '                   affiliation, password, admin, hidden) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'),
                (form.team_id.data, form.name.data, form.surname.data,
                 nickname, form.mail.data, form.affiliation.data,
                 password, form.admin.data, form.hidden.data))
        else:
            flash_errors(form)
        return redirect(url_for('admin', tab='users'))
    return render_template('admin/data.html', form=form, target='user',
                           action='add')

@app.route('/admin/user/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    if request.method == 'POST':
        form = ctforge.forms.UserForm()
        if form.validate_on_submit():
            if form.password.data:
                # update the password
                query_handler((
                    'UPDATE users '
                    'SET team_id = %s, name = %s, surname = %s, nickname = %s, '
                    '    mail = %s, affiliation = %s, password = %s, admin = %s, hidden = %s '
                    'WHERE id = %s'),
                    (form.team_id.data, form.name.data, form.surname.data, 
                     form.nickname.data, form.mail.data, form.affiliation.data,
                     bcrypt.hashpw(form.password.data, bcrypt.gensalt()),
                     form.admin.data, form.hidden.data, id))
            else:
                query_handler((
                    'UPDATE users '
                    'SET team_id = %s, name = %s, surname = %s, nickname = %s, '
                    '    mail = %s, affiliation = %s, admin = %s, hidden = %s '
                    'WHERE id = %s'),
                    (form.team_id.data, form.name.data, form.surname.data, 
                     form.nickname.data, form.mail.data, form.affiliation.data,
                     form.admin.data, form.hidden.data, id))
        else:
            flash_errors(form)
    else:
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute((
                'SELECT id, team_id, name, surname, nickname, mail, affiliation, admin, hidden '
                'FROM users '
                'WHERE id = %s'), [id])
            user = cur.fetchone()
        if user is None:
            flash('Invalid user!', 'error')
        else:
            form = ctforge.forms.UserForm(**user)
            return render_template('admin/data.html', form=form, target='user',
                                   action='edit')
    return redirect(url_for('admin', tab='users'))

@app.route('/admin/team/new', methods=['GET', 'POST'])
@attackdefense_mode_required
@admin_required
def add_team():
    form = ctforge.forms.TeamForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            query_handler((
                'INSERT INTO teams (ip, name, token, poc) '
                'VALUES (%s, %s, %s, %s)'),
                (form.ip.data, form.name.data, form.token.data,
                 form.poc.data))
        else:
            flash_errors(form)
        return redirect(url_for('admin', tab='teams'))
    return render_template('admin/data.html', form=form, target='team',
                           action='add')

@app.route('/admin/team/<int:id>', methods=['GET', 'POST'])
@attackdefense_mode_required
@admin_required
def edit_team(id):
    if request.method == 'POST':
        form = ctforge.forms.TeamForm()
        if form.validate_on_submit():
            query_handler((
                'UPDATE teams SET ip = %s, name = %s, token = %s, poc = %s '
                'WHERE id = %s'),
                (form.ip.data, form.name.data, form.token.data,
                 form.poc.data, id))
        else:
            flash_errors(form)
    else:
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute('SELECT * FROM teams WHERE id = %s', [id])
            team = cur.fetchone()
        if team is None:
            flash('Invalid team!', 'error')
        else:
            form = ctforge.forms.TeamForm(**team)
            return render_template('admin/data.html', form=form, target='team',
                                   action='edit')
    return redirect(url_for('admin', tab='teams'))

@app.route('/admin/service/new', methods=['GET', 'POST'])
@attackdefense_mode_required
@admin_required
def add_service():
    form = ctforge.forms.ServiceForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            query_handler((
                'INSERT INTO services (name, description, active, flag_lifespan,flag_id) '
                'VALUES (%s, %s, %s, %s, %s)'),
                (form.name.data, form.description.data, form.active.data,
                 form.flag_lifespan.data, form.flag_id.data))
        else:
            flash_errors(form)
        return redirect(url_for('admin', tab='services'))
    return render_template('admin/data.html', form=form, target='service',
                           action='add')

@app.route('/admin/service/<int:id>', methods=['GET', 'POST'])
@attackdefense_mode_required
@admin_required
def edit_service(id):
    if request.method == 'POST':
        form = ctforge.forms.ServiceForm()
        if form.validate_on_submit():
            query_handler((
                'UPDATE services SET name = %s, description = %s, '
                'active = %s, flag_lifespan = %s, flag_id = %s '
                'WHERE id = %s'),
                (form.name.data, form.description.data, form.active.data,
                 form.flag_lifespan.data, form.flag_id.data, id))
        else:
            flash_errors(form)
    else:
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute('SELECT * FROM services WHERE id = %s', [id])
            service = cur.fetchone()
        if service is None:
            flash('Invalid service!', 'error')
        else:
            form = ctforge.forms.ServiceForm(**service)
            return render_template('admin/data.html', form=form, target='service',
                                   action='edit')
    return redirect(url_for('admin', tab='services'))

@cache.memoize(timeout=20)
def get_jeopardy_settings():
    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        cur.execute('SELECT SUBSTRING(name, 10, LENGTH(name)) AS name, value '
                    'FROM ctf_config WHERE name LIKE \'jeopardy_%\'')
        config = { v['name']: v['value'] for v in cur.fetchall() }
    fields = [
        ('time_enabled', json.loads, False),
        ('start_time',
         lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S"),
         datetime.fromtimestamp(time.time())),
        ('end_time',
         lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S"),
         datetime.fromtimestamp(time.time())),
        ('ctf_running', json.loads, False)
    ]
    jeopardy = {}
    for k, from_string, default in fields:
        try:
            jeopardy[k] = from_string(config[k])
        except KeyError as e:
            jeopardy[k] = default

    if jeopardy['time_enabled']:
        now = datetime.now()
        jeopardy['ctf_running'] = jeopardy['start_time'] <= now <= jeopardy['end_time']

    return jeopardy

@app.route('/admin/jeopardy_settings', methods=['GET', 'POST'])
@jeopardy_mode_required
@admin_required
def jeopardy_settings():
    if request.method == 'POST':
        form = ctforge.forms.JeopardyForm()
        if form.validate_on_submit():
            form_vals = {
                'jeopardy_time_enabled': form.time_enabled.data,
                'jeopardy_start_time': form.start_time.data,
                'jeopardy_end_time': form.end_time.data,
                'jeopardy_ctf_running': form.ctf_running.data
            }

            db_conn = get_db_connection()
            try:
                with db_conn.cursor() as cur:
                    cur.executemany(
                        'INSERT INTO ctf_config (name, value) '
                        'VALUES (%(name)s, %(value)s) '
                        'ON CONFLICT (name) DO '
                        'UPDATE SET value = %(value)s',
                        [{'name':n, 'value': val} for n,val in form_vals.items()])
                flash('Configuration updated', 'success')
            except psycopg2.Error as e:
                db_conn.rollback()
                flash('Error: {}'.format(e), 'error')
        else:
            flash_errors(form)

        return redirect(url_for('admin'))

    jeopardy = get_jeopardy_settings()
    form = ctforge.forms.JeopardyForm(**jeopardy)
    return render_template('admin/data.html', form=form,
                           action='edit', target='jeopardy CTF',
                           return_to=url_for('admin'))

@app.route('/admin/challenge/new', methods=['GET', 'POST'])
@jeopardy_mode_required
@admin_required
def add_challenge():
    form =ctforge.forms.ChallengeForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            deadline = form.deadline.time.data if form.deadline.active.data else None
            query_handler((
                'INSERT INTO challenges (name, description, flag, points, tags, '
                '                        deadline, hidden, writeup, writeup_template) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'),
                [form.name.data, form.description.data, form.flag.data,
                 form.points.data, form.tags.data, deadline, form.hidden.data,
                 form.writeup.data, form.writeup_template.data])
        else:
            flash_errors(form)
        return redirect(url_for('admin', tab='challenges'))
    return render_template('admin/data.html', form=form, target='challenge',
                           action='add')

@app.route('/admin/challenge/<int:id>', methods=['GET', 'POST'])
@jeopardy_mode_required
@admin_required
def edit_challenge(id):
    if request.method == 'POST':
        form = ctforge.forms.ChallengeForm()
        if form.validate_on_submit():
            deadline = form.deadline.time.data if form.deadline.active.data else None
            query_handler((
                'UPDATE challenges '
                'SET name = %s, description = %s, flag = %s, points = %s, '
                '    tags = %s, deadline = %s, hidden = %s, '
                '    writeup = %s, writeup_template = %s '
                'WHERE id = %s'),
                [form.name.data, form.description.data, form.flag.data,
                 form.points.data, form.tags.data, deadline, form.hidden.data,
                 form.writeup.data, form.writeup_template.data, id])
        else:
            flash_errors(form)
    else:
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute('SELECT * FROM challenges WHERE id = %s', [id])
            challenge = cur.fetchone()
        if challenge is None:
            flash('Invalid challenge!', 'error')
        else:
            form = ctforge.forms.ChallengeForm(**challenge)
            # TODO is there a better way to do this?
            form.deadline.process(formdata=None, data={
                'active': challenge['deadline'] is not None,
                'time': challenge['deadline']})
            return render_template('admin/data.html', form=form,
                                   target='challenge', action='edit')
    return redirect(url_for('admin', tab='challenges'))


@app.route('/admin/evaluation/<int:challenge_id>/<int:user_id>', methods=['GET', 'POST'])
@jeopardy_mode_required
@admin_required
def edit_evaluation(challenge_id, user_id):
    # check if an evaluation has already been performed or not
    db_conn = db_connect()
    with db_conn.cursor() as cur:
        cur.execute((
            'SELECT U.mail AS mail, U.name, U.surname, U.nickname, C.name AS challenge, '
            '       W.timestamp AS timestamp, W.writeup AS writeup, E.grade, E.feedback '
            'FROM writeups AS W '
            'JOIN challenges AS C ON W.challenge_id = C.id '
            'JOIN users AS U ON W.user_id = U.id '
            'LEFT JOIN challenges_evaluations AS E '
            '     ON W.user_id = E.user_id AND W.challenge_id = E.challenge_id '
            'WHERE W.challenge_id = %s AND W.user_id = %s '
            'ORDER BY W.id DESC'),
            [challenge_id, user_id])
        evaluation = cur.fetchone()
    if evaluation is None:
        flash('Writeup not submitted, cannot evaluate!', 'error')
        return redirect(url_for('admin', tab='evaluations'))

    if request.method == 'POST':
        form = ctforge.forms.AdminWriteupForm()
        if form.validate_on_submit():
            query_handler((
                'INSERT INTO challenges_evaluations '
                '    (user_id, challenge_id, grade, feedback) '
                'VALUES (%s, %s, %s, %s) '
                'ON CONFLICT (user_id, challenge_id) '
                'DO UPDATE SET (grade, feedback, timestamp) = (EXCLUDED.grade, EXCLUDED.feedback, NOW())'),
                [user_id, challenge_id, form.grade.data, form.feedback.data])
        else:
            flash_errors(form)
    else:
        form = ctforge.forms.AdminWriteupForm(**evaluation)
        return render_template('admin/data.html', form=form, target='evaluation', action='edit')

    return redirect(url_for('admin', tab='evaluations'))


@app.route('/submit', methods=['GET', 'POST'])
@attackdefense_mode_required
@csrf.exempt
def submit():
    """Flag submitter service."""

    team_token = None
    # get the token associated with user's team
    if current_user.is_authenticated:
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute('SELECT token FROM teams WHERE id = %s',
                        [current_user.team_id])
            res = cur.fetchone()
        team_token = res['token'] if res is not None else None

    # initialize the flag form
    form = ctforge.forms.ServiceFlagForm(csrf_enabled=False)

    if request.method == 'POST':
        # process the form
        if form.validate_on_submit():
            team_token = form.team_token.data
            flag = form.flag.data
            try:
                db_conn = db_connect()
                db_conn.autocommit = False
                cur = db_conn.cursor()
                # get the team associated with the retrieved token
                cur.execute('SELECT id FROM teams WHERE token = %s', [team_token])
                res = cur.fetchone()
                if res is None:
                    raise ctforge.exceptions.InvalidToken()
                team_id = res['id']
                # get the flag that the user is trying to submit, if valid
                # (i.e. active and not one of the flags of his team)
                cur.execute(('SELECT service_id, get_current_round() - F.round > S.flag_lifespan - 1 AS expired, team_id '
                             'FROM flags F JOIN services S ON S.id = F.service_id '
                             'WHERE flag = %s'), [flag])
                res = cur.fetchone()
                if res is None:
                    raise ctforge.exceptions.InvalidFlag()
                if res['expired'] == 1:
                    raise ctforge.exceptions.ExpiredFlag()
                # check if the flag is owned by the same team that submitted it
                if res['team_id'] == team_id:
                    raise ctforge.exceptions.OwnFlag()
                # if we need to check integrity every submit, do it
                if not app.config['ALWAYS_SUBMIT']:
                    service_id = res['service_id']
                    # check whether the team's service is well-functioning or not
                    cur.execute(('SELECT successful '
                                 'FROM integrity_checks '
                                 'WHERE team_id = %s AND service_id = %s '
                                 'ORDER BY timestamp DESC LIMIT 1'),
                                [team_id, service_id])
                    res = cur.fetchone()
                    if res is None or res['successful'] != 1:
                        raise ctforge.exceptions.ServiceCorrupted()
                # store the attack in the database
                cur.execute(('INSERT INTO service_attacks (team_id, flag) '
                             'VALUES (%s, %s) '),
                             [team_id, flag])
                db_conn.commit()
                flash('Flag accepted!', 'success')
            except psycopg2.IntegrityError:
                # this exception is raised not only on duplicated entry, but also
                # when key constraint fails
                db_conn.rollback()
                flash('Duplicated flag!', 'error')
            except psycopg2.Error as e:
                db_conn.rollback()
                error_msg = 'Unknown database error: {}'.format(e)
                flash(error_msg, 'error')
                app.logger.error(error_msg)
            except ctforge.exceptions.InvalidToken:
                db_conn.rollback()
                flash('The provided token does not match any team!', 'error')
            except ctforge.exceptions.InvalidFlag:
                db_conn.rollback()
                flash('The submitted flag is invalid!', 'error')
            except ctforge.exceptions.OwnFlag:
                db_conn.rollback()
                flash('The submitted flag is your own!', 'error')
            except ctforge.exceptions.ExpiredFlag:
                db_conn.rollback()
                flash('The submitted flag is expired!', 'error')
            except ctforge.exceptions.ServiceCorrupted:
                db_conn.rollback()
                flash('Your service is corrupted, fix it before submitting flags!', 'error')
            except Exception as e:
                # this should never occur, but we keep it for safety reasons
                error_msg = 'Unknown error: {}'.format(e)
                flash(error_msg, 'error')
                app.logger.error(error_msg)
            finally:
                cur.close()
                db_conn.close()
        else:
            flash_errors(form)
    return render_template('submit.html', form=form, team_token=team_token)

@app.route('/user')
@login_required
def user():
    """Render a page with information about the user."""

    def load_file(pathname):
        try:
            with open(pathname, 'rb') as f:
               return base64.b64encode(f.read()).decode()
        except FileNotFoundError as e:
            app.logger.error(e)


    db_conn = get_db_connection()
    cur = db_conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = %s', [current_user.id])
    user = cur.fetchone()
    if user is None:
        cur.close()
        flash('Your user id is does not match any user', 'error')
        return redirect(url_for('index'))

    cur.execute('SELECT * FROM challenges C JOIN challenge_attacks A '
                'ON C.id = A.challenge_id WHERE A.user_id = %s ORDER BY A.timestamp', [current_user.id])
    challenges = cur.fetchall()

    ssh = load_file('/home/ctforge/keys/wutctf-{}_ed25519'.format(current_user.id))

    return render_template('user.html', user=user, challenges=challenges, 
                           ssh_encoded=ssh)


@app.route('/team')
@attackdefense_mode_required
@team_required
@login_required
def team():
    """Render a page with useful information about one's team."""

    db_conn = get_db_connection()
    cur = db_conn.cursor()
    # get the user's own team
    cur.execute('SELECT * FROM teams WHERE id = %s',
                [current_user.team_id])
    team = cur.fetchone()
    if team is None:
        cur.close()
        flash('Your team id is does not match any team', 'error')
        return redirect(url_for('index'))
    # get the members of the user's own team
    cur.execute('SELECT * FROM users WHERE team_id = %s',
                [current_user.team_id])
    members = cur.fetchall()
    # for each service get the number of attacks suffered and inflicted the
    # user's team
    cur.execute((
        '''SELECT S.id, S.name AS service_name,
           (SELECT COUNT(A.flag)
            FROM flags AS F JOIN service_attacks AS A ON F.flag = A.flag
            WHERE F.service_id = S.id AND A.team_id = %s AND A.timestamp >= CURRENT_TIMESTAMP - INTERVAL '15 minutes'
           ) AS inflicted,
           (SELECT COUNT(A.flag)
            FROM flags AS F JOIN service_attacks AS A ON F.flag = A.flag
            WHERE F.service_id = S.id AND F.team_id = %s AND A.timestamp >= CURRENT_TIMESTAMP - INTERVAL '15 minutes'
           ) AS suffered
           FROM services AS S
        '''), [current_user.team_id, current_user.team_id])
    attacks = cur.fetchall()
    cur.close()

    return render_template('team.html', team=team, members=members, attacks=attacks)


@app.route('/challenges_scoreboard')
@jeopardy_mode_required
def challenges_scoreboard():
    """Display the challenge scoreboard."""

    @cache.memoize(timeout=5)
    def challenge_list():
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute('SELECT *, deadline IS NULL OR deadline > NOW() AS "active" FROM challenges WHERE NOT hidden ORDER BY id')
            challenges = cur.fetchall()
            cur.execute('SELECT DISTINCT affiliation FROM users')
            affiliations = [ v['affiliation'] for v in cur.fetchall()
                             if v['affiliation'] ]
        return (challenges, affiliations)

    jeopardy = get_jeopardy_settings()
    if jeopardy['time_enabled']:
        now = datetime.now()
        jeopardy['ctf_ended'] = now >= jeopardy['end_time']
        jeopardy['start_time'] = jeopardy['start_time'].strftime("%H:%M on %d/%m/%Y")

    challenges, affiliations = challenge_list()
    return render_template('challenges_scoreboard.html',
                           challenges=challenges, affiliations=affiliations,
                           settings=jeopardy)


@app.route('/challenges')
@login_required
def challenges():
    """ Display the list of challenges with score and solvers """

    jeopardy = get_jeopardy_settings()
    now = datetime.now()

    @cache.memoize(timeout=5)
    def challenges_attacks():
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute('SELECT *, deadline IS NULL OR deadline > NOW() AS "active" '
                        'FROM challenges WHERE NOT hidden ORDER BY id')
            challenges = cur.fetchall()
            cur.execute('SELECT A.*, U.id as user_id, U.hidden as user_hidden '
                        'FROM challenge_attacks as A '
                        'LEFT JOIN users as U ON A.user_id = U.id')
            attacks = cur.fetchall()
        return (challenges, attacks)

    challenges, attacks = challenges_attacks()
    for chal in challenges:
        chal_attacks = [a for a in attacks if a['challenge_id'] == chal['id']]
        chal_solved = [a for a in chal_attacks if a['user_id'] == current_user.id]
        chal['solved'] = bool(chal_solved)
        chal['solved_time'] = None if not chal_solved else chal_solved[0]['timestamp']
        chal['solvers'] = sum( 1 for x in chal_attacks if not x['user_hidden'] )

    if jeopardy['time_enabled']:
        jeopardy['ctf_ended'] = now >= jeopardy['end_time']
        jeopardy['seconds_left'] = int((jeopardy['end_time'] - now).total_seconds())
        jeopardy['start_time'] = jeopardy['start_time'].strftime("%H:%M on %d/%m/%Y")

    return render_template('challenges.html', challenges=challenges,
                           settings=jeopardy)

@app.route('/scoreboard_jeopardy')
@cache.cached(timeout=5)
def _challenges():

    # if the ctf is not running return the empty object
    jeopardy = get_jeopardy_settings()
    now = datetime.now()
    if not jeopardy['ctf_running'] and (jeopardy['time_enabled'] and now < jeopardy['end_time']):
        return jsonify([])

    db_conn = get_db_connection()
    cur = db_conn.cursor()
    # get the challenges
    cur.execute('SELECT * FROM challenges WHERE NOT hidden')
    res = cur.fetchall()
    chals = {c['id']: c for c in res}

    # get only the users who solved at least one challenge that are not admin and not hidden,
    # sorted by timestamp, and the information about the solved challenges
    cur.execute((
        'SELECT U.id AS user_id, U.nickname AS nickname, U.affiliation AS affiliation, '
        '       CA.challenge_id AS challenge_id, CA.timestamp AS timestamp '
        'FROM users AS U JOIN challenge_attacks AS CA '
        'ON U.id = CA.user_id '
        'WHERE NOT admin AND NOT hidden '
        'ORDER BY timestamp'))
    challenge_attacks = cur.fetchall()
    cur.close()

    # counter of solvers per challenge
    solvers = {}
    # map user id to a dictionary containing the corresponding score
    users = {}
    for ca in challenge_attacks:
        cid, uid = ca['challenge_id'], ca['user_id']
        # skip solves of hidden challenges
        if cid in chals:
            # add the user if not present
            if uid not in users:
                users[uid] = {
                    'user': ca['nickname'],
                    'affiliation': ca['affiliation'],
                    'points': 0,
                    'challenges': {
                        c['name']: { 'points': 0, 'timestamp': None } for c in chals.values()
                    }
                }
            # get the number of users who already solved the challenge and compute
            # the number of points obtained by the user, taking into account the base score
            solvers[cid] = solvers.get(cid, 0) + 1
            points = math.floor(chals[cid]['points'] / solvers[cid]**0.15)
            users[uid]['challenges'][chals[cid]['name']] = {
                'points': points, 'timestamp': ca['timestamp']
            }
            users[uid]['points'] += points

    # the scoreboard is a list of dictionaries containing scoring details for each user
    # the list is sorted by total score and, in case of ties, depending on the last flag submission
    def sort_fn(u):
        timestamps = [c['timestamp'] for c in u['challenges'].values() if c['timestamp'] is not None]
        return u['points'], len(timestamps), None if len(timestamps) == 0 else datetime.now() - max(timestamps)

    scoreboard = list(users.values())
    scoreboard.sort(key=sort_fn, reverse=True)

    # add an index to the scoreboard row to preserve sorting
    for i, elm in enumerate(scoreboard):
        elm['position'] = i+1

    return jsonify(scoreboard)


@app.route('/challenge/<name>', methods=['GET', 'POST'])
@jeopardy_mode_required
@login_required
def challenge(name):
    """Display information about a challenge plus the flag submission form and the writeup."""

    jeopardy = get_jeopardy_settings()
    now = datetime.now()
    if not jeopardy['ctf_running'] and now < jeopardy['end_time']:
        return abort(404)

    db_conn = db_connect()
    cur = db_conn.cursor()

    # get challenge data if the challenge exists
    cur.execute('SELECT *, deadline IS NULL OR deadline > NOW() AS "active" FROM challenges WHERE name = %s',
                [name])
    challenge = cur.fetchone()
    # if the challenge is not valid abort
    if challenge is None or (challenge['hidden'] and not current_user.admin):
        cur.close()
        abort(404)

    # check if the current user already solved the challenge
    cur.execute(('SELECT * FROM challenge_attacks '
                 'WHERE user_id = %s AND challenge_id = %s'),
                 [current_user.id, challenge['id']])
    solved = cur.fetchone() is not None
    # get the list of all the writeups submitted by this user for this challenge
    cur.execute(('SELECT id, timestamp FROM writeups '
                 'WHERE user_id = %s AND challenge_id = %s '
                 'ORDER BY id DESC'),
                 [current_user.id, challenge['id']])
    writeups = cur.fetchall()
    # get the evaluation for this challenge
    evaluation = None
    if writeups:
        cur.execute(('SELECT feedback, grade, timestamp FROM challenges_evaluations '
                     'WHERE user_id = %s AND challenge_id = %s '),
                     [current_user.id, challenge['id']])
        evaluation = cur.fetchone()
    graded = evaluation is not None and evaluation['grade'] is not None

    # retrieve the writeup form, if any
    writeup_form = ctforge.forms.ChallengeWriteupForm(writeup=challenge['writeup_template'])
    # retrive the flag form
    flag_form = ctforge.forms.ChallengeFlagForm()

    # accept POST requests only if the challenge is active
    if request.method == 'POST':
        if not challenge['active']:
            flash('The deadline for the challenge has expired', 'error')
        else:
            # process the two mutually exclusive forms
            writeup_data = request.form.get('writeup')
            flag = request.form.get('flag')

            if writeup_data is not None:
                # only allow writeup submission if writeup support is enabled for this chal
                if challenge['writeup'] and writeup_form.validate_on_submit():
                    if graded:
                        # writeup already submitted, resubmission allowed only if there's no grade
                        flash('Your submission has already been graded, you cannot modify it', 'error')
                    else:
                        writeup_data = writeup_form.writeup.data
                        try:
                            # save this writeup into the db
                            cur.execute(('INSERT INTO writeups (user_id, challenge_id, writeup) '
                                        'VALUES (%s, %s, %s) RETURNING id'),
                                        [current_user.id, challenge['id'], writeup_data])
                            writeup_id = cur.fetchone()['id']
                            cur.close()
                            db_conn.commit()
                            flash('Writeup added', 'success')
                        except psycopg2.Error as e:
                            db_conn.rollback()
                            error_msg = 'Unknown database error: {}'.format(e)
                            flash(error_msg, 'error')
                            app.logger.error(error_msg)
                else:
                    flash_errors(writeup_form)
            else:
                if cur is None:
                    cur = db_conn.cursor()
                if flag is not None and flag_form.validate_on_submit():
                    flag = flag_form.flag.data

                    # Check if the user can submit flags
                    # if the ctf is over the flags are validated but the db is not updated
                    if not jeopardy['ctf_running']:
                        if jeopardy['time_enabled']:
                            if now >= jeopardy['end_time'] and flag == challenge['flag']:
                                flash('Flag accepted! (No points)', 'success')
                            else:
                                flash('Invalid flag', 'error')
                            return redirect(url_for('challenge', name=challenge['name']))
                        else:
                            flash('There is no running CTF!', 'error')
                            return redirect(url_for('challenge', name=challenge['name']))


                    if flag == challenge['flag']:
                        try:
                            # save this attack into the db
                            cur.execute((
                                'INSERT INTO challenge_attacks (user_id, challenge_id) '
                                'VALUES (%s, %s)'),
                                [current_user.id, challenge['id']])
                            cur.close()
                            db_conn.commit()
                            flash('Flag accepted!', 'success')
                        except psycopg2.IntegrityError:
                            # this exception is raised not only on duplicated entry,
                            # but also when key constraint fails
                            db_conn.rollback()
                            flash('You already solved this challenge')
                        except psycopg2.Error as e:
                            db_conn.rollback()
                            error_msg = 'Unknown database error: {}'.format(e)
                            flash(error_msg, 'error')
                            app.logger.error(error_msg)
                    else:
                        flash('Invalid flag', 'error')
                else:
                    flash_errors(flag_form)

        # close the pending connection to the database
        db_conn.close()
        return redirect(url_for('challenge', name=challenge['name']))

    db_conn.close()

    return render_template('challenge.html', flag_form=flag_form, writeup_form=writeup_form,
                           challenge=challenge, evaluation=evaluation, solved=solved,
                           graded=graded, writeups=writeups)


@app.route('/writeup/<int:id>')
@app.route('/writeup/<int:id>/<int:md>')
@jeopardy_mode_required
@login_required
def writeup(id, md=0):
    """Display the provided writeup."""

    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        # get the writeup data if it exists
        cur.execute((
            'SELECT W.id AS id, W.writeup AS writeup, W.timestamp AS timestamp, '
            '       U.id AS user_id, U.name AS user_name, U.surname AS user_surname, '
            '       C.id AS challenge_id, C.name AS challenge_name, C.points AS challenge_points '
            'FROM writeups AS W '
            'JOIN users AS U ON W.user_id = U.id '
            'JOIN challenges AS C ON W.challenge_id = C.id '
            'WHERE W.id = %s'), [id])
        writeup = cur.fetchone()
    # grant access to the author or admin
    if writeup is not None and (writeup['user_id'] == current_user.id or current_user.admin):
        with db_conn.cursor() as cur:
            cur.execute((
                'SELECT id, timestamp FROM writeups '
                'WHERE user_id = %s AND challenge_id = %s '
                'ORDER BY timestamp DESC'),
                [writeup['user_id'], writeup['challenge_id']])
            writeups = cur.fetchall()
        return render_template('writeup.html', writeup=writeup, writeups=writeups, md=md)
    abort(404)


@app.route('/service/<name>')
@attackdefense_mode_required
# @login_required # Needed if the description contains download links
def service(name):
    """Display information about a service."""

    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        # get service data if the service exists
        cur.execute('SELECT * FROM services WHERE name = %s',
                    [name])
        service = cur.fetchone()
    if service is None or not service['active']:
        abort(404)
    return render_template('service.html', service=service)


@app.route('/teams')
@attackdefense_mode_required
def teams():
    """Print teams data."""

    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        # get teams
        cur.execute('SELECT id, name FROM teams ORDER BY id')
        teams = cur.fetchall()
        # get users
        cur.execute(('SELECT id, team_id, name, surname, nickname '
                     'FROM users ORDER BY id'))
        users = cur.fetchall()
    return render_template('teams.html', teams=teams, users=users)

def round_info(db_conn):
    # get the latest round
    with db_conn.cursor() as cur:
        cur.execute('SELECT id AS round, timestamp FROM rounds ORDER BY id DESC LIMIT 1')
        res = cur.fetchone()
    rnd = res['round'] if res is not None and res['round'] else 0

    # get the time left until the next round
    date_now = datetime.now()
    seconds_left = app.config['ROUND_DURATION']
    if rnd >= 1:
        # get seconds left till new round
        seconds_left = max(
            int(((res['timestamp'] + timedelta(seconds=app.config['ROUND_DURATION'])) - date_now).total_seconds()), 0)

    return rnd, seconds_left, res['timestamp'] if res is not None else 0

@app.route('/scoreboard')
@attackdefense_mode_required
def scoreboard():
    # get info about the current round
    db_conn = get_db_connection()
    rnd, seconds_left, _ = round_info(db_conn)

    # get the list of services
    with db_conn.cursor() as cur:
        cur.execute('SELECT id, name, active FROM services ORDER BY name')
        services = cur.fetchall()

    return render_template('scoreboard.html', rnd=rnd, rnd_duration=app.config['ROUND_DURATION'],
                           time_left=seconds_left, services=services)

@app.route('/ctf_scoreboard')
@attackdefense_mode_required
@cache.cached(timeout=4)
def _scoreboard(rnd=None):
    db_conn = get_db_connection()
    rnd, seconds_left, rnd_start_timestamp = round_info(db_conn)

    with db_conn.cursor() as cur:

        scores = defaultdict(dict)
        ips = {}

        # get the scores of each team on each service
        cur.execute((
            'SELECT T.name AS team_name, T.ip as team_ip, '
            'SR.name AS service_name, SC.attack, SC.defense, SC.sla '
            'FROM scores AS SC '
            'JOIN services AS SR ON SC.service_id = SR.id '
            'JOIN teams AS T ON T.id = SC.team_id '
            'WHERE SC.round = GREATEST(get_current_round() - 1, 0)'))

        for score in cur:
            team = score['team_name']
            ip = score['team_ip']
            service = score['service_name']
            scores[team][service] = {
                'attack': score['attack'],
                'defense': score['defense'],
                'sla': score['sla'],
                'attack_flags': 0,
                'defense_flags': 0
            }
            ips[team] = ip

        # get the flag count for each service
        # attack
        cur.execute('''
            SELECT T.name as team, S.name as service, COUNT(F.flag) as count
            FROM service_attacks A
                 JOIN flags F ON F.flag = A.flag
                 JOIN teams T ON T.id = A.team_id
                 JOIN services S ON S.id = F.service_id
            WHERE A.timestamp < %s
            GROUP BY T.name, S.name
            ''', [rnd_start_timestamp])
        for row in cur:
            team = row['team']
            service = row['service']
            scores[team][service]['attack_flags'] = row['count']
        # defense
        cur.execute('''
            SELECT T.name as team, S.name as service, COUNT(F.flag) as count
            FROM service_attacks A
                 JOIN flags F ON F.flag = A.flag
                 JOIN teams T ON T.id = F.team_id
                 JOIN services S ON S.id = F.service_id
            WHERE A.timestamp < %s
            GROUP BY T.name, S.name
            ''', [rnd_start_timestamp])
        for row in cur:
            team = row['team']
            service = row['service']
            scores[team][service]['defense_flags'] = -row['count']

        # get total sla for each service
        cur.execute('''
            SELECT T.name as team, S.name as service,
                   count(case C.successful when TRUE then 1 else NULL end) AS successful,
                   count(*) as total
            FROM integrity_checks C
                 JOIN teams T ON T.id = C.team_id
                 JOIN services S ON S.id = C.service_id
            WHERE C.timestamp < %s
            GROUP BY T.name, S.name
        ''', [rnd_start_timestamp])
        for row in cur:
            team = row['team']
            service = row['service']
            scores[team][service]['sla_percentage'] = row['successful'] / row['total'] * 100

        # get the status of each service
        cur.execute((
            'SELECT T.name AS team_name, S.name AS service_name, C.timestamp, C.successful '
            'FROM teams AS T, services AS S, LATERAL ('
            '    SELECT IC.successful, IC.timestamp'
            '    FROM integrity_checks IC'
            '    WHERE IC.team_id = T.id AND IC.service_id = S.id'
            '    ORDER BY IC.timestamp DESC'
            '    LIMIT 1'
            ') AS C'))
        for check in cur:
            team = check['team_name']
            service = check['service_name']
            scores[team][service]['integrity'] = {
                'status': check['successful'],
                'timestamp': check['timestamp']
            }

    board = []
    for name, services in scores.items():
        entry = {
            'name': name,
            'ip': ips[name],
            'services': services,
            'attack': sum(s['attack'] for s in services.values()),
            'defense': sum(s['defense'] for s in services.values()),
            'sla': sum(s['sla'] for s in services.values()),
            'score': sum(s['attack'] + s['defense'] + s['sla'] for s in services.values())
        }
        board.append(entry)
    board.sort(key=lambda e: e['score'], reverse=True)

    return jsonify({
        'round': rnd,
        'seconds_left': seconds_left,
        'scores': board
    })

@app.route('/ctf_stats')
@app.route('/ctf_stats/<int:nrounds>')
@attackdefense_mode_required
@cache.cached(timeout=10)
def _stats(nrounds=None):
    db_conn = get_db_connection()

    nrounds = nrounds or round_info(db_conn)[0]

    with db_conn.cursor() as cur:
        cur.execute('''
        SELECT S.round AS round, T.name AS team, SUM(S.attack) + SUM(S.defense) + SUM(S.sla) AS score
        FROM scores S JOIN teams T ON S.team_id = T.id
        WHERE S.round >= get_current_round() - %s
        GROUP BY T.name, S.round
        ORDER BY S.round DESC
        ''', [nrounds])

        scores = defaultdict(dict)
        for row in cur:
            scores[row['team']][row['round']] = row['score']

    return jsonify(scores)

@app.route('/design')
@attackdefense_mode_required
def design():
    return render_template('design.html')

@app.route('/rules')
@jeopardy_mode_required
def rules():
    return render_template('rules.html')

@app.route('/')
def index():
    return render_template('index.html')
