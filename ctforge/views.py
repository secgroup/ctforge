#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import bcrypt
import datetime
import psycopg2
import psycopg2.extras
from flask import request, render_template, redirect, url_for, flash, abort, jsonify
from flask_login import current_user, login_required, login_user, logout_user
from functools import wraps
from collections import defaultdict

from ctforge import app, csrf, login_manager, cache
from ctforge.users import User
from ctforge.database import db_connect, get_db_connection, query_handler
from ctforge.utils import flash_errors
import ctforge.forms
import ctforge.exceptions


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
            if user is not None and bcrypt.checkpw(form.password.data, user.password):
                if login_user(user):
                    return redirect(url_for('index'))
                else:
                    flash('Could not log in', 'error')
            flash('Invalid mail or password', 'error')
            return redirect(url_for('login'))
        else:
            flash_errors(form)

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out!', 'success')
    return redirect(url_for('index'))

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
            '       U.name AS name, U.surname AS surname, C.name AS challenge, '
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
            query_handler((
                'INSERT INTO users (team_id, name, surname, nickname, mail, '
                '                   affiliation, password, admin, hidden) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'),
                (form.team_id.data, form.name.data,
                 form.surname.data, form.nickname.data, form.mail.data,
                 form.affiliation.data,
                 bcrypt.hashpw(form.password.data, bcrypt.gensalt()),
                 form.admin.data, form.hidden.data))
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
                    'SET team_id = %s, name = %s, surname = %s, nickname = %s '
                    '    mail = %s, affiliation = %s, password = %s, admin = %s, hidden = %s '
                    'WHERE id = %s'),
                    (form.team_id.data, form.name.data,
                     form.surname.data, form.nickname.data, form.mail.data,
                     form.affiliation.data,
                     bcrypt.hashpw(form.password.data, bcrypt.gensalt()),
                     form.admin.data, form.hidden.data, id))
            else:
                query_handler((
                    'UPDATE users '
                    'SET team_id = %s, name = %s, surname = %s, nickname = %s, '
                    '    mail = %s, affiliation = %s, admin = %s, hidden = %s '
                    'WHERE id = %s'),
                    (form.team_id.data, form.name.data,
                     form.affiliation.data,
                     form.surname.data, form.nickname.data, form.mail.data, form.admin.data,
                     form.hidden.data, id))
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
                'INSERT INTO services (name, description, active, flag_lifespan) '
                'VALUES (%s, %s, %s, %s)'),
                (form.name.data, form.description.data, form.active.data, form.flag_lifespan.data))
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
                'UPDATE services SET name = %s, description = %s, active = %s, flag_lifespan = %s '
                'WHERE id = %s'),
                (form.name.data, form.description.data, form.active.data, form.flag_lifespan.data, id))
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

@app.route('/admin/challenge/new', methods=['GET', 'POST'])
@jeopardy_mode_required
@admin_required
def add_challenge():
    form =ctforge.forms.ChallengeForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            query_handler((
                'INSERT INTO challenges (name, description, flag, points, '
                '                        active, hidden, writeup, writeup_template) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)'),
                [form.name.data, form.description.data, form.flag.data,
                 form.points.data, form.active.data, form.hidden.data, form.writeup.data,
                 form.writeup_template.data])
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
            query_handler((
                'UPDATE challenges '
                'SET name = %s, description = %s, flag = %s, points = %s, '
                '    active = %s, hidden = %s, writeup = %s, writeup_template = %s '
                'WHERE id = %s'),
                [form.name.data, form.description.data, form.flag.data,
                 form.points.data, form.active.data, form.hidden.data, form.writeup.data,
                 form.writeup_template.data, id])
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
            'SELECT U.mail AS mail, U.name, U.surname, C.name AS challenge, '
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
            if evaluation['feedback'] is None:
                # do a fresh insert
                query_handler((
                    'INSERT INTO challenges_evaluations '
                    '    (user_id, challenge_id, grade, feedback) '
                    'VALUES (%s, %s, %s, %s) '),
                    [user_id, challenge_id, form.grade.data, form.feedback.data])
            else:
                # only allow if not yet graded
                if evaluation['grade'] is None:
                    query_handler((
                        'UPDATE challenges_evaluations '
                        'SET grade = %s, feedback = %s, timestamp = NOW() '
                        'WHERE user_id = %s AND challenge_id = %s'),
                        [form.grade.data, form.feedback.data, user_id, challenge_id])
                else:
                    flash('Cannot modify a writeup evaluation once a grade has been set!',
                          'error')
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
                cur.execute(('SELECT service_id, get_current_round() - F.round > S.flag_lifespan - 1 AS expired '
                             'FROM flags F JOIN services S ON S.id = F.service_id '
                             'WHERE flag = %s AND team_id != %s'),
                             [flag, team_id])
                res = cur.fetchone()
                if res is None:
                    raise ctforge.exceptions.InvalidFlag()
                if res['expired'] == 1:
                    raise ctforge.exceptions.ExpiredFlag()
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

@app.route('/challenges')
@jeopardy_mode_required
def challenges():
    """Display the challenge scoreboard."""

    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        cur.execute('SELECT * FROM challenges')
        challenges = cur.fetchall()

    return render_template('challenges.html', challenges=challenges)

@cache.cached(timeout=30)
@app.route('/challenges_scoreboard')
def _challenges():
    db_conn = get_db_connection()
    cur = db_conn.cursor()
    # get the challenges
    cur.execute('SELECT * FROM challenges')
    res = cur.fetchall()
    chals = {c['id']: c for c in res} if len(res) != 0 else dict()
    # get only the users who solved at least one challenge that are not admin
    # and not hidden, sorted by timestamp. Along with the users get the
    # information about the solved challenges
    cur.execute((
        'SELECT U.id AS user_id, U.name AS name, U.surname AS surname, '
        '       U.admin AS admin, U.hidden AS hidden, '
        '       CA.challenge_id AS challenge_id, CA.timestamp AS timestamp '
        'FROM users AS U JOIN challenge_attacks AS CA '
        'ON U.id = CA.user_id '
        'WHERE NOT admin AND NOT hidden '
        'ORDER BY timestamp ASC '))
    challenge_attacks = cur.fetchall()
    cur.close()
    # map user id to a string representing his name and surname
    users = dict()
    # map the pair challenge id and user id to the timestamp
    attacks = dict()
    for ca in challenge_attacks:
        users[ca['user_id']] = '{} {}'.format(ca['name'], ca['surname'])
        attacks[(ca['challenge_id'], ca['user_id'])] = ca['timestamp']

    # compute the bonus: +3 for firt shot, +2 to second and +1 to third
    bonus_aux = dict()
    for (c, u), t in attacks.items():
        try:
            bonus_aux[c].append((u, t))
        except KeyError:
            bonus_aux[c] = [(u, t)]
    bonus = dict()
    for c in bonus_aux.keys():
        bonus_aux[c] = sorted(bonus_aux[c], key=lambda x: x[1])
        for i in range(len(bonus_aux[c])):
            bonus[(c, bonus_aux[c][i][0])] = 3 - i
            if i >= 2:
                break

    # compute the scoreboard as a list of dictionaries
    scoreboard = []
    for u, uv in users.items():
        score = {'user': uv, 'points': 0, 'challenges': {}}
        for c, cv in chals.items():
            try:
                timestamp = attacks[(c, u)]
                # only add the bonus points if the challenge score is > 0
                points = cv['points']
                if points > 0:
                    points += bonus.get((c, u), 0)
                score['points'] += points
            except KeyError:
                timestamp = None
                points = 0
            score['challenges'][cv['name']] = {'timestamp': timestamp, 'points': points}
        scoreboard.append(score)

    # sort the scoreboard by total points or, in case of a tie, by the time of the
    # last submission
    def sorting_key(u):
        timestamps = [c['timestamp'] for c in u['challenges'].values() if c['timestamp'] is not None]
        return u['points'], datetime.datetime.now() - max(timestamps)

    scoreboard.sort(key=sorting_key, reverse=True)

    return jsonify(scoreboard)


@app.route('/challenge/<name>', methods=['GET', 'POST'])
@jeopardy_mode_required
@login_required
def challenge(name):
    """Display information about a challenge plus the flag submission form and the writeup."""

    db_conn = db_connect()
    cur = db_conn.cursor()

    # get challenge data if the challenge exists
    cur.execute('SELECT * FROM challenges WHERE name = %s',
                [name])
    challenge = cur.fetchone()
    # if the challenge is not valid abort
    if challenge is None:
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
    if request.method == 'POST' and challenge['active']:
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
                'WHERE user_id = %s AND challenge_id = %s'
                'ORDER BY timestamp DESC'),
                [writeup['user_id'], writeup['challenge_id']])
            writeups = cur.fetchall()
        return render_template('writeup.html', writeup=writeup, writeups=writeups, md=md)
    abort(404)


@app.route('/service/<name>')
@attackdefense_mode_required
@login_required
def service(name):
    """Display information about a service."""

    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        # get service data if the service exists
        cur.execute('SELECT * FROM services WHERE name = %s',
                    [name])
        service = cur.fetchone()
    if service is None:
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
        cur.execute(('SELECT id, team_id, name, surname '
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
    date_now = datetime.datetime.now()
    seconds_left = app.config['ROUND_DURATION']
    if rnd >= 1:
        # get seconds left till new round
        seconds_left = max(
            ((res['timestamp'] + datetime.timedelta(seconds=app.config['ROUND_DURATION'])) - date_now).seconds, 0)

    return rnd, seconds_left

@app.route('/scoreboard')
@attackdefense_mode_required
def scoreboard():
    # get info about the current round
    db_conn = get_db_connection()
    rnd, seconds_left = round_info(db_conn)

    # get the list of services
    with db_conn.cursor() as cur:
        cur.execute('SELECT id, name, active FROM services')
        services = cur.fetchall()

    return render_template('scoreboard.html', rnd=rnd, rnd_duration=app.config['ROUND_DURATION'],
                           time_left=seconds_left, services=services)

#@cache.cached(timeout=60)
@app.route('/ctf_scoreboard')
@attackdefense_mode_required
def _scoreboard(rnd=None):
    db_conn = get_db_connection()
    rnd, seconds_left = round_info(db_conn)

    with db_conn.cursor() as cur:

        scores = defaultdict(dict)

        # get the scores of each team on each service
        cur.execute((
            'SELECT T.name AS team_name, SR.name AS service_name, SC.attack, SC.defense, SC.sla '
            'FROM scores AS SC '
            'JOIN services AS SR ON SC.service_id = SR.id '
            'JOIN teams AS T ON T.id = SC.team_id '
            'WHERE SC.round = get_current_round() - 1'))

        for score in cur:
            team = score['team_name']
            service = score['service_name']
            scores[team][service] = {
                'attack': score['attack'],
                'defense': score['defense'],
                'sla': score['sla']
            }

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

@app.route('/credits')
def credits():
    return render_template('credits.html')

@app.route('/design')
def design():
    return render_template('design.html')

@app.route('/')
def index():
    return render_template('index.html')
