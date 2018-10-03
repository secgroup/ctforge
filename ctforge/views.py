#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import bcrypt
import datetime
import psycopg2
import psycopg2.extras
from copy import deepcopy
from flask import request, render_template, redirect, url_for, flash, abort, jsonify
from flask_login import current_user, login_required, login_user, logout_user
from functools import wraps

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
                'INSERT INTO users (team_id, name, surname, mail, '
                '                   password, admin, hidden) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s)'),
                (form.team_id.data, form.name.data,
                 form.surname.data, form.mail.data,
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
                    'SET team_id = %s, name = %s, surname = %s, '
                    '    mail = %s, password = %s, admin = %s, hidden = %s '
                    'WHERE id = %s'),
                    (form.team_id.data, form.name.data,
                     form.surname.data, form.mail.data,
                     bcrypt.hashpw(form.password.data, bcrypt.gensalt()),
                     form.admin.data, form.hidden.data, id))
            else:
                query_handler((
                    'UPDATE users '
                    'SET team_id = %s, name = %s, surname = %s, '
                    '    mail = %s, admin = %s, hidden = %s '
                    'WHERE id = %s'),
                    (form.team_id.data, form.name.data,
                     form.surname.data, form.mail.data, form.admin.data,
                     form.hidden.data, id))
        else:
            flash_errors(form)
    else:
        db_conn = get_db_connection()
        with db_conn.cursor() as cur:
            cur.execute((
                'SELECT id, team_id, name, surname, mail, admin, hidden '
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
                'INSERT INTO services (name, description, active) '
                'VALUES (%s, %s, %s)'),
                (form.name.data, form.description.data, form.active.data))
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
                'UPDATE services SET name = %s, description = %s, active = %s '
                'WHERE id = %s'),
                (form.name.data, form.description.data, form.active.data, id))
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
                '                        active, writeup, writeup_template) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s)'),
                [form.name.data, form.description.data, form.flag.data,
                 form.points.data, form.active.data, form.writeup.data, 
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
                '    active = %s, writeup = %s, writeup_template = %s '
                'WHERE id = %s'),
                [form.name.data, form.description.data, form.flag.data,
                 form.points.data, form.active.data, form.writeup.data, 
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
                #if evaluation['grade'] is None:
                query_handler((
                    'UPDATE challenges_evaluations '
                    'SET grade = %s, feedback = %s, timestamp = NOW() '
                    'WHERE user_id = %s AND challenge_id = %s'),
                    [form.grade.data, form.feedback.data, user_id, challenge_id])
                #else:
                #    flash('Cannot modify a writeup evaluation once a grade has been set!',
                #          'error')
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
                cur.execute(('SELECT service_id FROM active_flags '
                             'WHERE flag = %s AND team_id != %s'),
                             [flag, team_id])
                res = cur.fetchone()
                if res is None:
                    raise ctforge.exceptions.InvalidFlag()
                service_id = res['service_id']
                # check whether the team's service is well-functioning or not
                #cur.execute(('SELECT I.successful, I.timestamp '
                #             'FROM active_flags AS A '
                #             'JOIN integrity_checks AS I '
                #             'ON A.flag = I.flag '
                #             'WHERE A.team_id = %s AND A.service_id = %s '
                #             'ORDER BY I.timestamp DESC LIMIT 1'),
                #             [team_id, service_id])
                #res = cur.fetchone()
                #if res is None or res['successful'] != 1:
                #    raise ctforge.exceptions.ServiceCorrupted()
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
        'SELECT S.name AS service_name, '
        '       COUNT(A.flag) AS suffered, '
        '       (SELECT COUNT(A1.flag) '
        '        FROM active_flags AS F1 '
        '        JOIN service_attacks AS A1 ON F1.flag = A1.flag '
        '        WHERE A1.team_id = F.team_id AND F1.service_id = F.service_id '
        '       ) AS inflicted '
        'FROM services AS S '
        'JOIN active_flags AS F ON S.id = F.service_id '
        'LEFT JOIN service_attacks AS A ON F.flag = A.flag '
        'WHERE F.team_id = %s '
        'GROUP BY F.team_id, F.service_id, S.name'),
        [current_user.team_id])
    attacks = cur.fetchall()
    cur.close()

    return render_template('team.html', team=team, members=members, attacks=attacks)

@app.route('/challenges')
@jeopardy_mode_required
def challenges():
    """Display the challenge scoreboard."""

    challenges_data = _challenges()

    return render_template('challenges.html', **challenges_data)

@cache.cached(timeout=30)
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

    # compute the bonus: +1 for firt shot, +0.5 to second and third
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
            if i == 0:
                bonus[(c, bonus_aux[c][i][0])] = 1
            elif i == 1 or i == 2:
                bonus[(c, bonus_aux[c][i][0])] = 0.5
            else:
                break

    # compute the scoreboard as a list of dictionaries
    scoreboard = []
    for u, uv in users.items():
        score = {'user': uv, 'points': 0}
        score['challenges'] = dict()
        solved_all = True
        for c, cv in chals.items():
            try:
                timestamp = attacks[(c, u)]
                # only add the bonus points if the challenge is not agreement
                points = cv['points']
                if cv['name'] != 'agreement':
                    points += bonus.get((c, u), 0)
                score['points'] += points
            except KeyError:
                timestamp = None
                points = 0
                solved_all = False
            score['challenges'][c] = {'timestamp': timestamp, 'points': points}
        if solved_all:
            score['points'] +=  1
        scoreboard.append(score)
    # sort the scoreboard by total points
    scoreboard = sorted(scoreboard, key=lambda x: x['points'], reverse=True)

    # charts computation
    graph_template = {
        "type": "serial",
        "categoryField": "date",
        "dataDateFormat": "YYYY-MM-DD HH:NN:SS",
        "startDuration": 0.5,
        "startEffect": "easeOutSine",
        "fontFamily": "Monda",
        "fontSize": 14,
        "theme": "dark",
        "categoryAxis": {
            "minPeriod": "ss",
            "parseDates": True
        },
        "chartCursor": {
            "enabled": True,
            "categoryBalloonDateFormat": "JJ:NN:SS",
            "categoryBalloonText": "[[category]]"

        },
        "chartScrollbar": {
            "enabled": True,
            "dragIcon": "dragIconRectSmall"
        },
        "trendLines": [],
        "graphs": [],
        "guides": [],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "title": ""
            }
        ],
        "allLabels": [],
        "balloon": {},
        "legend": {
            "enabled": True,
            "useGraphSettings": True,
            "color": "#D4D4D4",
        },
        "titles": [
            {
                "id": "Title-1",
                "size": 15,
                "text": ""
            }
        ],
        "dataProvider": []
    }

    date_start = app.config['DATE_START']
    date_now = datetime.datetime.now()
    challenges_graph_dict = {c_id: [] for c_id in chals.keys()}

    # compute the chart of points over time for each user
    users_graphs = []
    users_data_provider = []
    for i, board_entry in enumerate(scoreboard):
        users_graphs.append({
            "id": "mygraph-{}".format(i),
            "title": board_entry['user'],
            "valueField": "column-{}".format(i),
            "type": "line",
            "lineThickness": 3,
            "balloonText": "[[title]] [[value]]pts"})
        user_points = [[date_start.timestamp(), 0]]
        for chal_id, chal in board_entry['challenges'].items():
            if chal['timestamp'] is not None:
                user_points.append([chal['timestamp'].timestamp(), chal['points']])
                challenges_graph_dict[chal_id].append([chal['timestamp'].timestamp(), 1])

        # sort the list by date
        user_points = sorted(user_points, key=lambda x: x[0])
        # finally add the current date to the list
        user_points.append([date_now.timestamp(), 0])
        # perform the sum over all the points piled up by the current user
        for j in range(1, len(user_points)):
            user_points[j][1] += user_points[j - 1][1]
        # finally add the newly created list to the data_provider list
        for ts, pt in user_points:
            users_data_provider.append({
                "date": datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S'),
                "column-{}".format(i): pt
            })
    users_graph = deepcopy(graph_template)
    users_graph['titles'][0]['text'] = 'Players'
    users_graph['valueAxes'][0]['title'] = 'Points'
    users_graph['graphs'] = users_graphs
    users_graph['dataProvider'] = sorted(users_data_provider, key=lambda x: x['date'])

    # compute the cart of challenge solvers over time for each challenge
    challenges_graphs = []
    challenges_data_provider = []

    for i, chal in enumerate(chals.values()):
        challenges_graphs.append({
            "id": "mygraph-{}".format(i),
            "title": chal['name'],
            "valueField": "column-{}".format(i),
            "type": "line",
            "lineThickness": 3,
            "balloonText": "[[title]] solved by [[value]]"})

    for i, chal in enumerate(challenges_graph_dict.values()):
        chal_aux = chal
        chal_aux.append([date_now.timestamp(), 0])
        chal_aux = sorted(chal_aux, key=lambda x: x[0])
        for j in range(1, len(chal_aux)):
            chal_aux[j][1] += chal_aux[j - 1][1]
            # finally add the newly created list to the data_provider list
        for ts, solvers in chal_aux:
            challenges_data_provider.append({
                "date": datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S'),
                "column-{}".format(i): solvers
            })

    challenges_graph = deepcopy(graph_template)
    challenges_graph['titles'][0]['text'] = 'Challenges'
    challenges_graph['valueAxes'][0]['title'] = 'Solvers'
    challenges_graph['graphs'] = challenges_graphs
    challenges_graph['dataProvider'] = challenges_data_provider

    return {'challenges': chals, 'scoreboard': scoreboard,
            'users_graph': users_graph, 'challenges_graph': challenges_graph}


@app.route('/challenge/<name>',  methods=['GET', 'POST'])
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

@app.route('/scoreboard')
@attackdefense_mode_required
def scoreboard():
    # get the latest round
    db_conn = get_db_connection()
    with db_conn.cursor() as cur:
        cur.execute('SELECT id AS rnd, timestamp FROM rounds ORDER BY id DESC LIMIT 1')
        res = cur.fetchone()
    rnd = res['rnd']-1 if res is not None and res['rnd'] else 0

    # get the time left until the next round
    date_now = datetime.datetime.now()
    seconds_left = app.config['ROUND_DURATION']
    if rnd >= 1:
        # get seconds left till new round
        seconds_left = max(((res['timestamp'] + datetime.timedelta(seconds=app.config['ROUND_DURATION'])) - date_now).seconds, 0)

    # get all the other stuff out of the cached function
    scoreboard_data = _scoreboard(rnd)
    
    return render_template('scoreboard.html', rnd=rnd, time_left=seconds_left, **scoreboard_data)

#@cache.cached(timeout=60)
def _scoreboard(rnd):
    db_conn = get_db_connection()
    cur = db_conn.cursor()

    # retrieve the service table
    cur.execute('SELECT id, name, active FROM services')
    services = cur.fetchall()

    # retrieve the latest score of each team along with the team names'
    cur.execute((
        'SELECT T.id, T.name, T.ip, S.attack, S.defense '
        'FROM scores as S JOIN teams as T ON S.team_id = T.id '
        'WHERE round = %s'), [rnd])
    results = cur.fetchall()

    # start populating the board, it's a dictionary of dictionaries, see
    # the initialization below to grasp the structure
    board = {}
    for r in results:
        board[r['id']] = {
            'team': r['name'], 'ip': r['ip'], 'id': r['id'], 
            'attack': r['attack'], 'defense': r['defense'],
            'ratio_attack': 0, 'ratio_defense': 0, 'position': 0,
            'services': {}, 'attack_scores': [], 'defense_scores': [],
            'total_scores': []
        }

    # get services status
    cur.execute((
        'SELECT F.team_id, F.service_id, C.successful, MAX(C.timestamp) AS timestamp '
        'FROM active_flags AS F '
        'LEFT JOIN integrity_checks AS C ON '
        '     (F.flag = C.flag AND C.timestamp = (SELECT MAX(timestamp) '
        '                                         FROM integrity_checks '
        '                                         WHERE flag = F.flag)) '
        'GROUP BY F.team_id, F.service_id, C.successful'));
    services_status = cur.fetchall()
    for ss in services_status:
        board[ss['team_id']]['services'][ss['service_id']] = (ss['successful'], ss['timestamp'])
    # set default values
    for team_id in board:
        for service in services:
            try:
                _ = board[team_id]['services'][service['id']]
            except KeyError:
                board[team_id]['services'][service['id']] = (2, '???')
    # normalize scores avoiding divisions by 0. If the score table is empty
    # (it shouldn't, we can initialize it with 0s) assume the max scores to
    # be 0. The scoreboard will anyway result empty since the teams are
    # extracted from the score table
    if len(board):
        max_attack = max(max(team['attack'] for team in board.values()), 1)
        max_defense = max(max(team['defense'] for team in board.values()), 1)
    else:
        max_attack = max_defense = 0

    # get the scores of all the teams during the whole game to create some
    # nice graphs
    cur.execute('SELECT * FROM scores ORDER BY round')
    scores = cur.fetchall()
    cur.close()

    for s in scores:
        board[s['team_id']]['attack_scores'].append([int(s['round']), int(s['attack'])])
        board[s['team_id']]['defense_scores'].append([int(s['round']), int(s['defense'])])
        board[s['team_id']]['total_scores'].append([int(s['round']), int(0.6 * s['attack'] + 0.4 * s['defense'])])

    for team in board.values():
        team['ratio_attack'] = team['attack'] * 100 / max_attack
        team['ratio_defense'] = team['defense'] * 100 / max_defense
        team['score'] = 0.6 * team['ratio_attack'] + 0.4 * team['ratio_defense']

    # sort the board in descending order with respect to the score: the
    # sorted structure is a list of board values, we just leave out the
    # team id
    sorted_board = sorted([t[1] for t in board.items()],
                          key = lambda x: x['score'],
                          reverse = True)
    # add a position index to each team
    for i, team in enumerate(sorted_board):
        team['position'] = i+1

    # fill graph lists
    attack_graph = []
    defense_graph = []
    total_graph = []
    labels = []
    for team in sorted_board:
        labels.append(team['team'])
        attack_graph.append(team['attack_scores'])
        defense_graph.append(team['defense_scores'])
        total_graph.append(team['total_scores'])

    return {'services': services, 'board': sorted_board, 'labels': labels,
            'attack_graph': attack_graph, 'defense_graph': defense_graph,
            'total_graph': total_graph,
            'min_x': 0, 'max_x': rnd, 'min_y': 0, 'max_y': None}

@app.route('/credits')
def credits():
    return render_template('credits.html')

@app.route('/design')
def design():
    return render_template('design.html')

@app.route('/')
def index():
    return render_template('index.html')
