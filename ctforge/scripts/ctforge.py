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
import csv
import pkgutil
import argparse
import bcrypt
import json
import psycopg2
import urllib.parse
from shutil import copy2, rmtree
from getpass import getpass
from ctforge.database import db_connect

from ctforge import app, utils, database, users as users_module, mail as mail_module


CONFIG_FILE = os.path.expanduser('~/.ctforge/ctforge.conf')
 

def db_create_schema():
    db_conn = database.db_connect('postgres')
    db_conn.autocommit = True
    with db_conn.cursor() as cur:
        cur.execute('DROP DATABASE IF EXISTS {}'.format(app.config['DB_NAME']))
        cur.execute("CREATE DATABASE {} WITH ENCODING 'UTF8'".format(app.config['DB_NAME']))
    db_conn.close()

    db_conn = database.db_connect()
    with db_conn.cursor() as cur:
        cur.execute(pkgutil.get_data('ctforge', 'db/schema.sql'))
    db_conn.commit()
    db_conn.close()

def db_create_procedures():
    db_conn = database.db_connect()
    with db_conn.cursor() as cur:
        cur.execute(pkgutil.get_data('ctforge', 'db/procedures.sql'))
    db_conn.commit()
    db_conn.close()

def db_add_admin(name, surname, mail, nickname, password):
    db_add_user(name, surname, mail, nickname=nickname, password=password, admin=True, hidden=True)

def db_add_user(name, surname, mail, nickname=None, affiliation=None, password=None, admin=False, hidden=False, team_id=None):
    db_conn = database.db_connect()
    with db_conn.cursor() as cur:
        try:
            cur.execute((
                'INSERT INTO users (team_id, name, surname, mail, nickname, affiliation, password, admin, hidden) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'),
                [team_id, name, surname, mail, nickname, affiliation, bcrypt.hashpw(password, bcrypt.gensalt()) if password else None,
                 admin, hidden])
            db_conn.commit()
        except psycopg2.Error as e:
            db_conn.rollback()
            sys.stderr.write('Database error: {}'.format(e))
    db_conn.close()

def exit_on_resp(resp):
    if resp not in ['y', 'Y']:
        print('Goodbye...')
        sys.exit(1)

def ask(question, answer=None):
    print(question, end=' ')
    if answer is not None:
        print()
        return answer
    else:
        return input()

def init(args):
    print(('\nWelcome to the installation script of CTForge\n'
           'Please backup your {} file before continuing.\n'.format(CONF_FILE)))
    
    resp = ask('Do you want to proceed? (y/n)', 'y' if args.yes else None)
    exit_on_resp(resp)
    
    print('[*] Creating database schema')
    db_create_schema()

    print('[*] Installing SQL procedures')
    db_create_procedures()

    print('[*] Adding an administrative user')

    admin_name = ask('    name:', args.name)
    admin_surname = ask('    surname:', args.surname)
    admin_nickname = ask('    nickname:', args.nickname)
    admin_mail = ask('    mail:', args.mail)
    if args.password is None:
        admin_password = getpass('    password: ')
        admin_password_rep = getpass('    re-enter the password: ')
        if admin_password != admin_password_rep:
            sys.stderr.write("Passwords don't match, aborting!")
            sys.exit(1)
    else:
        admin_password = args.password

    db_add_admin(admin_name, admin_surname, admin_mail,
                 admin_nickname, admin_password)

    resp = ask('Save configuration to {} ? (y/n)'.format(CONFIG_FILE), 'y' if args.yes else None)
    exit_on_resp(resp)
    os.makedirs(os.path.dirname(CONFIG_FILE), mode=0o700, exist_ok=True)
    try:
        copy2(args.conf, CONFIG_FILE)
    except Exception as e:
        sys.stderr.write('Error: "{}"\n'.format(args.conf, CONFIG_FILE, e))

    if app.config['LOG_FILE'] is not None:
        logfile = app.config['LOG_FILE']
        if not os.path.exists(logfile):
            logdir = os.path.dirname(logfile)
            resp = ask('Create log dir {} ? (y/n)'.format(logdir), 'y' if args.yes else None)
            exit_on_resp(resp)
            os.makedirs(logdir, mode=0o700, exist_ok=True)
            resp = ask('Create log file {} ? (y/n)'.format(logfile), 'y' if args.yes else None)
            exit_on_resp(resp)
            os.mknod(logfile, mode=0o600)

def run(args):
    debug = args.debug or app.config['DEBUG']
    app.run(host=args.host, port=args.port, debug=debug, threaded=True)

def users_reader(file):
    return csv.DictReader(file, fieldnames=['id', 'surname', 'name', 'mail'], delimiter='\t', quotechar='"')

def imp(args):
    if args.users:
        print('Importing users...')
        users = users_reader(args.users)
        for user in users:
            db_add_user(name=user['name'], surname=user['surname'], mail=user['mail'], affiliation=args.affiliation)
        args.users.close()
        print('Done!')

def fix_affiliations(args):
    users = {}

    r1 = users_reader(args.file1)
    for u in r1:
        u['affiliation'] = args.aff1
        users[u['mail']] = u
    args.file1.close()

    r2 = users_reader(args.file2)
    for u in r2:
        try:
            user = users[u['mail']]
            user['affiliation'] += ', ' + args.aff2
        except KeyError:
            u['affiliation'] = args.aff2
            users[u['mail']] = u
    args.file2.close()

    db_conn = database.db_connect()
    print('[*] Fixing users affiliations')
    with db_conn.cursor() as cur:
        try:
            for u in users.values():
                cur.execute('UPDATE users SET affiliation = %s WHERE mail = %s', [u['affiliation'], u['mail']])
                if cur.rowcount != 1:
                    print('[!] User {} (mail {}) not in the DB!'.format(u['name'] + ' ' + u['surname'], u['mail']))
        except psycopg2.Error as e:
            db_conn.rollback()
            sys.stderr.write('Database error: {}'.format(e))
        else:
            db_conn.commit()
    db_conn.close()

def imp_chal(chal_info_file, public_folder):
    chal_info = json.loads(chal_info_file.read())
    print('Importing challenge `{}`...'.format(chal_info['title']))
    db_conn = db_connect()
    db_conn.autocommit = True
    with db_conn.cursor() as cur:
        # NOTE: need to manually copy public files to the webserver public folder
        description = chal_info['description']
        if chal_info['public_files']:
            description += '<br><br><p><b>Public Files:</b></p><ul>'
            for f in chal_info['public_files']:
                description += '<li><a href="{}">{}</a></li>'.format(
                    os.path.join(public_folder, f), f)
            description += '</ul>'
        cur.execute('INSERT INTO challenges (name, description, flag, points, '
                    'tags, hidden, writeup) VALUES (%s,%s,%s,%s,%s,%s,%s)',
                    [chal_info['title'], description, chal_info['flag'],
                     chal_info['points'], '/'.join(chal_info['tags']),
                     True, False])
    db_conn.close()
    print('Done.')

def send_activation_links(args):
    from time import sleep
    
    db_conn = database.db_connect()
    with db_conn.cursor() as cur:
        if args.mails:
            cur.execute('SELECT * FROM users WHERE password IS NULL AND mail = ANY(%s)',
                        [args.mails])
        else:
            cur.execute('SELECT * FROM users WHERE password IS NULL')
        users = cur.fetchall()

    if args.mails:
        mails = {user['mail'] for user in users}
        for mail in args.mails:
            if mail not in mails:
                print('[!] Skipping {}: either the mail is not in the DB or the user is already active'.format(mail))

    for n, user in enumerate(users):
        # wait 60 seconds every 20 mails to avoid too many consecutive connections
        if n > 0 and n % 20 == 0:
            sleep(60)
        mail_module.send_activation_link(users_module.User(**user))

def imp_grades(args):
    db_conn = db_connect()

    print('[*] Importing grades...')
    with db_conn.cursor() as cur:
        cur.execute('SELECT id FROM challenges WHERE name = %s', [args.challenge])
        chall_id = cur.fetchone()['id']

        with open(args.csv, 'r', newline='') as f:
            reader = csv.DictReader(f, delimiter='|', quotechar='"')

            try:
                for line in reader:
                    cur.execute('INSERT INTO challenges_evaluations (user_id, challenge_id, grade, feedback) '
                                'VALUES (%s, %s, %s, %s)', [line['user_id'], chall_id, line['grade'], line['comment']])
            except psycopg2.Error as e:
                db_conn.rollback()
                sys.stderr.write('Database error: {}'.format(e))
            except KeyError as e:
                # no need to rollback, this exception is raised before any insert is performed
                sys.stderr.write('Malformed CSV, missing column `{}`'.format(e.args[0]))
            else:
                db_conn.commit()
                print('[*] Done.')

    db_conn.close()

def export_writeups(args):
    rmtree(args.dir, ignore_errors=True)
    os.mkdir(args.dir)

    db_conn = db_connect()
    with db_conn.cursor() as cur:
        cur.execute('SELECT id FROM challenges WHERE name = %s', [args.challenge])
        chall_id = cur.fetchone()['id']

        cur.execute('SELECT DISTINCT user_id FROM writeups WHERE challenge_id = %s', [chall_id])
        users = cur.fetchall()

    for u in users:
        with db_conn.cursor() as cur:
            cur.execute('SELECT name, surname, mail FROM users WHERE id = %s', [u['user_id']])
            usr = cur.fetchone()

            cur.execute(
                'SELECT writeup, timestamp FROM writeups '
                'WHERE user_id = %s AND challenge_id = %s ORDER BY timestamp DESC',
                [u['user_id'], chall_id])
            writeups = cur.fetchall()

        with open('{}/writeup-{}.txt'.format(args.dir, u['user_id']), 'w') as f:
            f.write('{} {} ({})\n\n'.format(usr['name'], usr['surname'], usr['mail']))
            f.write('\n\n*-*-*-*-*-*-*-*-*-*-*\n\n'.join(
                'Submission time: {}\n{}'.format(w['timestamp'], w['writeup']) for w in writeups))

def create_csv_grading(args):
    db_conn = db_connect()

    with db_conn.cursor() as cur:
        cur.execute('SELECT w.user_id, u.name, u.surname, w.id AS challenge_id '
                    'FROM writeups w JOIN challenges c ON w.challenge_id = c.id JOIN users u ON w.user_id = u.id '
                    'WHERE c.name = %s AND w.timestamp = ('
                    '  SELECT MAX(timestamp) FROM writeups WHERE user_id = w.user_id AND challenge_id = w.challenge_id'
                    ') '
                    'ORDER BY w.user_id', [args.challenge])
        writeups = cur.fetchall()

    for w in writeups:
        w['user_name'] = w['name'] + ' ' + w['surname']
        w['latest_writeup'] = urllib.parse.urljoin(app.config['URL'], '/writeup/'+str(w['challenge_id']))

    with open(args.csv, 'w', newline='') as f:
        fields = ['user_id', 'user_name', 'latest_writeup', 'grade', 'excellent', 'unusual', 'comment']
        writer = csv.DictWriter(f, fieldnames=fields, delimiter='|', quotechar='"', extrasaction='ignore')
        writer.writeheader()
        writer.writerows(writeups)

def exp_writeups(args):
    if args.dir is not None:
        export_writeups(args)
    if args.csv is not None:
        create_csv_grading(args)

def parse_args():
    parser = argparse.ArgumentParser(description='Initialize or run CTForge')
    parser.add_argument('-c', '--conf', dest='conf', type=str,
                        default=CONFIG_FILE, help='Configuration file')
    subparsers = parser.add_subparsers(dest='command')

    parser_init = subparsers.add_parser('init', help='Install and initialize the framework')
    parser_init.add_argument('-n', '--name', type=str, help='Administrator name')
    parser_init.add_argument('-s', '--surname', type=str, help='Administrator surname')
    parser_init.add_argument('-k', '--nickname', type=str, help='Administrator nickname')
    parser_init.add_argument('-m', '--mail', type=str, help='Administrator mail')
    parser_init.add_argument('-p', '--password', type=str, help='Administrator password (unsafe)')
    parser_init.add_argument('-y', '--yes', action='store_true', help='Say Yes to all questions')

    parser_run = subparsers.add_parser('run', help='Run an instance of the framework for development purposes')
    parser_run.add_argument('-H', '--host', type=str, help='Hostname to listen on', default='127.0.0.1')
    parser_run.add_argument('-P', '--port', type=int, help='Port to listen on', default=5000)
    parser_run.add_argument('-D', '--disable-debug', dest='debug', action='store_false', help='Disable debug mode')

    parser_import = subparsers.add_parser('import_users', help='Import users')
    parser_import.add_argument('-u', '--users', type=argparse.FileType('r', encoding='utf16'), required=True,
                               help='A UTF-16 csv file of users to import, as generated by TISS. The supported format is: name, surname, mail. No header and tab as separator')
    parser_import.add_argument('-a', '--affiliation', type=str, default=None, help='Specify a single affiliation for all the imported users')

    parser_fix_affiliation = subparsers.add_parser('fix_affiliations', help='Fix affiliations of users in the DB')
    parser_fix_affiliation.add_argument('file1', type=argparse.FileType('r', encoding='utf16'), help='First CSV file of users')
    parser_fix_affiliation.add_argument('aff1', type=str, help='Affiliation of users in the first CSV')
    parser_fix_affiliation.add_argument('file2', type=argparse.FileType('r', encoding='utf16'), help='Second CSV file of users')
    parser_fix_affiliation.add_argument('aff2', type=str, help='Affiliation of users in the second CSV')

    parser_send_act_link = subparsers.add_parser('send_activation_links', help='Send activation links to users via mail')
    parser_send_act_link.add_argument('-u', '--user', type=str, help='Email address used to send links', required=True)
    parser_send_act_link.add_argument('-p', '--password', type=str, help='Password of the account used to send emails', required=True)
    parser_send_act_link.add_argument('-m', '--mails', nargs='+', help='Send the email only to these addresses')

    parser_challenge = subparsers.add_parser('import_challenge', help='Import challenge')
    parser_challenge.add_argument('challenge', type=argparse.FileType('r'), help='Challenges folder in which each subdirectory contains an `info.json` file')
    parser_challenge.add_argument('--public-files-uri', default='/data/public_files/', help='Webserver public folder')

    parser_grades = subparsers.add_parser('import_grades', help='Import grades from CSV file')
    parser_grades.add_argument('challenge', type=str, help='Name of the challenge')
    parser_grades.add_argument('csv', type=str, help='File containing grades')

    parser_export = subparsers.add_parser('export_writeups', help='Export writeups')
    parser_export.add_argument('challenge', type=str, help='Name of the challenge')
    parser_export.add_argument('-d', '--dir', type=str, help='Directory where to save writeups')
    parser_export.add_argument('-f', '--csv', type=str, help='File for grading')

    return parser.parse_args()

def main():
    global config

    args = parse_args()
    if args.conf is not None:
        print('[*] Reading configuration from {}'.format(args.conf))
        sys.stdout.flush()

        try:
            config = utils.parse_conf(args.conf)
        except Exception:
            sys.stderr.write('Invalid configuration file, aborting!')
            sys.exit(1)

        # update the global app configuration
        app.config.update(config)

    if args.command == 'run':
        run(args)
    elif args.command == 'init':
        init(args)
    elif args.command == 'import_users':
        imp(args)
    elif args.command == 'fix_affiliations':
        fix_affiliations(args)
    elif args.command == 'send_activation_links':
        send_activation_links(args)
    elif args.command == 'import_challenge':
        imp_chal(args.challenge, args.public_files_uri)
    elif args.command == 'import_grades':
        imp_grades(args)
    elif args.command == 'export_writeups':
        exp_writeups(args)
    else:
        sys.stderr.write("... Doing nothing, bye\n")
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
