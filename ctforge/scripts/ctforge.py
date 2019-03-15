#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import csv
import pkgutil
import argparse
import bcrypt
import json
import psycopg2
import smtplib
from shutil import copy2
from getpass import getpass
from ctforge.database import db_connect

from ctforge import app, utils, database

def db_create_schema():
    # db_conn = database.db_connect('postgres')
    # db_conn.autocommit = True
    # with db_conn.cursor() as cur:
    #     cur.execute('DROP DATABASE IF EXISTS {}'.format(app.config['DB_NAME']))
    #     cur.execute("CREATE DATABASE {} WITH ENCODING 'UTF8'".format(app.config['DB_NAME']))
    # db_conn.close()

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
    db_add_user(name, surname, mail, nickname=nickname, password=password, active=True, admin=True, hidden=True)

def db_add_user(name, surname, mail, nickname=None, affiliation=None, password=None, active=False, admin=False, hidden=False, team_id=None):
    db_conn = database.db_connect()
    with db_conn.cursor() as cur:
        try:
            cur.execute((
                'INSERT INTO users (team_id, name, surname, mail, nickname, affiliation, password, active, admin, hidden) '
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'),
                [team_id, name, surname, mail, nickname, affiliation, bcrypt.hashpw(password, bcrypt.gensalt()) if password else None,
                 active, admin, hidden])
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
    confile = os.path.expanduser('~/.ctforge/ctforge.conf')
    print(('\nWelcome to the installation script of CTForge\n'
           'Please backup your {} file before continuing.\n'.format(confile)))
    
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

    resp = ask('Save configuration to {} ? (y/n)'.format(confile), 'y' if args.yes else None)
    exit_on_resp(resp)
    os.makedirs(os.path.dirname(confile), mode=0o700, exist_ok=True)
    try:
        copy2(args.conf, confile)
    except Exception as e:
        sys.stderr.write('Error: "{}"\n'.format(args.conf, confile, e))

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
                    'tags, active, hidden, writeup) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                    [chal_info['title'], description, chal_info['flag'],
                     chal_info['points'], '/'.join(chal_info['tags']),
                     False, True, False])
    db_conn.close()
    print('Done.')

def send_activation_links(args):

    def send_email(from_email, from_password, to_email, email_text):
        import unicodedata

        email_text = unicodedata.normalize('NFKD', email_text).encode('ascii', 'ignore')
        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.ehlo()
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, email_text)
            server.close()
            print('Email to {} has been successfully sent!'.format(to_email))
        except Exception as e:  
            print('Error while sending email to {}: {}'.format(to_email, e))

    from_email = args.user
    from_password = args.password
    subject = 'WUTCTF Activation Link'
    body = (
        'Hello {},\n\n'
        'please click on the link below to activate your profile:\n\n{}\n\n'
        'The basic access authentication credentials are user: wutctf2019, password: wutctf2019\n\n'
        'Try to be polite when setting a nickname, '
        'it will identify you on the public scoreboard.\n\nHack the planet!')
    
    db_conn = database.db_connect()
    with db_conn.cursor() as cur:
        if args.mails:
            cur.execute('SELECT * FROM users WHERE active = FALSE AND token IS NOT NULL AND mail = ANY(%s)',
                        [args.mails])
        else:
            cur.execute('SELECT * FROM users WHERE active = FALSE AND token IS NOT NULL')
        users = cur.fetchall()

    if args.mails:
        mails = {user['mail'] for user in users}
        for mail in args.mails:
            if mail not in mails:
                print('[!] Skipping {}: either the mail is not in the DB or the user is already active'.format(mail))

    for user in users:
        email_text = (
            'From: {}+noreply\n'
            'To: {}\n'
            'Subject: {}\n\n'
            '{}').format(
                from_email, user['mail'], subject, body.format(
                    user['name'], 'https://wutctf.space/activate/{}'.format(
                        user['token']
                    )
                )
            )
        send_email(from_email, from_password, user['mail'], email_text)


def parse_args():
    parser = argparse.ArgumentParser(description='Initialize or run CTForge')
    parser.add_argument('-c', '--conf', dest='conf', type=str,
                        default='ctforge.conf', help='Configuration file')
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

    parser_challenge = subparsers.add_parser('import_challenge', help='Import Challenge')
    parser_challenge.add_argument('challenge', type=argparse.FileType('r'), help='Challenges folder in which each subdirectory contains an `info.json` file')
    parser_challenge.add_argument('--public-files-uri', default='/data/public_files/', help='Webserver public folder')

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
    else:
        sys.stderr.write("... Doing nothing, bye\n")
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
