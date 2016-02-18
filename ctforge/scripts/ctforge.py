#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pkgutil
import argparse
import bcrypt
from shutil import copy2
from getpass import getpass

from ctforge import app, utils, database

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

def db_add_admin(name, surname, mail, password):
    db_conn = database.db_connect()
    with db_conn.cursor() as cur:
        cur.execute((
            'INSERT INTO users (name, surname, mail, password, admin, hidden) '
            'VALUES (%s, %s, %s, %s, TRUE, TRUE)'),
            [name, surname, mail, bcrypt.hashpw(password, bcrypt.gensalt())])
    db_conn.commit()
    db_conn.close()    

def exit_on_resp(resp):
    if resp not in ['y' , 'Y']:
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
           'Please backup your ~/.ctforge/ctforge.conf file before continuing.\n'))
    
    resp = ask('Do you want to proceed? (y/n)', 'y' if args.yes else None)
    exit_on_resp(resp)
    
    print('[*] Creating database schema')
    db_create_schema()

    print('[*] Installing SQL procedures')
    db_create_procedures()

    print('[*] Adding an administrative user')

    admin_name = ask('    name:', args.name)
    admin_surname = ask('    surname:', args.surname)
    admin_mail = ask('    mail:', args.mail)
    if args.password is None:
        admin_password = getpass('    password: ')
        admin_password_rep = getpass('    re-enter the password: ')
        if admin_password != admin_password_rep:
            sys.stderr.write("Passwords don't match, aborting!")
            sys.exit(1)
    else:
        admin_password = args.password

    db_add_admin(admin_name, admin_surname, admin_mail, admin_password)

    resp = ask('Save configuration to ~/.ctforge/ctforge.conf ? (y/n)', 'y' if args.yes else None)
    exit_on_resp(resp)
    os.makedirs(os.path.expanduser('~/.ctforge/'), mode=0o700, exist_ok=True)
    copy2(args.conf, os.path.expanduser('~/.ctforge/ctforge.conf'))

    if app.config['LOG_FILE'] is not None:
        logfile = os.path.expanduser(app.config['LOG_FILE'])
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
    app.run(host=args.host, port=args.port, debug=debug)

def parse_args():
    parser = argparse.ArgumentParser(description='Initialize or run CTForge')
    parser.add_argument('-c', '--conf', dest='conf', type=str,
        help='Configuration file')
    subparsers = parser.add_subparsers(dest='command')

    parser_init = subparsers.add_parser('init', help='Install and initialize the framework')
    parser_init.add_argument('-n', '--name', type=str, help='Administrator name')
    parser_init.add_argument('-s', '--surname', type=str, help='Administrator surname')
    parser_init.add_argument('-m', '--mail', type=str, help='Administrator mail')
    parser_init.add_argument('-p', '--password', type=str, help='Administrator password (unsafe)')
    parser_init.add_argument('-y', '--yes', action='store_true', help='Say Yes to all questions')

    parser_run = subparsers.add_parser('run', help='Run an instance of the framework for development purposes')
    parser_run.add_argument('-H', '--host', type=str, help='Hostname to listen on', default='127.0.0.1')
    parser_run.add_argument('-P', '--port', type=int, help='Port to listen on', default=5000)
    parser_run.add_argument('-D', '--disable-debug', dest='debug', action='store_false', help='Disable debug mode')

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
    else:
        sys.stderr.write("... Doing nothing, bye\n")
        sys.exit(1)

    sys.exit(0)

if __name__ == '__main__':
    main()