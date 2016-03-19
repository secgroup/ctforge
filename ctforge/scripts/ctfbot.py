#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
The ctf swiss army knife: round initializer, flag dispatcher, service checker

This program can be used in three different modes, depending on the current
task we want to execute.

In advance mode, the script calls a stored procedure to prepare the database
for a new round and inserts fresh flags for all the service, team pairs. In
dispatch mode, all the flags are sent to the teams' vms by calling an external
script. In check mode, each service is tested by executing a script that
performs a safe access and retrieves the flag. The return code of the script
represents the status of the service, which is then saved into the database for
being used later during the score computation phase.

"""

import os
import sys
import signal
import string
import random
import argparse
import logging
import gevent
import ConfigParser
import mysql.connector as dbc
from gevent import Greenlet, Timeout, subprocess, sleep
from gevent.queue import Queue

__authors__     = ["Marco Squarcina <msquarci at dais.unive.it>",
                   "Mauro Tempesta <mtempest at dais.unive.it>"]
__license__     =  "MIT"
__copyright__   =  "Copyright 2013-15, University of Venice"

# global variables

# queue of tasks: each task is a pair (i_team, i_service)
tasks = Queue()
# seconds to wait before killing a spawned script
timeout = None
# flag format
flag_prefix = ''
flag_suffix_length = ''
# parameters for connecting to the database
db_config = {}
dispatch_script_path = ''
check_script_path = ''

class Team:
    """Simple class for representing a team entity, storing the id (idt), ip
    and team name (name)."""

    def __init__(self, idt, ip, name):
        # team id
        self.idt = idt
        # ip of the vulnerable machine of the team
        self.ip = ip
        # gang name for the team
        self.name = name

class Service:
    """Simple class for representing a service entity, storing the id (ids) and
    service name (name)."""

    def __init__(self, ids, name, active):
        # service id
        self.ids = ids
        # name of the service
        self.name = name
        # whether the service is active or not
        self.active = active

class Worker(Greenlet):
    """The main execution unit while in dispatch/check mode."""

    def __init__(self, n, dispatch, check):
        Greenlet.__init__(self)
        # numeric identifier of the worker
        self.n = n
        # team instance being processed
        self.team = None
        # service instance processed
        self.service = None
        # current flag for the pair (team, service)
        self.flag = ''
        # worker modalities 
        self.dispatch = dispatch
        self.check = check

    def _run(self):
        """Extract and execute jobs from the tasks queue until there is
        nothing left to do."""

        # initialize the connection to the DB
        self.db = Database(db_config)
        self.cursor = self.db.cnx.cursor()

        # fetch tasks from the queue
        while not tasks.empty():
            (self.team, self.service) = tasks.get()
            # get the active flag for this team/service
            self._get_flag()
            # check whether we need to dispatch the flag or check the service
            # status and proceed according to the given mode. The program logic
            # is not f*cked if we execute both actions. Theoretically, one
            # could advance the round, dispatch new flags and check services
            # with a single execution of this script
            if self.dispatch:
                self._dispatch_flag()
            if self.check:
                self._check_service()
        # close the DB connection
        self.cursor.close()
        self.db.close()

    def _get_flag(self):
        """Retrieve the active flag for the current (team, service) pair by
        querying the active_flags table."""

        query = ('SELECT flag '
                 'FROM active_flags '
                 'WHERE team_id = %s AND service_id = %s')
        try:
            self.cursor.execute(query, (self.team.idt, self.service.ids))
            self.flag = self.cursor.fetchone()[0]
        except:
            # no flag in the database? This is weird
            logging.critical(self._logalize("Error while getting the flag, "
                                            "aborting."))
            sys.exit(1)

    def _dispatch_flag(self):
        """Send the flag to a given team for a given service by executing an
        external script. The script is killed if it takes too long to
        complete."""

        # execute the script ignoring its return status
        self._execute(dispatch_script_path + '/' + self.service.name)

    def _check_service(self):
        """Check if a given service on a given host is working as expected by
        executing an external script. The return value of each script is
        recorded and processed according to the following rule:

        *    0:     service is working fine
        *   -1:     oserror while executing the script, since it's probably our
                    fault we do not add any record in the integrity_checks table
        * >125:     the shell spawned by Popen is unable to execute the script,
                    it's probably our fault as above
        * else:     the service is corrupted

        The script is killed if it takes too long to complete and the 
        service marked as corrupted."""

        # execute the script using its return value to determine the service
        # status
        status = self._execute(check_script_path + '/' +  self.service.name)
        if status == -1 or status > 125:
            return
        success = 1 if status == 0 else 0
        query = ("INSERT INTO integrity_checks "
                 "(flag, successful) "
                 "VALUES (%s, %s)")
        try:
            self.cursor.execute(query, (self.flag, success))
            self.db.cnx.commit()
        except dbc.Error as e:
            # another error occurred, no recovery possible
            logging.critical(self._logalize(("Unable to insert the integrity "
                                             "check report: {}").format(e)))
        else:
            # update successful
            logging.debug(self._logalize("Status added as {}".format(status)))

    def _execute(self, script_name):
        """Execute the provided script killing the process if it timeouts."""

        # set status of the service to corrupted by default
        status = 1
        command = ' '.join([script_name, self.team.ip, self.flag])
        timer = Timeout(timeout)
        timer.start()
        try:
            logging.debug(self._logalize("Executing {}".format(command)))
            process = subprocess.Popen(command, preexec_fn=os.setsid,
                                       shell=True)
            # ignore stdout and stderr
            process.communicate()
            status = process.returncode
        except Timeout:
            # the remote VM could be down, this is not a critical error but we
            # should anyway give it a look 
            logging.warning(self._logalize(("Timeout exceeded while executing "
                                            "{}").format(command)))
            # kill the process tree gently and wait a small amount of time for
            # the process to clear resources
            try:
                os.killpg(process.pid, signal.SIGTERM)
                sleep(3)
                # check if the process has terminated and in this case try to
                # kill it with a SIGKILL
                if process.poll() != None:
                    os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                # the program already terminated 
                pass
        except Exception as e:
            # wtf happened? this is an unknown error. Assume it's our fault
            status = -1
            logging.critical(self._logalize(("Error while executing "
                                             "{}: {}").format(command, e)))
        finally:
            timer.cancel()

        return status

    def _logalize(self, message):
        """Return a pretty string ready to be logged."""

        return 'Worker-{} ({}, {}): {}'.format(self.n, self.team.ip, 
                                               self.service.name, message)

class Database:
    def __init__(self, config):
        try:
            self.cnx = dbc.connect(**config)
        except dbc.Error as e:
            if e.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                logging.critical(("Wrong username or password during database "
                                  "connection, aborting"))
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                logging.critical("Database does not exist, aborting")
            else:
                logging.critical(("Error while connecting to the database, "
                                  "aborting: {}").format(e))
            sys.exit(1)

    def close(self):
        try:
            self.cnx.close()
        except dbc.Error as e:
            logging.critical("Error while closing the database connection")


def get_teams_services():
    """Retrieve the lists of team and service instances."""

    db = Database(db_config)
    query_teams = ("SELECT id, ip, name FROM teams")
    query_services = ("SELECT id, name, active FROM services")
    try:
        cursor = db.cnx.cursor()
        cursor.execute(query_teams)
        teams = [Team(*t) for t in cursor.fetchall()]
        cursor.execute(query_services)
        services = [Service(*s) for s in cursor.fetchall() if s[2] == 1]
    except dbc.Error as e:
        logging.critical(("Error while quering the database, "
                          "aborting: {}").format(e))
        sys.exit(1)
    finally:
        try:
            cursor.close()
        except:
            logging.critical("Unable to close the database cursor")
    db.close()

    return (teams, services)

def advance_round():
    """Advance the round: update results, truncate the active_flags table and
    store new flags in the database for each team and service."""

    (teams, services) = get_teams_services()
    
    db = Database(db_config)
    cursor = db.cnx.cursor()
    # advance the round and clear the flag tables
    try:
        rnd = cursor.callproc('switch_round', (0, ))[0]
    except dbc.Error as e:
        logging.critical(("Error while incrementing the round, "
                          "aborting: {}").format(e))
        sys.exit(1)
    db.cnx.commit()
    if not rnd: rnd = 1
    logging.info("Round {} started".format(rnd))
    # generate and insert the new flags to the database
    query = ('INSERT INTO flags '
             '(flag, team_id, service_id, round) '
             'VALUES (%s, %s, %s, %s)')
    for service in services:
        for team in teams:
            inserted = False
            while not inserted:
                flag = generate_flag()
                try:
                    cursor.execute(query, (flag, team.idt, service.ids, rnd))
                except dbc.IntegrityError:
                    logging.warning("Duplicate flag, generating a new one")
                except Exception as e:
                    logging.critical(("Error while adding a new flag to the "
                                      "database, aborting: {}").format(e))
                    sys.exit(1)
                else:
                    inserted = True
                    logging.debug(("New flag just added to the "
                                   "database: {}").format(flag))
    # committing all the new INSERTs
    db.cnx.commit()
    cursor.close()
    db.close()

def generate_flag():
    """Generate a random flag according to the provided config."""

    return flag_prefix + ''.join(random.choice(string.letters + string.digits)
                                 for _ in range(flag_suffix_length))

def main():
    global timeout, db_config, flag_prefix, flag_suffix_length, \
           dispatch_script_path, check_script_path

    # parse command line options, the round parameter is required
    parser = argparse.ArgumentParser(description='Flag dispatcher and checker')
    parser.add_argument('--advance', action='store_true', default=False,
        help="Advance the current round")
    parser.add_argument('--dispatch', action='store_true', default=False,
        help="Dispatch new flags to all the virtual machines")
    parser.add_argument('--check', action='store_true', default=False,
        help="Check the integrity of the services")
    parser.add_argument('-n',  dest='num_workers', type=int, default=1,
        help="Number of concurrent workers (default 1)")
    parser.add_argument('-t', dest='timeout', type=int, default=10,
        help="Seconds to wait before killing a spawned script (default 10)")
    parser.add_argument('-v', dest='verbose', action='store_true', 
        default=False, help="Set logging level to debug")
    args = parser.parse_args()
    if not any([args.advance, args.dispatch, args.check]):
        sys.stderr.write("At least one action is required, aborting.\n")
        sys.exit(1)
    # parse the shared configuration file. The SafeConfigParser class allows to
    # escape format strings by doubling the % sign, while ConfigParser does
    # not, meh...
    config = ConfigParser.SafeConfigParser()
    try:
        config.read('/opt/dctf/ctf.conf')
        db_config = {
            'user': config.get('database', 'user'),
            'password': config.get('database', 'password'),
            'host': config.get('database', 'host'),
            'database': config.get('database', 'name'),
            'raise_on_warnings': True
        }
        log_file = config.get('bot', 'log_file')
        log_format = config.get('bot', 'log_format')
        flag_prefix = config.get('bot', 'flag_prefix')
        flag_suffix_length = config.getint('bot', 'flag_suffix_length')
        dispatch_script_path = config.get('bot', 'dispatch_script_path')
        check_script_path = config.get('bot', 'check_script_path')
    except ConfigParser.NoOptionError as e:
        sys.stderr.write(("Malformed configuration file, aborting:\n"
                          "{}").format(e))
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(("Error while parsing the configuration, aborting:\n"
                          "{}").format(e))
        sys.exit(1)
    # set variables
    n_workers = args.num_workers
    timeout = args.timeout
    log_level = logging.DEBUG if args.verbose else logging.INFO
    # set logging
    try:
        logging.basicConfig(filename=log_file, format=log_format, 
                            level=log_level)
    except IOError:
        sys.stderr.write(("Unable to write logs to "
                          "{}, aborting\n".format(log_file)))
        sys.exit(1)
    if args.advance:
        # advance the round
        advance_round()
    if args.check or args.dispatch:
        # retrieve the list of teams and services
        (teams, services) = get_teams_services()
        # fill the queue of tasks, choosing the team order randomly :)
        for service in services:
            for team in random.sample(teams, len(teams)):
                tasks.put_nowait((team, service))
        # create the list of workers
        workers = []
        for i in range(n_workers):
            workers.append(Worker(i, args.dispatch, args.check))
            workers[-1].start()
        # join all workers
        gevent.joinall(workers)

    # exit gracefully
    sys.exit(0)

if __name__ == "__main__":
    main()
