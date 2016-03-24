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
import random
import argparse
import logging
import threading
import subprocess
import os.path
from queue import Queue
import psycopg2

from ctforge import database, utils, config


__authors__     = ["Marco Squarcina <msquarci at dais.unive.it>",
                   "Mauro Tempesta <mtempest at dais.unive.it>"]
__license__     =  "MIT"
__copyright__   =  "Copyright 2013-16, University of Venice"

# global variables

# custom logger
logger = logging.getLogger('bot')
# queue of tasks: each task is a pair (i_team, i_service)
tasks = Queue()
# seconds to wait before killing a spawned script
timeout = None
# just one connection to the database for all the threads
db_conn = None

def abort():
    """Terminate the program after if it is not possible to proceed."""

    # close the database connection
    if db_conn is not None:
        db_conn.close()
    sys.exit(1)

class Team:
    """Simple class for representing a team entity, storing the id ip
    and team name (name)."""

    def __init__(self, id, ip, name):
        # team id
        self.id = id
        # ip of the vulnerable machine of the team
        self.ip = ip
        # gang name for the team
        self.name = name

    def __repr__(self):
        return 'Team: {}, {}, {}'.format(self.id, self.ip, self.name)

class Service:
    """Simple class for representing a service entity, storing the id and
    service name (name)."""

    def __init__(self, id, name, active):
        # service id
        self.id = id
        # name of the service
        self.name = name
        # whether the service is active or not
        self.active = active

    def __repr__(self):
        return 'Service: {}, {}, {}'.format(self.id, self.name, self.active)

class Worker(threading.Thread):
    """The main execution unit while in dispatch/check mode."""

    def __init__(self, n, dispatch, check):
        super(Worker, self).__init__()
        # numeric identifier of the worker
        self.n = n
        # team instance being processed
        self.team = None
        # service instance processed
        self.service = None
        # current flag for the pair (team, service)
        self.flag = None
        # worker modalities 
        self.dispatch = dispatch
        self.check = check

    def run(self):
        """Extract and execute jobs from the tasks queue until there is
        nothing left to do."""

        # fetch tasks from the queue
        while not tasks.empty():
            self.team, self.service = tasks.get()
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

    def _get_flag(self):
        """Retrieve the active flag for the current (team, service) pair by
        querying the active_flags table."""

        try:
            with db_conn.cursor() as cur:
                cur.execute((
                    'SELECT flag FROM active_flags '
                    'WHERE team_id = %s AND service_id = %s')
                    , [self.team.id, self.service.id])
                res = cur.fetchone()
        except psycopg2.Error as e:
            logger.critical(self._logalize('Error while accessing the active flag table, aborting: {}'.format(e)))
            abort()

        if res is None:
            # the active_flags table must be empty, this should never happend
            logger.critical(self._logalize('The active_flags table did not return a flag for the current team/service, aborting'))
            abort()

        self.flag = res['flag']

    def _dispatch_flag(self):
        """Send the flag to a given team for a given service by executing an
        external script. The script is killed if it takes too long to
        complete."""

        # execute the script ignoring its return status
        self._execute(os.path.join(config['DISPATCH_SCRIPT_PATH'], self.service.name))

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

        # execute the script and assume the service status by the return address
        status = self._execute(os.path.join(config['CHECK_SCRIPT_PATH'], self.service.name))
        if status == -1 or status > 125:
            # our fault: we don't add anything in the integrity_checks table
            return
        success = status == 0
        try:
            with db_conn.cursor() as cur:
                cur.execute((
                    'INSERT INTO integrity_checks (flag, successful) '
                    'VALUES (%s, %s)')
                    , [self.flag, success])
            db_conn.commit()
        except psycopg2.Error as e:
            # an error occurred, no recovery possible
            logger.critical(self._logalize(('Unable to insert the integrity check report: {}').format(e)))
        else:
            # update successful
            logger.debug(self._logalize('Status added as {}'.format(status)))

    def _execute(self, script_name):
        """Execute the provided script killing the process if it timeouts."""

        # set status of the service to corrupted by default
        status = 1
        command = ' '.join([script_name, self.team.ip, self.flag])
        try:
            logger.debug(self._logalize("Executing {}".format(command)))
            # ignore stdout and stderr
            process = subprocess.Popen([script_name, self.team.ip, self.flag], preexec_fn=os.setsid,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            process.communicate(timeout=timeout)
            status = process.returncode
        except subprocess.TimeoutExpired:
            # the remote VM could be down, this is not a critical error but we
            # should anyway give it a look 
            logger.warning(self._logalize("Timeout exceeded while executing {}".format(command)))
            # politely kill the process tree and wait a small amount of time for
            # the process to clear resources
            process.terminate()
            time_tmp = time.time()
            while process.poll() is None and time.time() < (time_tmp + 3):
                time.sleep(0.1)
            if process.poll() is None:
                process.kill()
        except FileNotFoundError as e:
            logger.error(self._logalize('Script not found: {}'.format(e)))
        except ProcessLookupError:
            # we tried to kill an already terminated program or the script is not found
            pass
        except Exception as e:
            # wtf happened? this is an unknown error. Assume it's our fault
            status = -1
            logger.critical(self._logalize('Error while executing {}: {}'.format(command, e)))

        return status

    def _logalize(self, message):
        """Return a pretty string ready to be logged."""

        return 'Worker-{} ({}, {}): {}'.format(self.n, self.team.ip, 
                                               self.service.name, message)

def get_teams_services():
    """Retrieve the lists of team and service instances."""

    with db_conn.cursor() as cur:
        try:
            cur.execute('SELECT id, ip, name FROM teams')
            teams = [Team(**t) for t in cur.fetchall()]
            cur.execute('SELECT id, name, active FROM services')
            services = [Service(**s) for s in cur.fetchall() if s['active']]
        except psycopg2.Error as e:
            logger.critical("Error while quering the database, aborting: {}".format(e))
            abort()

    return (teams, services)

def advance_round(teams, services):
    """Advance the round: update results, truncate the active_flags table and
    store new flags in the database for each team and service."""

    with db_conn.cursor() as cur:
        # advance the round and clear the flag tables
        try:
            cur.execute('SELECT * FROM switch_round()')
            rnd = cur.fetchone()['switch_round']
        except psycopg2.Error as e:
            logger.critical(("Error while incrementing the round, "
                              "aborting: {}").format(e))
            abort()
    # commit the stored procedure operations (probably not needed)
    db_conn.commit()
    logger.info("Round {} started".format(rnd))

    # generate and insert the new flags to the database
    cur = db_conn.cursor()
    for service in services:
        for team in teams:
            inserted = False
            while not inserted:
                flag = utils.generate_flag(config['FLAG_PREFIX'], config['FLAG_SUFFIX'],
                                           config['FLAG_CHARS'], config['FLAG_LENGTH'])
                try:
                    cur.execute((
                        'INSERT INTO flags (flag, team_id, service_id, round) '
                        'VALUES (%s, %s, %s, %s)'),
                        (flag, team.id, service.id, rnd))
                except psycopg2.IntegrityError:
                    logger.warning('Duplicate flag, generating a new one')
                except psycopg2.Error as e:
                    logger.critical(('Error while adding a new flag to the '
                                      'database, aborting: {}').format(e))
                    abort()
                else:
                    inserted = True
                    logger.debug(('New flag just added to the database: {}').format(flag))
    db_conn.commit()
    cur.close()

def main():
    global logger, timeout, db_conn

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
        abort()

    # set variables
    n_workers = args.num_workers
    timeout = args.timeout
    log_level = logging.DEBUG if args.verbose else logging.INFO

    # set logging
    logger.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    fh = logging.FileHandler(config['BOT_LOG_FILE'])
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    # if the verbose mode is selected, log also on the console
    if args.verbose:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    # start the global db connection
    db_conn = database.db_connect(logger=logger)

    # retrieve the list of teams and services
    teams, services = get_teams_services()
    if args.advance:
        # advance the round
        advance_round(teams, services)
    if args.check or args.dispatch:
        # fill the queue of tasks, choosing the team order randomly :)
        for service in services:
            for team in random.sample(teams, len(teams)):
                tasks.put_nowait((team, service))

        # create the list of workers
        workers = []
        for i in range(n_workers):
            worker = Worker(i, args.dispatch, args.check)
            workers.append(worker)
            worker.start()

        # join all workers
        for worker in workers:
            worker.join()

    # exit gracefully
    sys.exit(0)

if __name__ == "__main__":
    main()
