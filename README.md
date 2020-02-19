CTForge
=======
Forge your own CTF.

CTForge is the framework developed by the hacking team from University of Venice to easily host jeopardy and attack-defense [CTF security competitions](https://ctftime.org/ctf-wtf/). It provides the software components for running the game, namely the website and the checkbot (optional). The website is the primary interface used by players to access the game rules, the challenges/services descriptions and the scoreboard. In case of an attack-defense game mode the checkbot will, cyclically, store new flags in each team and retrieve them to ensure that everything is working properly.

Setup
-----
Depending on the desired game mode, requirements and setup may change. Instructions below are for a basic install of ctforge in jeopardy mode using the built-in webserver. Remember that deploying ctforge in production requires a real webserver like [nginx](http://nginx.org/) paired with [uWSGI](https://github.com/unbit/uwsgi).

Since CTForge is entirely written in Python, a working Python 3 installation is required. Additionally, the [PostgreSQL](http://www.postgresql.org/) DBMS is needed. Detailed steps for configuring and installing the software on a server are provided below (tested on Ubuntu 16.04, although we use [Gentoo](https://wiki.gentoo.org/wiki/Hardened_Gentoo) on production hosts).

Install the aforementioned packages

    $ sudo apt install python3-dev postgresql postgresql-contrib postgresql-server-dev-all

Add a database user with the permission to create new databases

    $ sudo service postgresql start
    $ sudo -u postgres createuser -d -P ctforge

Download and unpack the CTForge source code

    $ git clone git@github.com:secgroup/ctforge.git
    $ cd ctforge

Now prepare the Python virtualenv
 
    $ mkdir -p ~/.venvs/
    $ virtualenv -p /usr/bin/python3 ~/.venvs/ctforge
    $ . ~/.venvs/ctforge/bin/activate

Install the framework in development mode for now, adjust the configuration file to your needs then initialize CTForge. The initialization script will prompt for an administrative user which will be used to login on the website and add/modify the live settings of the game (challenges/services/teams).

    (ctforge)$ ./setup.py develop
    (ctforge)$ cp ctforge.conf ctforge.custom.conf
    (ctforge)$ vim ctforge.custom.conf
    (ctforge)$ ctforge -c ctforge.custom.conf init
    [*] Reading configuration from ctforge.custom.ctforge.conf

    Welcome to the installation script of CTForge
    Please backup your /home/ctforge/.ctforge/ctforge.conf file before continuing.

    Do you want to proceed? (y/n) y
    [*] Creating database schema
    [*] Installing SQL procedures
    [*] Adding an administrative user
        name: Marco
        surname: Squarcina
        mail: squarcina@*****.**
        password: *******************
        re-enter the password: *******************
    Save configuration to /home/ctforge/.ctforge/ctforge.conf ? (y/n) y


Now you can run the site and edit your custom theme, the application will automatically reload upon file modifications:

    (ctforge)$ ctforge run

Feel free to start editing your theme from the default theme `dctf2017` (under the `themes/` folder). When you are done editing the template, install the package using:

    (ctforge)$ ./setup.py install


Contacts
--------
CTForge is developed by [Marco Squarcina](https://minimalblue.com), Mauro Tempesta and Lorenzo Veronese aided by all the guys from [c00kies@venice](https://secgroup.github.io/).

