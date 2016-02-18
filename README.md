CTForge
=======
Forge you own CTF.

CTForge is the framework developed by the hacking team from University of Venice to easily host jeopardy and attack-defense [CTF security competitions](https://ctftime.org/ctf-wtf/). It provides the software components for running the game, namely the website and the checkbot (optional). The website is the primary interface used by players to access the game rules, the challenges/services descriptions and the scoreboard. In case of an attack-defense game mode the checkbot will, cyclically, store new flags in each team and retrieve them to ensure that everything is working properly.

Setup
-----
Depending on the desired game mode, requirements and setup may change.

### Jeopardy (aka challenge based)
Since CTForge is entirely written in Python, a working Python 3 installation is required. Additionally, a webserver like [nginx](http://nginx.org/) and [PostgreSQL](http://www.postgresql.org/) are needed to deploy the infrastructure. Detailed steps for configuring and installing the software on a server are provided below (tested on Ubuntu 15.10, although we use [Gentoo](https://wiki.gentoo.org/wiki/Hardened_Gentoo) on production hosts).

Install the aforementioned packages

    $ sudo apt install nginx uwsgi python3-dev postgresql postgresql-contrib postgresql-server-dev-all

Create an user for running the website instance

    $ sudo useradd ctforge -m -G users -s /bin/bash

Add a database user with the permission to create new databases

    $ sudo -u postgres createuser -d -P ctforge
    $ sudo service postgresql restart

Login as the `ctforge` user, download and unpack the CTForge source code

    $ sudo -u ctforge -i
    $ git clone git@github.com:secgroup/ctforge.git
    $ cd ctforge

Now prepare the Python virtualenv
 
    $ mkdir -p ~/.venvs/
    $ virtualenv -p /usr/bin/python3 ~/.venvs/ctforge
    $ . ~/.venvs/ctforge/bin/activate

Install the framework in development mode for now, adjust the configuration file to your needs and initialize CTForge

    (ctforge)$ ./setup.py develop
    (ctforge)$ cp ctforge.conf ctforge.custom.conf
    (ctforge)$ ctforge -c ctforge.custom.conf init

 Now you can run the site and edit your custom template, the application will automatically reload upon file modifications. Take a look at the `dctf2016` resources in the `examples/` folder

    (ctforge)$ ctforge run

When you are done editing the template, install the package using

    (ctforge)$ ./setup.py install

Congratulations!

Deployment using Nginx and Uwsgi
--------------------------------


### Attack-defense
Todo.