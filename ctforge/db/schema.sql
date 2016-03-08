CREATE TABLE teams (
    id            SERIAL,
    ip            VARCHAR(15) NOT NULL,
    name          VARCHAR(60) NOT NULL,
    token         VARCHAR(60) NOT NULL,
    poc           INT DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE (name),
    UNIQUE (ip),
    UNIQUE (token)
);

CREATE TABLE rounds (
    id            INT NOT NULL,
    timestamp     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE TABLE users (
    id            SERIAL,
    team_id       INT NULL,
    name          VARCHAR(45) NOT NULL,
    surname       VARCHAR(45) NOT NULL,
    mail          VARCHAR(70) NOT NULL,
    password      VARCHAR(100) NOT NULL,
    admin         BOOLEAN NOT NULL DEFAULT FALSE,
    hidden        BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    UNIQUE (mail)
);

CREATE TABLE challenges (
    id            SERIAL,
    name          VARCHAR(45) NOT NULL,
    description   TEXT NOT NULL,
    flag          VARCHAR(120) NOT NULL,
    points        INT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT FALSE,
    writeup       BOOLEAN NOT NULL DEFAULT FALSE,
    writeup_template TEXT,
    PRIMARY KEY (id),
    UNIQUE (name)
);

CREATE TABLE challenge_attacks (
    user_id       INT NOT NULL,
    challenge_id  INT NOT NULL,
    timestamp     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, challenge_id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (challenge_id) REFERENCES challenges (id)
);

CREATE TABLE writeups (
    id            SERIAL,
    writeup       TEXT NOT NULL,
    grade         INT,
    feedback      TEXT,
    timestamp     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE TABLE challenge_writeups (
    user_id       INT NOT NULL,
    challenge_id  INT NOT NULL,
    writeup_id    INT NOT NULL,
    PRIMARY KEY (user_id, challenge_id, writeup_id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (challenge_id) REFERENCES challenges (id),
    FOREIGN KEY (writeup_id) REFERENCES writeups (id)
);

CREATE TABLE services (
    id            SERIAL,
    name          VARCHAR(45) NOT NULL,
    description   TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE (name)
);

CREATE TABLE active_flags (
    flag          VARCHAR(30) NOT NULL,
    team_id       INT NOT NULL,
    service_id    INT NOT NULL,
    round         INT NOT NULL,
    PRIMARY KEY (flag),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    FOREIGN KEY (service_id) REFERENCES services (id),
    FOREIGN KEY (round) REFERENCES rounds (id)
);

CREATE TABLE flags (
    flag          VARCHAR(30) NOT NULL,
    team_id       INT NOT NULL,
    service_id    INT NOT NULL,
    round         INT NOT NULL,
    n_checks      INT DEFAULT 0,
    n_up_checks   INT DEFAULT 0,
    PRIMARY KEY (flag),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    FOREIGN KEY (service_id) REFERENCES services (id),
    FOREIGN KEY (round) REFERENCES rounds (id)
);

CREATE TABLE service_attacks (
    id            SERIAL,
    team_id       INT NOT NULL,
    flag          VARCHAR(30) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (team_id, flag),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    FOREIGN KEY (flag) REFERENCES flags (flag)
);

CREATE TABLE integrity_checks (
    flag          VARCHAR(30) NOT NULL,
    timestamp     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    successful    BOOLEAN NOT NULL,
    PRIMARY KEY (flag, timestamp),
    FOREIGN KEY (flag) REFERENCES active_flags (flag)
);

CREATE TABLE scores (
    team_id       INT NOT NULL,
    round         INT NOT NULL,
    attack        INT NOT NULL,
    defense       INT NOT NULL,
    PRIMARY KEY (team_id, round),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    FOREIGN KEY (round) REFERENCES rounds (id)
);