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
    nickname      VARCHAR(45) NOT NULL,
    mail          VARCHAR(70) NOT NULL,
    affiliation   VARCHAR(100) NULL,
    password      VARCHAR(100) NOT NULL,
    admin         BOOLEAN NOT NULL DEFAULT FALSE,
    hidden        BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    UNIQUE (mail),
    UNIQUE (nickname)
);

CREATE TABLE challenges (
    id                SERIAL,
    name              VARCHAR(45) NOT NULL,
    description       TEXT NOT NULL,
    flag              VARCHAR(120) NOT NULL,
    points            INT NOT NULL,
    short_description TEXT NOT NULL DEFAULT '', 
    active            BOOLEAN NOT NULL DEFAULT FALSE,
    hidden            BOOLEAN NOT NULL DEFAULT TRUE,
    writeup           BOOLEAN NOT NULL DEFAULT FALSE,
    writeup_template  TEXT,
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
    user_id       INT NOT NULL,
    challenge_id  INT NOT NULL,
    writeup       TEXT NOT NULL,
    timestamp     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (challenge_id) REFERENCES challenges (id)
);

CREATE TABLE challenges_evaluations (
    user_id       INT NOT NULL,
    challenge_id  INT NOT NULL,
    grade         INT,
    feedback      TEXT,
    timestamp     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, challenge_id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (challenge_id) REFERENCES challenges (id)
);

CREATE TABLE services (
    id            SERIAL,
    name          VARCHAR(45) NOT NULL,
    description   TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT FALSE,
    flag_lifespan INT NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE (name)
);

CREATE TABLE flags (
    flag          VARCHAR(30) NOT NULL,
    team_id       INT NOT NULL,
    service_id    INT NOT NULL,
    round         INT NOT NULL,
    PRIMARY KEY (flag),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    FOREIGN KEY (service_id) REFERENCES services (id),
    FOREIGN KEY (round) REFERENCES rounds (id)
);

CREATE TABLE service_attacks (
    id            SERIAL,
    team_id       INT NOT NULL,
    flag          VARCHAR(30) NOT NULL,
    timestamp     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE (team_id, flag),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    FOREIGN KEY (flag) REFERENCES flags (flag)
);

CREATE TABLE integrity_checks (
    round         INT NOT NULL,
    team_id       INT NOT NULL,
    service_id    INT NOT NULL,
    timestamp     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    successful    BOOLEAN NOT NULL,
    PRIMARY KEY (team_id, service_id, round, timestamp),
    FOREIGN KEY (round) REFERENCES rounds (id),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    FOREIGN KEY (service_id) REFERENCES services (id)
);

CREATE TABLE scores (
    round         INT NOT NULL,
    team_id       INT NOT NULL,
    service_id    INT NOT NULL,
    attack        DOUBLE PRECISION NOT NULL,
    defense       DOUBLE PRECISION NOT NULL,
    sla           DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (round, team_id, service_id),
    FOREIGN KEY (round) REFERENCES rounds (id),
    FOREIGN KEY (team_id) REFERENCES teams (id),
    FOREIGN KEY (service_id) REFERENCES services (id)
);
