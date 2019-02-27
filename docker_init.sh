#!/bin/sh

docker exec -ti ctforge_postgres_1 createuser -U postgres -d ctforge
docker exec -u postgres -t ctforge_postgres_1 sh -c "psql --command 'CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\" WITH SCHEMA ctforge'"
docker exec -ti ctforge_ctforge_1 ctforge init
