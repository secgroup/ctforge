#!/bin/sh

docker-compose exec postgres createuser -U postgres -d ctforge
docker-compose exec postgres createdb -U postgres -O ctforge -E UTF8 ctforge
docker-compose exec postgres psql -U postgres -d ctforge --command 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'
docker-compose exec ctforge ctforge init
