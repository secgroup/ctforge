#!/bin/sh

docker exec -ti ctforge_postgres_1 createuser -U postgres -d ctforge
docker exec -ti ctforge_postgres_1 createdb -U postgres -O ctforge -E UTF8 ctforge
docker exec -ti ctforge_postgres_1 psql -U postgres -d ctforge --command 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'
docker exec -ti ctforge_ctforge_1 ctforge init