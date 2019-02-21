#!/bin/sh

docker exec -ti ctforge_postgres_1 createuser -U postgres -d ctforge
docker exec -ti ctforge_ctforge_1 ctforge init
