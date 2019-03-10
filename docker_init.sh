#!/bin/sh

docker-compose exec ctforge_postgres_1 createuser -U postgres -d ctforge
docker-compose exec ctforge_ctforge_1 ctforge init
