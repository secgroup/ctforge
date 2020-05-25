#!/bin/sh

docker-compose exec postgres createuser -U postgres -d ctforge
docker-compose exec ctforge ctforge init
