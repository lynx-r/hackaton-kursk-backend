#!/usr/bin/env bash

source .env

PORT=8080 TOKEN_SECRET=$TOKEN_SECRET REALM_KEY=$REALM_KEY REALM_NAME=$REALM_NAME ORIGIN_URL="https://hackaton-kursk.shashki.online" java -jar ./build/libs/hackaton-kursk-backend-0.0.1-SNAPSHOT.jar

