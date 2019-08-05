#!/usr/bin/env bash

git pull
./gradlew bootJar
echo Restarting backend hackaton-kursk-java.service
sudo systemctl restart hackaton-kursk-java.service
