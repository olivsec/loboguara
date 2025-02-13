#!/usr/bin/env bash

ALREADY_INSTALLED=".installed"

if [ ! -e "$ALREADY_INSTALLED" ]
then
    source /opt/loboguara/install_via_docker.sh
    [[ $? -eq 0 ]] && sudo -u loboguara touch "$ALREADY_INSTALLED"
fi

sudo -u loboguara /opt/loboguara/start.sh
