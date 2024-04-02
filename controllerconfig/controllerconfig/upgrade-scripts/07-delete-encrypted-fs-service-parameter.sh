#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#
# This migration script is used for deleting the encrypted-fs attribute
# of 'platform config' service parameter during the activate stage of
# platform upgrade if it is present.


# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

# Only run this script during upgrade-activate and from release 22.12
if [[ "$ACTION" != "activate" ||  "$FROM_RELEASE" != "22.12" ]]; then
    log "$NAME: skipping encryption-fs service parameter deletion."
    exit 0
fi

source /etc/platform/openrc

# Get the UUID of the encrypted-fs attribute
ENCRYPTED_FS_UUID=$( system service-parameter-list --service platform --section config | grep " encrypted-fs " | awk -F '|' '{print $2}'| xargs );

# Check if ENCRYPTED_FS_UUID is not empty
if [ -n "$ENCRYPTED_FS_UUID" ]; then
    # If ENCRYPTED_FS_UUID is not empty, delete the parameter
    system service-parameter-delete $ENCRYPTED_FS_UUID
fi
