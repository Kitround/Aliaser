#!/bin/bash

# --- Configuration ---
LOCAL_PATH="/path/to/aliaser"
VM_USER="user"
VM_HOST="192.168.x.x"
VM_PATH="~/aliaser"
# ---------------------

rsync -av --exclude='app/json/' --exclude='.git/' \
  "$LOCAL_PATH/" \
  "$VM_USER@$VM_HOST:$VM_PATH/"

ssh "$VM_USER@$VM_HOST" "
  docker build -f $VM_PATH/docker/Dockerfile -t aliaser:latest $VM_PATH
  docker restart \$(docker ps -q --filter name=aliaser)
"