#!/bin/bash

WAPOD_BIN=$(realpath ./data/wapod)

find_ports() {
  local from=$1
  local count=$2
  local -a ports=()

  for ((port=from; port<=65535; port++)); do
    if ! ss -tuln | grep -q ":$port "; then
      ports+=($port)
      if [ ${#ports[@]} -eq $count ]; then
        break
      fi
    fi
  done

  echo "${ports[@]}"
}

start_wapod() {
  local -a available_ports=($(find_ports 8000 2))
  local workdir=$1
  local admin_port=${available_ports[0]}
  local user_port=${available_ports[1]}

  mkdir -p $workdir
  echo "Running wapod in $workdir with admin port $admin_port and user port $user_port"
  run_wapod $workdir $admin_port $user_port >$workdir/wapod.log 2>&1 &
  while ! ss -tuln | grep -q ":$admin_port"; do
    sleep 1
  done
  curl -s localhost:$admin_port/prpc/Worker.Init
  curl -s localhost:$admin_port/prpc/Status.Info | jq .
  sleep 1000
}

run_wapod() {
  local workdir=$1
  local admin_port=$2
  local user_port=$3

  cd $workdir && $WAPOD_BIN --admin-port $admin_port --user-port $user_port
}

start_wapod data/wapod-0
