#!/bin/bash

####################################################
# Usage
####################################################
usage() {
  echo ""
  echo "Usage: $0 -i <ec2-ip-address> -c <path-to-certificate>  -v <app-version>"
  echo ""

  exit 1
}

####################################################
# Main
####################################################

SERVER_IP=
CERT_PATH=
APP_VERSION=
RESET=

while getopts i:c:v: opt
do
  case "$opt" in
    i) SERVER_IP=$OPTARG;;
    c) CERT_PATH=$OPTARG;;
    v) APP_VERSION=$OPTARG;;
    r) RESET=$OPTARG;;
  esac
done

if [[ -z "$SERVER_IP" ]] || [[ -z "$CERT_PATH" ]] || [[ -z "$APP_VERSION" ]]; then
  usage
fi

connection=true

if [ $APP_VERSION = 1 ]
then
  clear
  echo "Deploying v1"
  ssh -tt -o ConnectTimeout=5 -i $CERT_PATH ubuntu@$SERVER_IP << EOF || connection=false
  cd cs-demo
  git fetch
  git reset --hard origin/master
  git checkout master
  sudo docker-compose down && sudo docker-compose up --build -d
  echo "Creating test user"
  curl 'http://localhost/register' -s --data-raw 'username=tst&email=tst%40mail.com&password=tst&register='
  exit
EOF
elif [ $APP_VERSION = 2 ]
then
  clear
  echo "Deploying v2"
  ssh -tt -o ConnectTimeout=5 -i $CERT_PATH ubuntu@$SERVER_IP << EOF || connection=false
  cd cs-demo
  git fetch
  git checkout ext_logging
  git reset --hard origin/ext_logging
  sudo docker-compose down && sudo docker-compose up --build -d
  exit
EOF
elif [ $APP_VERSION = 0 ]
then
  clear
  echo "Shutting down cluster"
  ssh -tt -o ConnectTimeout=5 -i $CERT_PATH ubuntu@$SERVER_IP << EOF || connection=false
  cd cs-demo
  sudo docker-compose down
  sudo docker volume prune -f
  exit
EOF
else
  echo "Error: Application version MUST be 1 or 2"
fi

if [ $connection = true ]
then
  echo "============================================================================"
  echo "Finishing deploying application.Please wait a few seconds..."
  sleep 10
  echo "Application $APP_VERSION deployed: http://$SERVER_IP"
else
  echo "============================================================================"
  echo "ERROR: Deployment server not available. Please check connection and try again."
fi