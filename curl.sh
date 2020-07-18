#!/bin/bash
sleep=1
timestamp() {
  date +"%T"
}

URL="https://haproxy.serverless.my.id/"

for (( ; ; ))
do
    timestamp
    echo "CURL $URL"
    curl -L $URL
    echo ""
    echo ""
    sleep $sleep
done