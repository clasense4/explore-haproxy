#!/bin/bash
sudo apt-get update -y
sudo apt install -y git curl wget htop
cd /home/ubuntu
wget https://github.com/tsenart/vegeta/releases/download/v12.8.3/vegeta-12.8.3-linux-amd64.tar.gz
tar xvfz vegeta-12.8.3-linux-amd64.tar.gz
sudo mv vegeta /usr/local/bin/vegeta