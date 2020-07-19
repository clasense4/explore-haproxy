#!/bin/bash
sudo apt-get update -y
sudo apt install -y git curl wget htop ca-certificates gcc libc6-dev liblua5.3-dev libpcre3-dev libssl-dev libsystemd-dev make wget zlib1g-dev haproxy
cd /home/ubuntu
git clone https://github.com/haproxy/haproxy.git
cd haproxy
sudo git checkout v2.2.0
sudo make TARGET=linux-glibc USE_LUA=1 USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1 USE_SYSTEMD=1 EXTRA_OBJS="contrib/prometheus-exporter/service-prometheus.o"
sudo make install-bin

sudo systemctl stop haproxy
sudo cp /usr/local/sbin/haproxy /usr/sbin/haproxy
sudo systemctl start haproxy