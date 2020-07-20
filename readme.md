# Exploring HA Proxy

## Introduction

In this repository we will explore how HA Proxy works. The goal of this implementation is to get understanding how HA Proxy works. The instance is used for **SSL offloading** and proxies around **25000 requests per second**. Also we will explore how to monitor HA Proxy and send our metrics to Prometheus.

## Pre-requisite

1. AWS Account
2. Terraform
3. Domain Name

## HA Proxy Instance

I use this following commands to create a HA Proxy instance using terraform.

```terraform
module "haproxy" {
  source                      = "../modules/ec2"
  name                        = "HAProxy"
  ami_id                      = "ami-07ce5f60a39f1790e"
  instance_type               = "t2.micro"
  key_name                    = "fajri_haproxy"
  associate_public_ip_address = true
  security_groups             = ["${aws_security_group.haproxy_sg.id}"]
  subnet_id                   = "subnet-69398430"
  user_data                   = "userdata_haproxy.sh"
}

resource "aws_security_group" "haproxy_sg" {
  name        = "haproxy"
  description = "Allow access to HA Proxy instance from VPN"
  vpc_id      = "vpc-7829341f"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["202.80.214.161/32"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8404
    to_port     = 8404
    protocol    = "tcp"
    cidr_blocks = ["202.80.214.161/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "haproxy_public_dns" {
  value = module.haproxy.public_dns
}
```

This is the user data to install HA Proxy.

```shell
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
```

And this is the ec2 terraform module.

```terraform
resource "aws_instance" "this" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  key_name                    = var.key_name
  associate_public_ip_address = var.associate_public_ip_address
  security_groups             = var.security_groups
  subnet_id                   = var.subnet_id
  user_data                   = file(var.user_data)
  tags = {
    Name        = var.name
    Description = "Managed by terraform"
  }
  lifecycle {
    ignore_changes = [
      # Ignore changes to security group, it will force a new resource
      tags, security_groups, vpc_security_group_ids, associate_public_ip_address
    ]
  }
}
```

Execute with this command to create the instance.

```shell
terraform plan
terraform apply -auto-approve
```

I choose default VPC from AWS and just use the default subnet (`subnet-69398430`), it is `ap-southeast-1c (apse1-az3)`. And for the rest of the infrastructure, it will be using the same availability zone, or we simply say it the same data center. The security group is allowed only me to ssh into the instance and open the prometheus metrics & stat.

After the instance is ready, we can ssh into the instance. We wil configure this instance later after creating the backend instances.


## Backend Instance

I use this following commands to create 3 Backend instance using terraform. The backend is just a plain PHP script with Nginx and PHP-FPM.

```terraform
resource "aws_security_group" "backend_sg" {
  name        = "backend"
  description = "Allow access from HA Proxy instance"
  vpc_id      = "vpc-7829341f"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["172.31.0.0/16"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["${module.haproxy.private_ip}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

module "backend_1" {
  source                      = "../modules/ec2"
  name                        = "backend_1"
  ami_id                      = "ami-07ce5f60a39f1790e"
  instance_type               = "t2.micro"
  key_name                    = "fajri_haproxy"
  associate_public_ip_address = true
  security_groups             = ["${aws_security_group.backend_sg.id}"]
  subnet_id                   = "subnet-69398430"
  user_data                   = "userdata_php.sh"
}

output "backend_1_private_ip" {
  value = module.backend_1.private_ip
}

module "backend_2" {
  source                      = "../modules/ec2"
  name                        = "backend_2"
  ami_id                      = "ami-07ce5f60a39f1790e"
  instance_type               = "t2.micro"
  key_name                    = "fajri_haproxy"
  associate_public_ip_address = true
  security_groups             = ["${aws_security_group.backend_sg.id}"]
  subnet_id                   = "subnet-69398430"
  user_data                   = "userdata_php.sh"
}

output "backend_2_private_ip" {
  value = module.backend_2.private_ip
}

module "backend_3" {
  source                      = "../modules/ec2"
  name                        = "backend_3"
  ami_id                      = "ami-07ce5f60a39f1790e"
  instance_type               = "t2.micro"
  key_name                    = "fajri_haproxy"
  associate_public_ip_address = true
  security_groups             = ["${aws_security_group.backend_sg.id}"]
  subnet_id                   = "subnet-69398430"
  user_data                   = "userdata_php.sh"
}

output "backend_3_private_ip" {
  value = module.backend_3.private_ip
}
```

This is the user data to install the Backend instance.

```shell
#!/bin/bash
sudo apt-get update -y
sudo apt-get install nginx git zip curl wget php php-fpm -y

sudo mkdir /var/www/php
cat <<EOF | sudo tee /var/www/php/index.php
<?php
print_r(\$_SERVER['SERVER_ADDR']);
EOF
sudo chown -R www-data:www-data /var/www/php
sudo rm -rf /etc/nginx/sites-available/example.com
cat <<EOF | sudo tee /etc/nginx/sites-available/example.com
server {
    listen 80;
    root /var/www/php;
    index index.php index.html index.htm index.nginx-debian.html;
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php7.2-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    location ~ /\.ht {
        deny all;
    }
}
EOF
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/
sudo unlink /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl stop apache2
sudo systemctl restart nginx
```

Execute with this command to create the instance.

```shell
terraform plan
terraform apply -auto-approve
```

The backend instances allowed port 22 to be accessed by any machine inside the VPC. And port 80 is only allowed for the HA Proxy instance.

## Preparing the SSL certificate

I use let's encrypt to get a free SSL certificate. I have a domain (`serverless.my.id`) and it is registered to route53. I use this following command to get certificate.

```
sudo certbot certonly --dns-route53 -d "*.serverless.my.id" -d serverless.my.id --agree-tos --no-bootstrap --manual-public-ip-logging-ok --preferred-challenges dns-01 --server https://acme-v02.api.letsencrypt.org/directory
```

> :exclamation: **If you have problem** with unreadable aws profile, change it to `[default]` profile.

And use this commands to combine the certificate.

```
sudo cat /etc/letsencrypt/live/serverless.my.id/fullchain.pem \
    /etc/letsencrypt/live/serverless.my.id/privkey.pem \
    | sudo tee serverless.my.id.pem
```

## Configuring HA Proxy instance

SSH to the HA Proxy instance and check the installation with this command. Make sure the Prometheus exporter is ready.

```
haproxy -v

HA-Proxy version 2.2.0 2020/07/07 - https://haproxy.org/
Status: long-term supported branch - will stop receiving fixes around Q2 2025.
Known bugs: http://www.haproxy.org/bugs/bugs-2.2.0.html
Running on: Linux 4.15.0-1058-aws #60-Ubuntu SMP Wed Jan 15 22:35:20 UTC 2020 x86_64

haproxy -vv | grep Prometheus

Built with the Prometheus exporter as a service

```

Let's check if the port: 22, 80, 443 and 8404 is open in the instance.

```
sudo netstat -ntpl

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:8404            0.0.0.0:*               LISTEN      32063/haproxy
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      2913/systemd-resolv
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      924/sshd
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      32063/haproxy
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      32063/haproxy
tcp6       0      0 :::22                   :::*                    LISTEN      924/sshd
```

Great, now take a note on the backend instances private ip, then update the `/etc/haproxy/haproxy.cfg` with this configuration.

```
global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # Default SSL material locations
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

    # Default ciphers to use on SSL-enabled listening sockets.
    # For more information, see ciphers(1SSL). This list is from:
    #  https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
    # An alternative list with additional directives can be obtained from
    #  https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=haproxy
    ssl-default-bind-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS
    ssl-default-bind-options no-sslv3

    maxconn 2048
    tune.ssl.default-dh-param 2048

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    option  http-server-close
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend haproxy.serverless.my.id
    bind *:80
    bind *:443 ssl crt /etc/ssl/serverless.my.id/serverless.my.id.pem #CHANGETHIS
    http-request redirect scheme https unless { ssl_fc }
    default_backend backend

frontend stats
   bind *:8404
   option http-use-htx
   http-request use-service prometheus-exporter if { path /metrics }
   stats enable
   stats uri /stats
   stats refresh 10s

backend backend
    balance roundrobin
    option forwardfor
    http-request set-header X-Forwarded-Port %[dst_port]
    http-request add-header X-Forwarded-Proto https if { ssl_fc }
    option httpchk GET /
    server node1 172.31.14.51:80 check #CHANGETHIS
    server node2 172.31.1.31:80 check #CHANGETHIS
    server node3 172.31.5.178:80 check #CHANGETHIS
```

> :exclamation: **Do not forget** to upload the SSL certificate and change the backend instance IP address

Validate the haproxy configuration and restart the HA Proxy service with this command

```
haproxy -c -V -f /etc/haproxy/haproxy.cfg
sudo service haproxy restart
```

## Mapping the HA Proxy instance to route53

I will use a sub domain to access our setup with this following terraform code.

```terraform
resource "aws_route53_record" "www" {
  zone_id = "Z0267035H2P3O9XYGZ3K"
  name    = "haproxy.serverless.my.id"
  type    = "A"
  ttl     = "300"
  records = ["${module.haproxy.public_ip}"]
}
```

## Test our setup

If we check our EC2 menu, we should see something like this.

![](/images/haproxy_ec2_menu.png)

We can open our browser to see it in action.

![](/images/haproxy_in_action.gif)

Let's check the prometheus exporter

![](/images/prometheus_exporter.png)

Open `/var/log/haproxy.log` to see our load balancer in action.

```shell
tail -f /var/log/haproxy.log

Jul 20 03:45:14 ip-172-31-6-128 haproxy[32063]: 202.80.214.161:49802 [20/Jul/2020:03:45:14.123] stats stats/<PROMEX> 0/0/0/0/0 200 44229 - - LR-- 1/1/0/0/0 0/0 "GET /metrics HTTP/1.1"
Jul 20 03:45:19 ip-172-31-6-128 haproxy[32063]: 202.80.214.161:49804 [20/Jul/2020:03:45:19.117] stats stats/<PROMEX> 0/0/0/0/0 200 44230 - - LR-- 1/1/0/0/0 0/0 "GET /metrics HTTP/1.1"
Jul 20 03:45:24 ip-172-31-6-128 haproxy[32063]: 202.80.214.161:49810 [20/Jul/2020:03:45:24.117] stats stats/<PROMEX> 0/0/0/0/0 200 44230 - - LR-- 1/1/0/0/0 0/0 "GET /metrics HTTP/1.1"
Jul 20 03:45:26 ip-172-31-6-128 haproxy[32063]: 202.80.214.161:49582 [20/Jul/2020:03:45:26.485] haproxy.serverless.my.id~ backend/node3 0/0/0/1/1 200 212 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Jul 20 03:45:26 ip-172-31-6-128 haproxy[32063]: 202.80.214.161:49582 [20/Jul/2020:03:45:26.934] haproxy.serverless.my.id~ backend/node1 0/0/0/1/1 200 212 - - ---- 1/1/0/0/0 0/0 "GET /favicon.ico HTTP/1.1"
Jul 20 03:45:27 ip-172-31-6-128 haproxy[32063]: 202.80.214.161:49582 [20/Jul/2020:03:45:27.224] haproxy.serverless.my.id~ backend/node2 0/0/0/1/1 200 209 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Jul 20 03:45:27 ip-172-31-6-128 haproxy[32063]: 202.80.214.161:49582 [20/Jul/2020:03:45:27.401] haproxy.serverless.my.id~ backend/node3 0/0/0/1/1 200 212 - - ---- 1/1/0/0/0 0/0 "GET /favicon.ico HTTP/1.1"
Jul 20 03:45:27 ip-172-31-6-128 haproxy[32063]: 3.101.0.4:61187 [20/Jul/2020:03:45:27.616] haproxy.serverless.my.id haproxy.serverless.my.id/<NOSRV> 0/-1/-1/-1/0 302 119 - - LR-- 2/2/0/0/0 0/0 "GET / HTTP/1.1"
Jul 20 03:45:28 ip-172-31-6-128 haproxy[32063]: 3.101.0.4:30286 [20/Jul/2020:03:45:28.355] haproxy.serverless.my.id~ backend/node1 0/0/1/1/2 200 172 - - ---- 2/2/0/0/0 0/0 "GET / HTTP/1.1"
Jul 20 03:45:29 ip-172-31-6-128 haproxy[32063]: 202.80.214.161:49816 [20/Jul/2020:03:45:29.116] stats stats/<PROMEX> 0/0/0/0/0 200 44220 - - LR-- 2/1/0/0/0 0/0 "GET /metrics HTTP/1.1"
```

---

## Prometheus and Grafana

Follow this guides: [prometheus](https://prometheus.io/docs/introduction/first_steps/) and [grafana](https://grafana.com/docs/grafana/latest/getting-started/getting-started/) for quick setup. And I also include a grafana dashboard (`serverless.my.id-1595219746160.json`) to monitor ssl and proxy request.

The metrics that I think is important:

```
haproxy_process_current_ssl_connections
haproxy_process_max_frontend_ssl_key_rate
haproxy_process_max_ssl_rate
haproxy_process_ssl_connections_total
haproxy_process_current_frontend_ssl_key_rate
haproxy_process_requests_total
haproxy_process_max_connections
haproxy_frontend_http_requests_total
haproxy_process_current_ssl_connections
```

And this is the example of Grafana dashboard after the json is imported.

![](/images/grafana_serverlessmyid.png)

---

## Load test with Vegeta

Let's try with a few simple vegeta command on my local machine

```shell
echo "POST https://haproxy.serverless.my.id" | ./vegeta -cpus=6 attack -duration=1m -rate=1000 -workers=100  | tee reports.bin | ./vegeta report

Requests      [total, rate, throughput]         60000, 1000.02, 994.58
Duration      [total, attack, wait]             1m0s, 59.999s, 19.286ms
Latencies     [min, mean, 50, 90, 95, 99, max]  58.657µs, 27.124ms, 19.833ms, 20.549ms, 23.034ms, 291.102ms, 968.815ms
Bytes In      [total, mean]                     696418, 11.61
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           99.49%
Status Codes  [code:count]                      0:307  200:59693  
Error Set:
Post "https://haproxy.serverless.my.id": dial tcp 0.0.0.0:0->3.1.23.168:443: connect: no route to host
Post "https://haproxy.serverless.my.id": dial tcp: lookup haproxy.serverless.my.id on 1.0.0.1:53: read udp 192.168.0.184:40341->1.0.0.1:53: read: no route to host
Post "https://haproxy.serverless.my.id": dial tcp: lookup haproxy.serverless.my.id on 1.0.0.1:53: read udp 192.168.0.184:36153->1.0.0.1:53: read: no route to host
...
Post "https://haproxy.serverless.my.id": EOF
Post "https://haproxy.serverless.my.id": read tcp 192.168.0.184:51569->3.1.23.168:443: read: connection reset by peer

echo "POST https://haproxy.serverless.my.id" | ./vegeta -cpus=8 attack -duration=2m -rate=4000 -workers=100  | tee reports.bin | ./vegeta report
Requests      [total, rate, throughput]         480000, 4000.02, 3690.36
Duration      [total, attack, wait]             2m2s, 2m0s, 2.205s
Latencies     [min, mean, 50, 90, 95, 99, max]  44.434µs, 283.444ms, 209.258ms, 625.791ms, 944.355ms, 1.297s, 5.85s
Bytes In      [total, mean]                     5274757, 10.99
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           93.95%
Status Codes  [code:count]                      0:28948  200:450979  502:73  
Error Set:
Post "https://haproxy.serverless.my.id": dial tcp 0.0.0.0:0->3.1.23.168:443: connect: no route to host
Post "https://haproxy.serverless.my.id": dial tcp 0.0.0.0:0->3.1.23.168:443: socket: too many open files
Post "https://haproxy.serverless.my.id": dial tcp: lookup haproxy.serverless.my.id on 1.0.0.1:53: dial udp 1.0.0.1:53: socket: too many open files
Post "https://haproxy.serverless.my.id": dial tcp: lookup haproxy.serverless.my.id on 1.0.0.1:53: read udp 192.168.0.184:56169->1.0.0.1:53: read: no route to host
..
Post "https://haproxy.serverless.my.id": dial tcp: lookup haproxy.serverless.my.id on 1.0.0.1:53: read udp 192.168.0.184:46105->1.0.0.1:53: read: no route to host
502 Bad Gateway
Post "https://haproxy.serverless.my.id": dial tcp: lookup haproxy.serverless.my.id on 1.0.0.1:53: read udp 192.168.0.184:37205->1.0.0.1:53: read: no route to host
...
Post "https://haproxy.serverless.my.id": dial tcp: lookup haproxy.serverless.my.id on 1.0.0.1:53: read udp 192.168.0.184:42794->1.0.0.1:53: read: no route to host

```

This what is it looking on my machine and the HA Proxy instances.

![](/images/vegeta_in_action.gif)

The HA Proxy instance still survive, but not really, after I check with this command, we have some failures.

```shell
date && echo -n "Failures: " && cat /var/log/haproxy.log | grep 'SSL handshake failure' | wc -l
Mon Jul 20 05:36:44 UTC 2020
Failures: 17
```

But still survive. Our goal is to load test until the HA Proxy server can't serve anymore request, so we knew its limit. The instance is not suitable for production of course, it is t2.micro (1vCPU 1GB Ram).

So we will create 2 load test instance, and install vegeta inside that instance. I use this following terraform script.

```terraform
module "vegeta_1" {
  source                      = "../modules/ec2"
  name                        = "vegeta_1"
  ami_id                      = "ami-07ce5f60a39f1790e"
  instance_type               = "t3a.medium"
  key_name                    = "fajri_haproxy"
  associate_public_ip_address = true
  security_groups             = ["${aws_security_group.attacker_sg.id}"]
  subnet_id                   = "subnet-69398430"
  user_data                   = "userdata_vegeta.sh"
}

module "vegeta_2" {
  source                      = "../modules/ec2"
  name                        = "vegeta_2"
  ami_id                      = "ami-07ce5f60a39f1790e"
  instance_type               = "t3a.medium"
  key_name                    = "fajri_haproxy"
  associate_public_ip_address = true
  security_groups             = ["${aws_security_group.attacker_sg.id}"]
  subnet_id                   = "subnet-69398430"
  user_data                   = "userdata_vegeta.sh"
}

resource "aws_security_group" "attacker_sg" {
  name        = "attacker"
  description = "Allow access to Attacker instance from VPN"
  vpc_id      = "vpc-7829341f"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["202.80.214.161/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "vegeta_1_public_dns" {
  value = module.vegeta_1.public_dns
}
output "vegeta_2_public_dns" {
  value = module.vegeta_2.public_dns
}
```

This is the user data to install Vegeta.

```shell
#!/bin/bash
sudo apt-get update -y
sudo apt install -y git curl wget htop
cd /home/ubuntu
wget https://github.com/tsenart/vegeta/releases/download/v12.8.3/vegeta-12.8.3-linux-amd64.tar.gz
tar xvfz vegeta-12.8.3-linux-amd64.tar.gz
sudo mv vegeta /usr/local/bin/vegeta
```

After the terraform is finished, we can ssh to the instance, and execute our vegeta script in those 2 instances. This instance is t3a.medium (2vCPU 4GB RAM)

```
echo "POST https://haproxy.serverless.my.id" | vegeta -cpus=2 attack -duration=5m -rate=4000 -workers=100  | tee reports.bin | vegeta report
```

First attempt, the HA Proxy is able to handle around 4k TCP connections.

![](/images/vegeta_1st_attack.gif)

But after I increase the ulimit (temporary to 50000). This is what we got.

![](/images/vegeta_2nd_attack.gif)

The HA Proxy instance suddenly dropping the connection. And it is not serving any request from vegeta, the prometheus also not sending any data and even if we access https://haproxy.serverless.my.id it is not accessible.

And after checking the haproxy.log, here is the result.

```
date && echo -n "Failures: " && cat /var/log/haproxy.log | grep 'SSL handshake failure' | wc -l
Mon Jul 20 06:16:13 UTC 2020
Failures: 3321
```

---

## Conclusion

Metrics is important when working with any systems. In this case, the important metrics is `haproxy_process_current_ssl_connections`. With help of Prometheus and Grafana, we can see it in a single dashboard. But there is also a challenge, for example, when the traffic is very high, this endpoint `http://haproxy.serverless.my.id:8404/metrics` is can't be accessed. So the result in our Grafana dashboard, we have empty space. Because the resource is all used to serve the traffic.

![](/images/grafana_dashboard_emptyspace.png)


## Tricks

## Vegeta Load test Commands

```
echo "POST https://haproxy.serverless.my.id" | ./vegeta -cpus=2 attack -duration=10m -rate=100 -workers=4  | tee reports.bin | ./vegeta report
# 60K Total request in 1 minute
time echo "POST https://haproxy.serverless.my.id" | vegeta -cpus=1 attack -duration=1m -rate=1000 -workers=50  | tee reports.bin | vegeta report
# 60K Total request in 1 minute
time echo "POST https://haproxy.serverless.my.id" | vegeta -cpus=2 attack -duration=1m -rate=1000 -workers=100  | tee reports.bin | vegeta report
# 120K Total request in 1 minute (Failed)
time echo "POST https://haproxy.serverless.my.id" | vegeta -cpus=2 attack -duration=1m -rate=2000 -workers=100  | tee reports.bin | vegeta report
```

## Resources

### Up and running, concepts

- [https://www.digitalocean.com/community/tutorials/how-to-implement-ssl-termination-with-haproxy-on-ubuntu-14-04](https://www.digitalocean.com/community/tutorials/how-to-implement-ssl-termination-with-haproxy-on-ubuntu-14-04)
- [https://www.digitalocean.com/community/tutorials/an-introduction-to-haproxy-and-load-balancing-concepts](https://www.digitalocean.com/community/tutorials/an-introduction-to-haproxy-and-load-balancing-concepts)
- [https://www.digitalocean.com/community/tutorial_series/load-balancing-wordpress-with-haproxy](https://www.digitalocean.com/community/tutorial_series/load-balancing-wordpress-with-haproxy)
- [https://www.linode.com/docs/uptime/loadbalancing/how-to-use-haproxy-for-load-balancing/](https://www.linode.com/docs/uptime/loadbalancing/how-to-use-haproxy-for-load-balancing/)
- [https://serversforhackers.com/c/letsencrypt-with-haproxy](https://serversforhackers.com/c/letsencrypt-with-haproxy)
- [https://www.haproxy.com/blog/the-four-essential-sections-of-an-haproxy-configuration/](https://www.haproxy.com/blog/the-four-essential-sections-of-an-haproxy-configuration/)


### Monitoring

- [https://www.haproxy.com/blog/exploring-the-haproxy-stats-page/](https://www.haproxy.com/blog/exploring-the-haproxy-stats-page/)
- [https://github.com/prometheus/haproxy_exporter](https://github.com/prometheus/haproxy_exporter)
- [https://www.haproxy.com/blog/haproxy-exposes-a-prometheus-metrics-endpoint/](https://www.haproxy.com/blog/haproxy-exposes-a-prometheus-metrics-endpoint/)


### Load test HA Proxy

- [https://medium.com/@sachinmalhotra/load-testing-haproxy-part-1-f7d64500b75d](https://medium.com/@sachinmalhotra/load-testing-haproxy-part-1-f7d64500b75d)
- [https://medium.com/@sachinmalhotra/load-testing-haproxy-part-2-4c8677780df6](https://medium.com/@sachinmalhotra/load-testing-haproxy-part-2-4c8677780df6)
- [https://medium.com/free-code-camp/how-we-fine-tuned-haproxy-to-achieve-2-000-000-concurrent-ssl-connections-d017e61a4d27](https://medium.com/free-code-camp/how-we-fine-tuned-haproxy-to-achieve-2-000-000-concurrent-ssl-connections-d017e61a4d27)