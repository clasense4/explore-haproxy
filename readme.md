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

Take a note on the backend instances private ip, then SSH to the HA Proxy instance. Update the `/etc/haproxy/haproxy.cfg` with this configuration.

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

![](/images/haproxy_in_action.webm)

---

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