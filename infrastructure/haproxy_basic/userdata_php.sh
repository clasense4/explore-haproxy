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