################
# HA Proxy Instance
################

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
    cidr_blocks = ["202.80.214.161/32"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["202.80.214.161/32"]
  }

  ingress {
    from_port   = 32700
    to_port     = 32700
    protocol    = "tcp"
    cidr_blocks = ["202.80.214.161/32"]
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

resource "aws_route53_record" "www" {
  zone_id = "Z0267035H2P3O9XYGZ3K"
  name    = "haproxy.serverless.my.id"
  type    = "A"
  ttl     = "300"
  records = ["${module.haproxy.public_ip}"]
}


################
# Backend Instance
################

resource "aws_security_group" "backend_sg" {
  name        = "backend"
  description = "Allow access from HA Proxy instance"
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
    cidr_blocks = ["${module.haproxy.private_ip}/32"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
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
