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