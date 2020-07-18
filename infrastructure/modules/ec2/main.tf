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

output "id" {
  value = aws_instance.this.id
}
output "public_dns" {
  value = aws_instance.this.public_dns
}
output "public_ip" {
  value = aws_instance.this.public_ip
}
output "private_ip" {
  value = aws_instance.this.private_ip
}