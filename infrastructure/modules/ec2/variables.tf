variable "name" {
  description = "Name identifier"
  type        = string
  default     = ""
}
variable "ami_id" {
  description = "AMI ID"
  type        = string
}
variable "instance_type" {
  description = "Instance type"
  type        = string
  default     = "t2.micro"
}
variable "key_name" {
  description = "Key name for SSH"
  type        = string
}
variable "associate_public_ip_address" {
  description = "true or false"
  type        = bool
}
variable "security_groups" {
  description = "List of security groups"
  type        = list(string)
}
variable "subnet_id" {
  description = "Subnet ID"
  type        = string
}
variable "user_data" {
  description = "User data"
}