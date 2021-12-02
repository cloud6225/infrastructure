variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "profile" {
  type = string
  description = "profile"
}

variable "subnet_azs" {
  default = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "vpc_name" {
  default = "main"
}

variable "cidr_block_vpc" {
  default = "10.0.0.0/16"
}

variable "cidr_block_route" {
  default = "0.0.0.0/0"
}

variable "mysubnet_group" {
  default = "subnet_group"
}

variable "db_pg" {
  default = "pg"
}

variable "s3_domain"{
	default = "mrudulladhwe"
}

variable "s3_name"{
	default = "bucket57"
}

variable "rds_password" {
  type = string
  description = "rds password"
}

variable "postgres_username" {
  type = string
  description = "postgres username"
}

variable "rds_name" {
  default = "csye6225"
}

variable "port" {
  default = "5432"
}

variable "ec2_key" {
  type        = string
  description = "ec2 key pair"
}

variable "aws_profile_name"{
    type = string
}


variable "domain_Name"{
    type = string
}

variable "prod_acc"{
  default = "695302741031"
}

variable "dynamoDBName"{
     description = "Enter DynamoDB Name"
     type = string
}

variable "fromAddress"{
  default = "prod.mrudulladhwe.me"
}

variable "lambdabucket"{
  default = "lambda.email.bucket"
}

variable "snstopic"{
  default = "user-updates-topic"
}