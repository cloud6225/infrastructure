variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "profile" {
  default = "dev"
}

variable "subnet_azs" {
  default = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "vpc_name"{
    default = "main"
}

variable "cidr_block_vpc"{
  default = "10.0.0.0/16"
}

variable "cidr_block_route"{
}
  default = "0.0.0.0/0"