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