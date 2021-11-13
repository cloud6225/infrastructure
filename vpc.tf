

#creating vpc
resource "aws_vpc" "main" {
  cidr_block           = var.cidr_block_vpc
  enable_dns_hostnames = true
  tags = {
    Name = "main"
  }
}

#creating subnet
resource "aws_subnet" "public_subnet" {
  count                   = length(var.subnet_azs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${10 + count.index}.0/24"
  availability_zone       = element(var.subnet_azs, count.index)
  map_public_ip_on_launch = true
  tags = {
    Name = "PublicSubnet"
  }
}

#creating internet gateway for above subnets
resource "aws_internet_gateway" "gateway" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "main"
  }
}


#public route table created with destination CIDR block 0.0.0.0/0 and target as internet gateway
resource "aws_route_table" "routeTable" {
  vpc_id = aws_vpc.main.id

  depends_on = [aws_internet_gateway.gateway]

  route {
    cidr_block = var.cidr_block_route
    gateway_id = aws_internet_gateway.gateway.id
  }

  tags = {
    Name = "routeTable"
  }
}

#attaching subnets to routing table
resource "aws_route_table_association" "route" {
  count          = length(var.subnet_azs)
  subnet_id      = element(aws_subnet.public_subnet.*.id, count.index)
  route_table_id = aws_route_table.routeTable.id
}

data "aws_ami" "example_ami" {
  most_recent = true
  owners      = ["695302741031", "867641324123"]
}

#app security group
resource "aws_security_group" "application" {
  name        = "application"
  description = "app security group"
  vpc_id      = aws_vpc.main.id
  
  ingress = [
    {
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      description      = "TLS from VPC"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      description      = "SSH from VPC"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      description      = "HTTP from VPC"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description = "web application"
      from_port        = 8001
      to_port          = 8001
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = []
      self = false
    }
  ]
  egress = [
    {
      description = "HTTP"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = []
      self = false
    },
    {
      description = "HTTPS"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = []
      self = false
    },
    {
      description = "Postgres"
      from_port        = 5432
      to_port          = 5432
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = []
      self = false
    },
  ]
  tags = {
    Name = "application"
  }
}

#db security group
resource "aws_security_group" "database" {
  name        = "database"
  description = "app security group"
  vpc_id      = aws_vpc.main.id
  
  ingress = [
    {
      description      = "Porstgres"
      from_port        = 5432
      to_port          = 5432
      protocol         = "tcp"
      cidr_blocks      = []
      security_groups  = [aws_security_group.application.id]
      self             = false
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
    }
  ]
  tags = {
    Name = "database"
  }
}

#creating subnet group
resource "aws_db_subnet_group" "subnet_group" {
  name       = "subnet_group"
  subnet_ids = aws_subnet.public_subnet.*.id

  tags = {
    Name = "DB subnet group"
  }
}

#creating parameter group
resource "aws_db_parameter_group" "parameter_group" {
  name   = var.db_pg
  family = "postgres13"
}

#creating RDS instance
resource "aws_db_instance" "rds_instance" {
  allocated_storage      = 10
  engine                 = "postgres"
  engine_version         = "13"
  instance_class         = "db.t3.micro"
  multi_az               = false
  name                   = var.rds_name
  identifier             = "csye6225"
  username               = var.postgres_username
  password               = var.rds_password
  db_subnet_group_name   = aws_db_subnet_group.subnet_group.name
  parameter_group_name   = var.db_pg
  publicly_accessible    = false
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.database.id]
}

#creating S3 bucket
resource "aws_s3_bucket" "bucket" {
  bucket        = "${var.s3_name}.${var.profile}.${var.s3_domain}"
  force_destroy = true
  acl           = "private"

  lifecycle_rule {
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

// resource "aws_s3_bucket_public_access_block" "bucket_access" {
//   bucket = aws_s3_bucket.bucket.id

//   block_public_acls   = true
//   block_public_policy = true
//   ignore_public_acls = true
//   restrict_public_buckets = true
// }

#creating IAM role
resource "aws_iam_role" "role" {
  name = "EC2-CSYE6225"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "tag-value"
  }
}

#creating IAM policy

resource "aws_iam_policy" "policy" {
    name = "WebAppS3"
    description = "ec2 will be able to talk to s3 buckets"
    policy = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
              "s3:ListAllMyBuckets", 
              "s3:GetBucketLocation",
              "s3:GetObject",
              "s3:PutObject",
			        "s3:DeleteObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${aws_s3_bucket.bucket.id}",
                "arn:aws:s3:::${aws_s3_bucket.bucket.id}/*"
            ]
        }
    ]
    }
    EOF

}

resource "aws_iam_role_policy_attachment" "attach_role_policy" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}

#creating IAM profile
resource "aws_iam_instance_profile" "profile" {
  name = "profile"
  role = aws_iam_role.role.name
}

#creating ec2 instance
resource "aws_instance" "ec2_instance" {
  ami                     = data.aws_ami.example_ami.id
  instance_type           = "t2.micro"
  iam_instance_profile    = aws_iam_instance_profile.profile.name
  vpc_security_group_ids  = [aws_security_group.application.id]
  depends_on              = [aws_db_instance.rds_instance]
  disable_api_termination = false
  subnet_id               = aws_subnet.public_subnet[0].id
  key_name                = var.ec2_key
  root_block_device {
    delete_on_termination = true
    volume_size           = 20
    volume_type           = "gp2"
  }
  user_data = <<-EOF
  #! /bin/bash
  echo export POSTGRES_USER="${var.postgres_username}" >> /etc/environment
  echo export POSTGRES_PASSWORD="${var.rds_password}" >> /etc/environment
  echo export POSTGRES_HOST="${aws_db_instance.rds_instance.address}" >> /etc/environment
  echo export POSTGRES_DB="${var.rds_name}" >> /etc/environment
  echo export AWS_S3_BUCKET_NAME="${aws_s3_bucket.bucket.bucket}" >> /etc/environment
  echo export POSTGRES_PORT="${var.port}" >> /etc/environment
  echo export AWS_REGION_NAME="${var.region}" >> /etc/environment
 
  EOF

  tags = {
    Name = "MyEC2Instance"
  }
}






