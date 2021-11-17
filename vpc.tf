

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
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadbalancer_sg.id]
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
      security_groups  = [aws_security_group.loadbalancer_sg.id]
      self             = false
    },
    {
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      description      = "HTTP from VPC"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadbalancer_sg.id]
      self             = false
    },
    {
      description = "web application"
      from_port        = 8001
      to_port          = 8001
      protocol         = "tcp"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = [aws_security_group.loadbalancer_sg.id]
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
  depends_on  = [aws_vpc.main, aws_security_group.application]
  vpc_id      = aws_vpc.main.id
  
  ingress = [
    {
      description      = "Postgres"
      from_port        = 5432
      to_port          = 5432
      protocol         = "tcp"
      cidr_blocks      = [aws_vpc.main.cidr_block]
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

# Load Balancer Security Group
resource "aws_security_group" "loadbalancer_sg" {
  name          = "loadbalancer_sg"
  vpc_id        =  aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }

   ingress{
    from_port   = 8001
    to_port     = 8001
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    
    }

    ingress{
    description = "Postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }

  # Allow all outbound traffic.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
        Name = "loadbalancer_sg"
        Description = "Load Balancer Security Group"
    }
}

#creating subnet group
resource "aws_db_subnet_group" "subnet_group" {
  name       = "subnet_group"
  subnet_ids = aws_subnet.public_subnet.*.id

  tags = {
    Name = "My DB subnet group"
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
// resource "aws_instance" "ec2_instance" {
//   ami                     = data.aws_ami.example_ami.id
//   instance_type           = "t2.micro"
//   iam_instance_profile    = aws_iam_instance_profile.profile.name
//   vpc_security_group_ids  = [aws_security_group.application.id]
//   depends_on              = [aws_db_instance.rds_instance]
//   disable_api_termination = false
//   subnet_id               = aws_subnet.public_subnet[0].id
//   key_name                = var.ec2_key
//   root_block_device {
//     delete_on_termination = true
//     volume_size           = 20
//     volume_type           = "gp2"
//   }
//   user_data = <<-EOF
//   #! /bin/bash
//   echo export POSTGRES_USER="${var.postgres_username}" >> /etc/environment
//   echo export POSTGRES_PASSWORD="${var.rds_password}" >> /etc/environment
//   echo export POSTGRES_HOST="${aws_db_instance.rds_instance.address}" >> /etc/environment
//   echo export POSTGRES_DB="${var.rds_name}" >> /etc/environment
//   echo export AWS_S3_BUCKET_NAME="${aws_s3_bucket.bucket.bucket}" >> /etc/environment
//   echo export POSTGRES_PORT="${var.port}" >> /etc/environment
//   echo export AWS_REGION_NAME="${var.region}" >> /etc/environment
 
//   EOF

//   tags = {
//     Name = "MyEC2Instance"
//   }
// }


#launching configuration with auto-scaling group
resource "aws_launch_configuration" "as_conf" {
  name = "asg_launch_config"
  image_id      = data.aws_ami.example_ami.id
  instance_type = "t2.micro"
  key_name      = var.ec2_key
  associate_public_ip_address = true
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

  iam_instance_profile = aws_iam_instance_profile.profile.name
  security_groups = [aws_security_group.application.id]

  root_block_device {
    delete_on_termination = true
    volume_size           = 20
    volume_type           = "gp2"
  }

  depends_on              = [aws_db_instance.rds_instance, aws_s3_bucket.bucket]
}

resource "aws_lb" "load_balancing" {
  name               = "webapp-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.loadbalancer_sg.id]
  subnets            = aws_subnet.public_subnet.*.id
  ip_address_type    = "ipv4"

  tags = {
    Environment = "prod"
  }
}

resource "aws_lb_target_group" "target_grp" {
  name     = "target-grp"
  port     = 8001
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  depends_on = [aws_lb.load_balancing]

  tags = {
    name = "albTargetGroup"
  }
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 30
    path                = "/healthstatus"
    port                = "8001"
    matcher             = "200"
  }

}

resource "aws_lb_listener" "webapp_listener" {
  load_balancer_arn = aws_lb.load_balancing.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target_grp.arn
  }
}

resource "aws_autoscaling_group" "autoscaling_group" {
  name                 = "autoscalingGrp"
  default_cooldown     = 60
  launch_configuration = aws_launch_configuration.as_conf.name
  min_size             = 3
  max_size             = 5
  desired_capacity     = 3
  vpc_zone_identifier  = [aws_subnet.public_subnet[0].id]
  target_group_arns    = [aws_lb_target_group.target_grp.arn]

  tag {
    key                 = "Name"
    value               = "MyEC2Instance"
    propagate_at_launch = true
  }
}

# AutoScaling Policies
resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
}

resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  alarm_name          = "CPUAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "5"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoscaling_group.name
  }
  alarm_description = "Scale-up if CPU > 5% for 1 minute"
  alarm_actions     = [ aws_autoscaling_policy.WebServerScaleUpPolicy.arn ]
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_name          = "CPUAlarmLow"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "3"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoscaling_group.name
  }
  alarm_description = "Scale-down if CPU < 3% for 1 minute"
  alarm_actions     = [ aws_autoscaling_policy.WebServerScaleDownPolicy.arn ]
}

data "aws_route53_zone" "selected" {
  name = format("%s.%s",var.aws_profile_name, var.domain_Name)
  private_zone = false
}

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "api.${data.aws_route53_zone.selected.name}"
  type    = "A"
  
  alias {
    name = aws_lb.load_balancing.dns_name
    zone_id = aws_lb.load_balancing.zone_id
    evaluate_target_health = true
  }
}

resource "aws_iam_role_policy" "CodeDeploy_EC2_S3" {
  name = "CodeDeploy-EC2-S3"
  role = aws_iam_role.role.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*",
        "s3:List*",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}/*",
        "arn:aws:s3:::webapp.${var.aws_profile_name}.${var.domain_Name}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "gh_upload_s3" {
  name   = "gh_upload_s3"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                  "s3:Get*",
                  "s3:List*",
                  "s3:PutObject",
                  "s3:DeleteObject",
                  "s3:DeleteObjectVersion"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}",
                "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}/*"
              ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "GH_Code_Deploy" {
  name   = "GH-Code-Deploy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:application:${aws_codedeploy_app.code_deploy_app.name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
         "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentgroup:${aws_codedeploy_app.code_deploy_app.name}/${aws_codedeploy_deployment_group.code_deploy_deployment_group.deployment_group_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}

# IAM Role for CodeDeploy
resource "aws_iam_role" "code_deploy_role" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "ghactions-app_user_policy" {
  name   = "ghactions-app_user_policy"
  policy = <<-EOF
  {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": [
          "ec2:AttachVolume",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CopyImage",
          "ec2:CreateImage",
          "ec2:CreateKeypair",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteKeyPair",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSnapshot",
          "ec2:DeleteVolume",
          "ec2:DeregisterImage",
          "ec2:DescribeImageAttribute",
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:DescribeSubnets",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DetachVolume",
          "ec2:GetPasswordData",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:RegisterImage",
          "ec2:RunInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances"
        ],
        "Resource" : "*"
      }]
  }
  EOF

}

#CodeDeploy App and Group for webapp
resource "aws_codedeploy_app" "code_deploy_app" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "code_deploy_deployment_group" {
  app_name               = "${aws_codedeploy_app.code_deploy_app.name}"
  deployment_group_name  = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn       = "${aws_iam_role.code_deploy_role.arn}"
  autoscaling_groups     = [aws_autoscaling_group.autoscaling_group.name]

  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "MyEC2Instance"
  }

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  depends_on = [aws_codedeploy_app.code_deploy_app]
}

data "aws_caller_identity" "current" {}

locals {
  aws_user_account_id = "${data.aws_caller_identity.current.account_id}"
}

# Attach the policy for CodeDeploy role for webapp
resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = "${aws_iam_role.code_deploy_role.name}"
}

resource "aws_iam_user_policy_attachment" "ghactions-app_ec2_policy_attach" {
  user       = "ghactions-app"
  policy_arn = "${aws_iam_policy.ghactions-app_user_policy.arn}"
}

resource "aws_iam_user_policy_attachment" "ghactions-app_s3_policy_attach" {
  user       = "ghactions-app"
  policy_arn = "${aws_iam_policy.gh_upload_s3.arn}"
}

resource "aws_iam_user_policy_attachment" "ghactions-app_codedeploy_policy_attach" {
  user       = "ghactions-app"
  policy_arn = "${aws_iam_policy.GH_Code_Deploy.arn}"
}

resource "aws_iam_role_policy_attachment" "AmazonCloudWatchAgent" {
  role       = aws_iam_role.role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}






