# infrastructure

## Description
Use Terraform to create following resources:
 - Virtual Private Cloud
 - 3 subnets each in different availability zones
 - Internet gateway and attached to VPC
 - Route table and attach it to all subnets
## Tech Stack
- AWS CLI
- Terraform

## How to run the project
- Clone this repo and go inside repo in you local machine
- Configure IAM user profile in AWS CLI using command
  `aws configure --profile dev`
- Set aws provider profile
- Initialize terraform using
  `terraform init`
- Creating network resources and running terraform
  `terraform plan`
  `terraform apply`
- Clean up of resources using
  `terraform destroy`

## Import ACM certificate
- Command to import ACM certificate
`aws acm import-certificate --certificate fileb://C:/Users/mrudu/Downloads/prod_mrudulladhwe_me/prod_mrudulladhwe_me.crt --certificate-chain fileb://C:/Users/mrudu/Downloads/prod_mrudulladhwe_me/prod_mrudulladhwe_me.ca-bundle --private-key fileb://C:/Users/mrudu/Desktop/ssl/csr.key`



