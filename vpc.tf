

#creating vpc
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "main"
  }
}

#creating subnet
resource "aws_subnet" "public_subnet" {
  count                   = "${length(var.subnet_azs)}"
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${10 + count.index}.0/24"
  availability_zone       = "${element(var.subnet_azs, count.index)}"
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
      cidr_block = "0.0.0.0/0"
      gateway_id = "${aws_internet_gateway.gateway.id}"
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
