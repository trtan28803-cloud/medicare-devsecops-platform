# Terraform Infrastructure as Code (IaC) - Hệ thống MediCare trên AWS Cloud
# Khởi tạo tự động: VPC, Public/Private Subnets, Security Group Zero-Trust & EC2
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS Region triển khai hạ tầng y tế MediCare"
  type        = string
  default     = "ap-southeast-1"
}

variable "allowed_vpn_cidr" {
  description = "Dải IP VPN Chi nhánh được phép truy cập quản trị"
  type        = string
  default     = "10.30.10.0/24"
}

resource "aws_vpc" "medicare_vpc" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name        = "medicare-hicp-vpc"
    Environment = "production"
    Project     = "MediCare-ZeroTrust"
  }
}

resource "aws_subnet" "vlan20_server_subnet" {
  vpc_id                  = aws_vpc.medicare_vpc.id
  cidr_block              = "10.20.10.0/24"
  map_public_ip_on_launch = false
  tags = {
    Name = "medicare-vlan20-server-subnet"
  }
}

resource "aws_security_group" "medicare_zero_trust_sg" {
  name        = "medicare-zero-trust-sg"
  description = "Zero Trust Security Group for MediCare EHR & Wazuh SIEM"
  vpc_id      = aws_vpc.medicare_vpc.id

  ingress {
    description = "HTTPS Web EHR via Nginx Reverse Proxy"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP Suricata IDS Probe & Redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.10.10.0/24", var.allowed_vpn_cidr]
  }

  ingress {
    description = "Wazuh Agent Enrollment & Telemetry"
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = ["10.10.10.0/24", var.allowed_vpn_cidr]
  }

  egress {
    description = "Allow controlled outbound updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "medicare-zero-trust-sg"
  }
}
