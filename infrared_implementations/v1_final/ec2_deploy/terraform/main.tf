###############################################################
# InfraRed — EC2 실 배포 Terraform
# 설계서_최종.docx 구현 순서 #3
###############################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # 원격 상태 관리 (S3 + DynamoDB 잠금)
  backend "s3" {
    bucket         = "infrared-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "infrared-terraform-lock"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "InfraRed"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

###############################################################
# 데이터 소스
###############################################################
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

###############################################################
# VPC 및 네트워크
###############################################################
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "infrared-vpc-${var.environment}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "infrared-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "infrared-public-subnet" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "infrared-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

###############################################################
# 보안 그룹
###############################################################
resource "aws_security_group" "infrared" {
  name        = "infrared-sg-${var.environment}"
  description = "InfraRed security group"
  vpc_id      = aws_vpc.main.id

  # HTTP (Nginx → HTTPS 리다이렉트)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }
  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }
  # SSH (관리 IP만 허용)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
    description = "SSH admin access"
  }
  # Agent 인그레스 (8443 — TLS 클라이언트 인증)
  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Agent TLS ingress"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All egress"
  }

  tags = { Name = "infrared-sg" }
}

###############################################################
# IAM Role (EC2 → Bedrock, S3, SSM)
###############################################################
resource "aws_iam_role" "ec2_role" {
  name = "infrared-ec2-role-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "infrared-ec2-policy"
  role = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = "arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.claude-*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${var.s3_log_bucket}",
          "arn:aws:s3:::${var.s3_log_bucket}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
        Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/infrared/*"
      },
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData", "cloudwatch:GetMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "InfraRed" }
        }
      },
    ]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  name = "infrared-ec2-profile-${var.environment}"
  role = aws_iam_role.ec2_role.name
}

###############################################################
# SSM Parameter Store — 시크릿
###############################################################
resource "aws_ssm_parameter" "db_password" {
  name  = "/infrared/${var.environment}/db_password"
  type  = "SecureString"
  value = var.db_password
  tags  = {}
}

resource "aws_ssm_parameter" "jwt_secret" {
  name  = "/infrared/${var.environment}/jwt_secret"
  type  = "SecureString"
  value = var.jwt_secret
  tags  = {}
}

resource "aws_ssm_parameter" "redis_password" {
  name  = "/infrared/${var.environment}/redis_password"
  type  = "SecureString"
  value = var.redis_password
  tags  = {}
}

###############################################################
# EC2 인스턴스
###############################################################
resource "aws_instance" "infrared" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.infrared.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2.name
  key_name               = var.key_pair_name

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    delete_on_termination = true
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment    = var.environment
    aws_region     = var.aws_region
    domain_name    = var.domain_name
    s3_log_bucket  = var.s3_log_bucket
    discord_webhook = var.discord_webhook_url
  }))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 강제
    http_put_response_hop_limit = 1
  }

  monitoring = true

  tags = { Name = "infrared-server-${var.environment}" }

  lifecycle {
    ignore_changes = [ami]   # AMI 자동 업데이트 시 인스턴스 재생성 방지
  }
}

###############################################################
# Elastic IP
###############################################################
resource "aws_eip" "infrared" {
  instance = aws_instance.infrared.id
  domain   = "vpc"
  tags     = { Name = "infrared-eip" }
}

###############################################################
# S3 — 로그 장기 보관
###############################################################
resource "aws_s3_bucket" "logs" {
  bucket = var.s3_log_bucket
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    default_retention {
      mode  = "GOVERNANCE"
      days  = 90
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "archive-old-logs"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############################################################
# CloudWatch 알람
###############################################################
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "infrared-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "EC2 CPU 사용률 80% 초과"
  dimensions          = { InstanceId = aws_instance.infrared.id }
}

resource "aws_cloudwatch_metric_alarm" "disk_high" {
  alarm_name          = "infrared-disk-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "disk_used_percent"
  namespace           = "InfraRed"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  alarm_description   = "디스크 사용률 85% 초과"
}

###############################################################
# 출력값
###############################################################
output "instance_public_ip" {
  description = "EC2 인스턴스 공인 IP"
  value       = aws_eip.infrared.public_ip
}

output "instance_id" {
  description = "EC2 인스턴스 ID"
  value       = aws_instance.infrared.id
}

output "api_url" {
  description = "InfraRed API URL"
  value       = "https://${var.domain_name}"
}

output "s3_log_bucket" {
  description = "S3 로그 버킷 이름"
  value       = aws_s3_bucket.logs.bucket
}
