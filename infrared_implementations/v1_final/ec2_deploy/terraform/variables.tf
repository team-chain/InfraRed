variable "aws_region"          { default = "us-east-1" }
variable "environment"         { default = "production" }
variable "instance_type"       { default = "t3.small" }
variable "vpc_cidr"            { default = "10.10.0.0/16" }
variable "public_subnet_cidr"  { default = "10.10.1.0/24" }
variable "key_pair_name"       { description = "EC2 Key Pair 이름" }
variable "domain_name"         { description = "인프라레드 도메인 (예: infrared.yourdomain.com)" }
variable "s3_log_bucket"       { description = "로그 보관 S3 버킷 이름" }
variable "db_password"         { sensitive = true }
variable "jwt_secret"          { sensitive = true }
variable "redis_password"      { sensitive = true }
variable "discord_webhook_url" { sensitive = true; default = "" }
variable "admin_cidr_blocks"   { default = ["0.0.0.0/0"]; description = "SSH 허용 IP CIDR 목록" }
