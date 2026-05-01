# ============================================================
# Amazon ElastiCache — Redis 7
# ============================================================
# dev 설정:
#   - cache.t3.micro, 단일 노드
#   - auth_token 없음 (VPC 내 SG로 보호)
#   - 자동 장애 조치 없음
# ============================================================

resource "aws_elasticache_subnet_group" "main" {
  name        = "${local.name_prefix}-redis-subnet"
  subnet_ids  = aws_subnet.public[*].id
  description = "InfraRed ElastiCache 서브넷 그룹"

  tags = { Name = "${local.name_prefix}-redis-subnet" }
}

resource "aws_elasticache_cluster" "main" {
  cluster_id           = "${local.name_prefix}-redis"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  # 유지보수 / 백업
  maintenance_window       = "sun:05:00-sun:06:00"
  snapshot_retention_limit = 1
  snapshot_window          = "04:00-05:00"

  apply_immediately = true  # dev: 즉시 변경 적용

  tags = { Name = "${local.name_prefix}-redis" }
}

locals {
  redis_url = "redis://${aws_elasticache_cluster.main.cache_nodes[0].address}:${aws_elasticache_cluster.main.port}/0"
}
