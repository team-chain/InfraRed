# ============================================================
# ECS Fargate — 클러스터 + 태스크 정의 + 서비스
# ============================================================
# 서비스 목록:
#   ingestion        : FastAPI Ingestion API (ALB 연결)
#   frontend         : React 대시보드 (ALB 연결)
#   detection-worker : Redis events:raw 소비
#   enrichment-worker: Redis signals:matched 소비
#   correlation-worker: Redis signals:enriched 소비
#   llm-worker       : Redis incidents:new 소비 + Bedrock 호출
# ============================================================

# ── ECS 클러스터 ─────────────────────────────────────────────
resource "aws_ecs_cluster" "main" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "disabled"  # dev: 비용 절약
  }

  tags = { Name = "${local.name_prefix}-cluster" }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ── 공통 환경변수 (민감하지 않은 값) ──────────────────────────
locals {
  database_url = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:${aws_db_instance.main.port}/${var.db_name}"

  common_env = [
    { name = "ENV",        value = var.env },
    { name = "LOG_LEVEL",  value = "INFO" },
    { name = "TZ",         value = "Asia/Seoul" },
    { name = "TENANT_ID",  value = var.tenant_id },
    { name = "AGENT_ID",   value = var.agent_id },
    { name = "ASSET_ID",   value = var.asset_id },
    { name = "REDIS_URL",  value = local.redis_url },
    { name = "DATABASE_URL", value = local.database_url },
    { name = "JWT_ALG",    value = "HS256" },
    { name = "JWT_ISSUER", value = var.jwt_issuer },
    { name = "JWT_AUDIENCE", value = var.jwt_audience },
  ]

  # JWT_SECRET은 Secrets Manager에서 주입
  common_secrets = [
    {
      name      = "JWT_SECRET"
      valueFrom = aws_secretsmanager_secret.jwt_secret.arn
    }
  ]

  # awslogs 드라이버 공통 옵션 헬퍼
  # (각 태스크에서 서비스 이름만 바꿔서 사용)
  log_region = var.region
}

# ── 1. Ingestion API ─────────────────────────────────────────
resource "aws_ecs_task_definition" "ingestion" {
  family                   = "${local.name_prefix}-ingestion"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.ingestion_cpu
  memory                   = var.ingestion_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "ingestion"
    image     = "${local.ecr_base}/${local.name_prefix}-backend:latest"
    essential = true

    command = ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

    portMappings = [{ containerPort = 8000, protocol = "tcp" }]

    environment = concat(local.common_env, [
      { name = "INGEST_HOST",  value = "0.0.0.0" },
      { name = "INGEST_PORT",  value = "8000" },
      { name = "CORS_ORIGINS", value = var.cors_origins },
      { name = "INTERNAL_API_BASE_URL", value = "http://localhost:8000" },
    ])

    secrets = local.common_secrets

    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')\" || exit 1"]
      interval    = 15
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/infrared/${var.env}/ingestion"
        "awslogs-region"        = local.log_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Service = "ingestion" }
}

resource "aws_ecs_service" "ingestion" {
  name            = "${local.name_prefix}-ingestion"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.ingestion.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  enable_execute_command = true  # ECS Exec (디버그)

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true  # NAT Gateway 없이 ECR pull
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ingestion.arn
    container_name   = "ingestion"
    container_port   = 8000
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  depends_on = [aws_lb_listener.ingestion]

  tags = { Service = "ingestion" }
}

# ── 2. Frontend ──────────────────────────────────────────────
resource "aws_ecs_task_definition" "frontend" {
  family                   = "${local.name_prefix}-frontend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "frontend"
    image     = "${local.ecr_base}/${local.name_prefix}-frontend:latest"
    essential = true

    portMappings = [{ containerPort = 3000, protocol = "tcp" }]

    environment = [
      { name = "VITE_API_BASE_URL", value = "http://${aws_lb.main.dns_name}" }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/infrared/${var.env}/frontend"
        "awslogs-region"        = local.log_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Service = "frontend" }
}

resource "aws_ecs_service" "frontend" {
  name            = "${local.name_prefix}-frontend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.frontend.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.frontend.arn
    container_name   = "frontend"
    container_port   = 3000
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  depends_on = [aws_lb_listener.frontend]

  tags = { Service = "frontend" }
}

# ── Worker 공통 헬퍼 (태스크 정의 반복 감소) ─────────────────
# Terraform은 동적 반복 리소스를 위해 for_each를 사용하지만,
# 각 Worker의 command가 다르므로 개별 정의합니다.

# ── 3. Detection Worker ──────────────────────────────────────
resource "aws_ecs_task_definition" "detection_worker" {
  family                   = "${local.name_prefix}-detection-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "detection-worker"
    image     = "${local.ecr_base}/${local.name_prefix}-backend:latest"
    essential = true
    command   = ["python", "-m", "app.workers.detection.worker"]

    environment = local.common_env
    secrets     = local.common_secrets

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/infrared/${var.env}/detection-worker"
        "awslogs-region"        = local.log_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Service = "detection-worker" }
}

resource "aws_ecs_service" "detection_worker" {
  name            = "${local.name_prefix}-detection-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.detection_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  enable_execute_command = true

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  tags = { Service = "detection-worker" }
}

# ── 4. Enrichment Worker ─────────────────────────────────────
resource "aws_ecs_task_definition" "enrichment_worker" {
  family                   = "${local.name_prefix}-enrichment-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "enrichment-worker"
    image     = "${local.ecr_base}/${local.name_prefix}-backend:latest"
    essential = true
    command   = ["python", "-m", "app.workers.enrichment.worker"]

    environment = local.common_env
    secrets     = local.common_secrets

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/infrared/${var.env}/enrichment-worker"
        "awslogs-region"        = local.log_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Service = "enrichment-worker" }
}

resource "aws_ecs_service" "enrichment_worker" {
  name            = "${local.name_prefix}-enrichment-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.enrichment_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  enable_execute_command = true

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  tags = { Service = "enrichment-worker" }
}

# ── 5. Correlation Worker ────────────────────────────────────
resource "aws_ecs_task_definition" "correlation_worker" {
  family                   = "${local.name_prefix}-correlation-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "correlation-worker"
    image     = "${local.ecr_base}/${local.name_prefix}-backend:latest"
    essential = true
    command   = ["python", "-m", "app.workers.correlation.worker"]

    environment = local.common_env
    secrets     = local.common_secrets

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/infrared/${var.env}/correlation-worker"
        "awslogs-region"        = local.log_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Service = "correlation-worker" }
}

resource "aws_ecs_service" "correlation_worker" {
  name            = "${local.name_prefix}-correlation-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.correlation_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  enable_execute_command = true

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  tags = { Service = "correlation-worker" }
}

# ── 6. LLM Worker ────────────────────────────────────────────
resource "aws_ecs_task_definition" "llm_worker" {
  family                   = "${local.name_prefix}-llm-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "llm-worker"
    image     = "${local.ecr_base}/${local.name_prefix}-backend:latest"
    essential = true
    command   = ["python", "-m", "app.workers.llm.worker"]

    environment = concat(local.common_env, [
      { name = "BEDROCK_REGION",   value = var.bedrock_region },
      { name = "BEDROCK_MODEL_ID", value = var.bedrock_model_id },
    ])
    secrets = local.common_secrets

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/infrared/${var.env}/llm-worker"
        "awslogs-region"        = local.log_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Service = "llm-worker" }
}

resource "aws_ecs_service" "llm_worker" {
  name            = "${local.name_prefix}-llm-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.llm_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  enable_execute_command = true

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  tags = { Service = "llm-worker" }
}
