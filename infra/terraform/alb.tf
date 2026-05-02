# ============================================================
# Application Load Balancer
# ============================================================
# 리스너:
#   :80   → Ingestion API (포트 8000)
#   :3000 → Frontend      (포트 3000)
# ============================================================

resource "aws_lb" "main" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  idle_timeout               = 60
  enable_deletion_protection = false  # dev

  tags = { Name = "${local.name_prefix}-alb" }
}

# ── Target Group: Ingestion API ──────────────────────────────
resource "aws_lb_target_group" "ingestion" {
  name        = "${local.name_prefix}-ingestion-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"  # Fargate awsvpc 모드

  health_check {
    enabled             = true
    path                = "/healthz"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
    matcher             = "200"
  }

  deregistration_delay = 30  # dev: 빠른 롤링 업데이트

  tags = { Name = "${local.name_prefix}-ingestion-tg" }
}

# ── Target Group: Frontend ───────────────────────────────────
resource "aws_lb_target_group" "frontend" {
  name        = "${local.name_prefix}-frontend-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
    matcher             = "200-399"
  }

  deregistration_delay = 30

  tags = { Name = "${local.name_prefix}-frontend-tg" }
}

# ── Listener: :80 → Ingestion ────────────────────────────────
resource "aws_lb_listener" "ingestion" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ingestion.arn
  }
}

# ── Listener: :3000 → Frontend ───────────────────────────────
resource "aws_lb_listener" "frontend" {
  load_balancer_arn = aws_lb.main.arn
  port              = 3000
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}
