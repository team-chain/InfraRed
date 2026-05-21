"""Phase 2-C/D: RBAC + Tenant Membership + 온보딩 플로우 API.

설계서 2-C: 역할은 user 자체 속성이 아닌 테넌트 내 역할.
한 사용자가 여러 테넌트에 다른 역할로 소속 가능.

설계서 2-D: 신규 테넌트 가입부터 에이전트 설치까지 5단계 온보딩.

엔드포인트:
  GET    /users/me/memberships         - 내 테넌트 멤버십 목록
  GET    /users/{tenant_id}/members    - 테넌트 멤버 목록
  POST   /users/{tenant_id}/invite     - 멤버 초대
  PATCH  /users/{tenant_id}/members/{user_id}/role - 역할 변경
  DELETE /users/{tenant_id}/members/{user_id}      - 멤버 제거
  GET    /onboarding/status            - 온보딩 상태
  POST   /onboarding/complete/{step}   - 온보딩 단계 완료
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.config import get_settings
from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_role
from app.iam.security import create_token, verify_user_token

router = APIRouter(tags=["users"])

_VALID_ROLES = {"owner", "security_manager", "analyst", "viewer"}


async def _send_invite_email(email: str, tenant_id: str, role: str) -> None:
    """초대 메일 자동 발송 (best-effort).

    pending_invitation 저장 직후 호출. SMTP/SES 미설정시 조용히 skip.
    """
    from urllib.parse import urlencode
    settings = get_settings()
    base = settings.frontend_base_url or "https://app.infrared.kr"
    params = urlencode({"invite_email": email, "tenant_id": tenant_id, "role": role})
    link = f"{base}/?{params}"
    body = (
        f"InfraRed {tenant_id} 테넌트에 {role} 권한으로 초대받으셨습니다.\n\n"
        f"가입을 완료하려면 다음 링크로 접속하세요 (14일 유효):\n"
        f"{link}\n\n"
        f"본인이 가입한 적이 없다면 무시하셔도 됩니다."
    )
    try:
        from asyncio import to_thread
        from app.dispatcher.email import send_email_alert
        await to_thread(
            send_email_alert,
            f"[InfraRed] {tenant_id} 초대",
            body,
            to_override=email,
        )
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).warning(
            "invite_email_send_failed email=%s tenant=%s error=%s",
            email, tenant_id, exc,
        )


# ============================================================
# 멤버십 관리
# ============================================================

class InviteRequest(BaseModel):
    email: str
    role: str = Field(..., pattern="^(owner|security_manager|analyst|viewer)$")


class RoleChangeRequest(BaseModel):
    role: str = Field(..., pattern="^(owner|security_manager|analyst|viewer)$")


@router.get("/users/me/memberships")
async def my_memberships(
    claims: dict = Depends(verify_user_token),
) -> dict:
    """현재 사용자의 모든 테넌트 멤버십 목록."""
    user_id = str(claims["sub"])
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT tm.tenant_id, tm.role, tm.created_at,
                       t.name as tenant_name, t.plan
                FROM tenant_memberships tm
                JOIN tenants t ON tm.tenant_id = t.tenant_id
                WHERE tm.user_id = :user_id
                ORDER BY tm.created_at
            """),
            {"user_id": user_id},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "tenant_id": r["tenant_id"],
                "tenant_name": r["tenant_name"],
                "plan": r["plan"],
                "role": r["role"],
                "joined_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


@router.get("/users/{tenant_id}/members")
async def list_members(
    tenant_id: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """테넌트 멤버 목록."""
    if claims["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT tm.user_id, tm.role, tm.created_at,
                       u.email, u.mfa_enabled
                FROM tenant_memberships tm
                JOIN users u ON tm.user_id = u.user_id
                WHERE tm.tenant_id = :tenant_id
                ORDER BY tm.created_at
            """),
            {"tenant_id": tenant_id},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "user_id": r["user_id"],
                "email": r["email"],
                "role": r["role"],
                "mfa_enabled": r["mfa_enabled"],
                "joined_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


@router.get("/users/{tenant_id}/pending-invitations")
async def list_pending_invitations(
    tenant_id: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """미가입 사용자 대상 초대 목록 (가입 대기 중)."""
    if claims["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT id, email, role, created_at, expires_at
                FROM pending_invitations
                WHERE tenant_id = :tenant_id AND expires_at > NOW()
                ORDER BY created_at DESC
            """),
            {"tenant_id": tenant_id},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "id": str(r["id"]),
                "email": r["email"],
                "role": r["role"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
            }
            for r in rows
        ]
    }


@router.delete("/users/{tenant_id}/pending-invitations/{invitation_id}")
async def cancel_pending_invitation(
    tenant_id: str,
    invitation_id: str,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """대기 중인 초대 취소."""
    if claims["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    async with get_session() as session:
        result = await session.execute(
            text("""
                DELETE FROM pending_invitations
                WHERE id = :id AND tenant_id = :tenant_id
                RETURNING email
            """),
            {"id": invitation_id, "tenant_id": tenant_id},
        )
        deleted = result.fetchone()
        if not deleted:
            raise HTTPException(status_code=404, detail="invitation_not_found")
        await session.commit()

    return {"status": "cancelled", "email": deleted[0]}


@router.post("/users/{tenant_id}/invite", status_code=201)
async def invite_member(
    tenant_id: str,
    payload: InviteRequest,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """멤버 초대 (owner만 가능).

    가입된 사용자면 즉시 tenant_memberships에 추가.
    미가입자면 pending_invitations에 저장하여 가입 시 자동 적용.
    """
    if claims["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    inviter_id = str(claims["sub"])

    async with get_session() as session:
        # 사용자 조회
        user_row = await session.execute(
            text("SELECT user_id FROM users WHERE email = :email LIMIT 1"),
            {"email": payload.email},
        )
        user = user_row.fetchone()

        if user:
            # 기존 가입자 → 즉시 멤버십 부여
            user_id = str(user[0])

            exists = await session.execute(
                text("SELECT 1 FROM tenant_memberships WHERE tenant_id = :tid AND user_id = :uid"),
                {"tid": tenant_id, "uid": user_id},
            )
            if exists.fetchone():
                raise HTTPException(status_code=409, detail="already_member")

            await session.execute(
                text("""
                    INSERT INTO tenant_memberships (tenant_id, user_id, role, invited_by)
                    VALUES (:tenant_id, :user_id, :role, :invited_by)
                """),
                {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "role": payload.role,
                    "invited_by": inviter_id,
                },
            )
            await session.commit()

            await write_audit_log(
                tenant_id=tenant_id, actor=inviter_id, action="user.invite",
                resource=payload.email,
                metadata={"role": payload.role, "status": "joined"},
            )
            # 기존 가입자에게도 합류 안내 메일 발송 (Dashboard 로그인 안내)
            await _send_invite_email(payload.email, tenant_id, payload.role)
            return {
                "status": "joined",
                "user_id": user_id,
                "email": payload.email,
                "role": payload.role,
            }

        # 미가입자 → pending_invitations에 저장
        # 동일 (tenant_id, email) pending이 있으면 role/inviter/expires_at 갱신
        await session.execute(
            text("""
                INSERT INTO pending_invitations (tenant_id, email, role, invited_by, expires_at)
                VALUES (:tenant_id, :email, :role, :invited_by, NOW() + INTERVAL '14 days')
                ON CONFLICT (tenant_id, email) DO UPDATE SET
                    role = EXCLUDED.role,
                    invited_by = EXCLUDED.invited_by,
                    expires_at = EXCLUDED.expires_at
            """),
            {
                "tenant_id": tenant_id,
                "email": payload.email,
                "role": payload.role,
                "invited_by": inviter_id,
            },
        )
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id, actor=inviter_id, action="user.invite",
        resource=payload.email,
        metadata={"role": payload.role, "status": "pending"},
    )
    # 미가입자에게 가입 링크 메일 자동 발송
    await _send_invite_email(payload.email, tenant_id, payload.role)
    return {
        "status": "pending",
        "email": payload.email,
        "role": payload.role,
        "expires_in_days": 14,
    }


@router.patch("/users/{tenant_id}/members/{target_user_id}/role")
async def change_member_role(
    tenant_id: str,
    target_user_id: str,
    payload: RoleChangeRequest,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """멤버 역할 변경."""
    if claims["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    actor_id = str(claims["sub"])

    async with get_session() as session:
        result = await session.execute(
            text("""
                UPDATE tenant_memberships
                SET role = :role
                WHERE tenant_id = :tenant_id AND user_id = :user_id
                RETURNING user_id
            """),
            {"tenant_id": tenant_id, "user_id": target_user_id, "role": payload.role},
        )
        if not result.fetchone():
            raise HTTPException(status_code=404, detail="member_not_found")
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id, actor=actor_id, action="user.role_change",
        resource=target_user_id, metadata={"new_role": payload.role},
    )
    return {"user_id": target_user_id, "role": payload.role}


@router.delete("/users/{tenant_id}/members/{target_user_id}")
async def remove_member(
    tenant_id: str,
    target_user_id: str,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """멤버 제거."""
    if claims["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    actor_id = str(claims["sub"])

    # owner 스스로 제거 방지
    if target_user_id == actor_id:
        raise HTTPException(status_code=400, detail="자기 자신을 제거할 수 없습니다")

    async with get_session() as session:
        result = await session.execute(
            text("""
                DELETE FROM tenant_memberships
                WHERE tenant_id = :tenant_id AND user_id = :user_id
                RETURNING user_id
            """),
            {"tenant_id": tenant_id, "user_id": target_user_id},
        )
        if not result.fetchone():
            raise HTTPException(status_code=404, detail="member_not_found")
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id, actor=actor_id, action="user.remove", resource=target_user_id
    )
    return {"removed": True, "user_id": target_user_id}


# ============================================================
# Phase 2-D: 온보딩 플로우
# ============================================================

_ONBOARDING_STEPS = {
    1: "테넌트 등록",
    2: "API 토큰 발급",
    3: "설치 명령 생성",
    4: "연결 확인",
    5: "기본 정책 설정",
}


@router.get("/onboarding/status")
async def get_onboarding_status(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """온보딩 진행 상태."""
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT step, completed_steps, first_heartbeat_at, completed_at, updated_at
                FROM onboarding_state
                WHERE tenant_id = :tenant_id
            """),
            {"tenant_id": tenant_id},
        )
        row = result.mappings().fetchone()

        # 에이전트 연결 여부 실시간 확인
        agent_result = await session.execute(
            text("""
                SELECT COUNT(*) as count
                FROM agents
                WHERE tenant_id = :tenant_id
                  AND last_heartbeat > NOW() - INTERVAL '5 minutes'
            """),
            {"tenant_id": tenant_id},
        )
        connected_agents = agent_result.scalar() or 0

    if not row:
        return {
            "current_step": 1,
            "completed_steps": [],
            "total_steps": 5,
            "steps": [
                {"step": k, "name": v, "completed": False}
                for k, v in _ONBOARDING_STEPS.items()
            ],
            "agent_connected": connected_agents > 0,
            "completed": False,
        }

    completed_steps = row["completed_steps"] or []

    # Step 4 자동 완료: 에이전트 연결 감지
    if connected_agents > 0 and 4 not in completed_steps:
        completed_steps = sorted(set(completed_steps + [4]))

    return {
        "current_step": row["step"],
        "completed_steps": completed_steps,
        "total_steps": 5,
        "steps": [
            {
                "step": k,
                "name": v,
                "completed": k in completed_steps,
            }
            for k, v in _ONBOARDING_STEPS.items()
        ],
        "agent_connected": connected_agents > 0,
        "first_heartbeat_at": row["first_heartbeat_at"].isoformat() if row["first_heartbeat_at"] else None,
        "completed": row["completed_at"] is not None,
    }


@router.post("/onboarding/complete/{step}", status_code=200)
async def complete_onboarding_step(
    step: int,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """온보딩 단계 완료 처리."""
    tenant_id = claims["tenant_id"]

    if step not in _ONBOARDING_STEPS:
        raise HTTPException(status_code=400, detail=f"유효하지 않은 단계: {step}")

    now = datetime.now(timezone.utc)

    async with get_session() as session:
        # upsert
        await session.execute(
            text("""
                INSERT INTO onboarding_state (tenant_id, step, completed_steps, updated_at)
                VALUES (:tenant_id, :step, :steps, :now)
                ON CONFLICT (tenant_id) DO UPDATE
                SET completed_steps = (
                        SELECT ARRAY(
                            SELECT DISTINCT unnest(onboarding_state.completed_steps || :steps)
                            ORDER BY 1
                        )
                    ),
                    step = GREATEST(onboarding_state.step, :step),
                    updated_at = :now,
                    completed_at = CASE
                        WHEN :step = 5 THEN :now
                        ELSE onboarding_state.completed_at
                    END
            """),
            {
                "tenant_id": tenant_id,
                "step": step,
                "steps": [step],
                "now": now,
            },
        )
        await session.commit()

    return {
        "step": step,
        "step_name": _ONBOARDING_STEPS[step],
        "completed": True,
        "is_final": step == 5,
    }


@router.post("/onboarding/generate-install-command")
async def generate_install_command(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """에이전트 설치 one-liner 명령 생성.

    설계서 2-D 3단계: curl one-liner 자동 생성 (토큰 포함).
    """
    tenant_id = claims["tenant_id"]

    # 에이전트용 토큰 생성 (별도 짧은 TTL)
    token = create_token(
        subject=f"agent-setup-{tenant_id}",
        tenant_id=tenant_id,
        role="agent",
    )

    # 설치 명령 생성
    from app.config import get_settings  # noqa: PLC0415
    settings = get_settings()
    api_base = settings.internal_api_base_url.replace("http://ingestion:", "https://api.")

    install_cmd = (
        f'curl -fsSL "{api_base}/install-agent.sh" | '
        f'bash -s -- --token "{token}" --tenant "{tenant_id}"'
    )

    return {
        "command": install_cmd,
        "token": token,
        "tenant_id": tenant_id,
        "note": "이 명령은 10분간 유효합니다. 안전한 환경에서 실행하세요.",
    }
