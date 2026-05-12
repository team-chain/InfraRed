"""Static Playbook -- LLM 비가용 시 fallback 대응 요약 (설계서 4.2).

rule_id 기반 분기로 탐지 컨텍스트에 맞는 한국어 요약 생성.
Discord 1차 즉시 알림 (get_first_alert_summary) 및
LLM Worker fallback (summarize_with_playbook) 에서 사용.
"""
from __future__ import annotations

from app.models.llm import LLMResult


def _render(template: str, *, source_ip: str | None = None, username: str | None = None) -> str:
    """템플릿 변수 치환 ({source_ip}, {username})."""
    result = template
    result = result.replace("{source_ip}", source_ip or "알 수 없는 IP")
    result = result.replace("{username}", username or "알 수 없는 계정")
    return result


_PLAYBOOK: dict[str, dict] = {
    "AUTH-001": {
        "title": "SSH 브루트포스 공격",
        "summary": "{source_ip}에서 {username} 계정을 대상으로 SSH 브루트포스 공격이 탐지되었습니다. 단시간 내 다수의 로그인 실패가 확인되었습니다.",
        "intent": "자격증명 무차별 대입을 통한 SSH 계정 탈취 시도입니다. (MITRE T1110.001)",
        "kill_chain": "Credential Access 단계. 공격자가 자동화된 도구로 패스워드를 대입하고 있습니다.",
        "actions": [
            "해당 IP의 SSH 접속 시도 횟수와 시간대를 확인하세요.",
            "fail2ban 또는 ufw로 해당 IP를 즉시 차단하세요.",
            "SSH 포트를 비표준 포트로 변경하거나 키 기반 인증만 허용하도록 설정하세요.",
            "authorized_keys 파일 변경 여부를 확인하세요.",
        ],
    },
    "AUTH-002": {
        "title": "root 계정 로그인 시도/성공",
        "summary": "{source_ip}에서 root 계정으로의 SSH 접근이 탐지되었습니다.",
        "intent": "최고 권한 계정 탈취 시도입니다. 성공 시 서버 전체가 장악됩니다. (MITRE T1078)",
        "kill_chain": "Initial Access 단계. root 직접 로그인은 대부분의 보안 정책에서 금지됩니다.",
        "actions": [
            "/etc/ssh/sshd_config에서 PermitRootLogin을 no로 설정하세요.",
            "해당 IP가 allowlist에 없다면 즉시 차단하세요.",
            "root 계정의 최근 명령 내역(last, history)을 즉시 확인하세요.",
            "sudo 설정 및 cron 작업 변경 여부를 점검하세요.",
        ],
    },
    "AUTH-003": {
        "title": "계정 열거 (Invalid User Probe)",
        "summary": "{source_ip}에서 존재하지 않는 계정으로 반복 접속을 시도하고 있습니다.",
        "intent": "유효한 사용자명을 탐색하는 계정 열거 공격입니다. (MITRE T1592)",
        "kill_chain": "Reconnaissance 단계. 이후 브루트포스 또는 Credential Stuffing으로 이어질 수 있습니다.",
        "actions": [
            "해당 IP를 방화벽 또는 fail2ban으로 차단하세요.",
            "SSH 배너 메시지를 최소화하여 정보 노출을 줄이세요.",
            "AllowUsers 지시자로 허용 계정을 명시적으로 제한하세요.",
        ],
    },
    "AUTH-004": {
        "title": "로그인 실패 후 성공 (계정 탈취 의심)",
        "summary": "{source_ip}에서 {username} 계정에 반복 실패 후 로그인 성공이 탐지되었습니다. 계정 탈취 가능성이 높습니다.",
        "intent": "무차별 대입 또는 Credential Stuffing을 통한 계정 탈취 성공 의심입니다. (MITRE T1110.001 -> T1078)",
        "kill_chain": "Initial Access 단계. 공격자가 인증에 성공하여 내부 진입이 완료된 상태일 수 있습니다.",
        "actions": [
            "{username} 계정의 비밀번호를 즉시 변경하세요.",
            "최근 로그인 세션(w, last)을 확인하고 의심스러운 세션을 종료하세요.",
            "계정에서 실행된 명령어 이력을 점검하세요.",
            "MFA(다중 인증)를 활성화하세요.",
            "해당 IP를 차단하고 동일 IP의 다른 서버 접근 시도를 확인하세요.",
        ],
    },
    "AUTH-005": {
        "title": "신규 IP에서 로그인 성공",
        "summary": "{source_ip}에서 {username} 계정으로 처음 보는 IP 주소를 통해 로그인이 성공했습니다.",
        "intent": "기존에 사용하지 않던 IP에서의 접근으로 계정 탈취 또는 외부 접근 가능성이 있습니다. (MITRE T1078)",
        "kill_chain": "Initial Access 단계. 정상 사용자의 비정상 접근 또는 탈취된 계정 사용일 수 있습니다.",
        "actions": [
            "사용자에게 접근 여부를 직접 확인하세요.",
            "해당 IP의 지역 정보와 VPN 사용 여부를 확인하세요.",
            "의심스러운 경우 세션을 즉시 종료하고 비밀번호를 변경하세요.",
        ],
    },
    "AUTH-006": {
        "title": "비업무 시간대 로그인",
        "summary": "{source_ip}에서 {username} 계정으로 새벽 시간대(KST 00:00~06:00)에 로그인이 탐지되었습니다.",
        "intent": "비업무 시간대의 접근은 내부자 위협 또는 탈취된 계정 사용 가능성을 시사합니다. (MITRE T1078)",
        "kill_chain": "Initial Access 단계. 비정상적인 시간대의 접근입니다.",
        "actions": [
            "해당 사용자에게 접근 여부를 확인하세요.",
            "최근 실행된 명령어 이력을 점검하세요.",
            "필요시 계정을 임시 잠금하고 비밀번호를 변경하세요.",
        ],
    },
    "AUTH-006A": {
        "title": "Credential Stuffing 공격",
        "summary": "{username} 계정에 대해 1시간 내 다수의 서로 다른 IP({source_ip} 포함)에서 로그인 시도가 탐지되었습니다.",
        "intent": "유출된 자격증명 목록을 이용한 Credential Stuffing 공격입니다. (MITRE T1110.004)",
        "kill_chain": "Credential Access 단계. 대규모 자동화 공격으로 다수의 IP를 통해 동일 계정을 공격합니다.",
        "actions": [
            "{username} 계정의 비밀번호를 즉시 변경하세요.",
            "계정에 MFA(다중 인증)를 활성화하세요.",
            "공격에 사용된 IP 대역을 방화벽에서 차단하세요.",
            "Have I Been Pwned 등에서 해당 계정의 유출 여부를 확인하세요.",
        ],
    },
    "AUTH-006B": {
        "title": "Password Spraying 공격",
        "summary": "{source_ip}에서 1시간 내 다수의 서로 다른 계정을 대상으로 로그인을 시도했습니다.",
        "intent": "계정 잠금을 피하기 위해 여러 계정에 소수의 패스워드를 시도하는 Password Spraying 공격입니다. (MITRE T1110.003)",
        "kill_chain": "Credential Access 단계. 조직 내 취약한 공통 패스워드를 사용하는 계정을 노립니다.",
        "actions": [
            "해당 IP를 즉시 차단하세요.",
            "조직 전체 비밀번호 정책(길이, 복잡도)을 점검하세요.",
            "피해 계정 여부를 확인하고 비밀번호를 변경하세요.",
            "MFA를 전사적으로 활성화하세요.",
        ],
    },
    "AUTH-007": {
        "title": "해외 IP 로그인 성공",
        "summary": "{source_ip}(해외 IP)에서 {username} 계정으로 로그인이 성공했습니다.",
        "intent": "허용되지 않은 국가의 IP에서의 접근으로 VPN 우회 또는 계정 탈취 가능성이 있습니다. (MITRE T1078)",
        "kill_chain": "Initial Access 단계. 지리적으로 비정상적인 접근입니다.",
        "actions": [
            "사용자에게 해외에서의 접근 여부를 확인하세요.",
            "확인되지 않은 경우 즉시 세션을 종료하고 비밀번호를 변경하세요.",
            "Geo-blocking 정책을 적용하세요.",
        ],
    },
    "WEB-HNY-001": {
        "title": "Honeypot 경로 접근 탐지",
        "summary": "{source_ip}에서 공개되지 않은 Honeypot 경로에 접근했습니다. 자동화된 스캐너 또는 의도적인 탐색 활동입니다.",
        "intent": "정상 사용자는 접근하지 않는 숨겨진 경로 접근으로 공격자의 정찰 활동을 의미합니다.",
        "kill_chain": "Reconnaissance 단계. 공격자가 서버 구조를 파악하려는 시도입니다.",
        "actions": [
            "해당 IP의 전체 접근 로그를 확인하세요.",
            "자동화된 스캐너라면 IP를 즉시 차단하세요.",
            "접근한 경로와 민감한 파일 노출 여부를 점검하세요.",
            "WAF(Web Application Firewall) 규칙을 추가하세요.",
        ],
    },
    "WEB-001": {
        "title": "웹셸 업로드/접근 의심",
        "summary": "{source_ip}에서 업로드 디렉터리 내 실행 가능한 파일(웹셸 의심)에 접근했습니다.",
        "intent": "파일 업로드 취약점을 통한 원격 코드 실행 시도입니다. (MITRE T1505.003)",
        "kill_chain": "Execution 단계. 웹셸이 배포되면 서버를 원격으로 제어할 수 있습니다.",
        "actions": [
            "업로드 디렉터리의 실행 권한을 즉시 제거하세요.",
            "의심 파일을 격리하고 내용을 분석하세요.",
            "웹서버 프로세스의 최근 실행 명령어를 확인하세요.",
            "파일 업로드 기능의 확장자 및 MIME 타입 검증을 강화하세요.",
        ],
    },
    "WEB-002": {
        "title": "관리자 경로 스캔",
        "summary": "{source_ip}에서 관리자 및 로그인 페이지를 반복 탐색하고 있습니다.",
        "intent": "관리자 인터페이스를 찾기 위한 자동화 스캔입니다. (MITRE T1595)",
        "kill_chain": "Reconnaissance 단계. 이후 브루트포스 또는 취약점 공격으로 이어질 수 있습니다.",
        "actions": [
            "관리자 페이지에 IP 화이트리스트를 적용하세요.",
            "해당 IP를 차단하세요.",
            "HTTP 요청 속도 제한(Rate Limiting)을 적용하세요.",
        ],
    },
    "WEB-007": {
        "title": "CVE 취약점 탐침 경로 접근",
        "summary": "{source_ip}에서 알려진 취약점 경로(.env, /actuator, /.git 등)에 접근을 시도했습니다.",
        "intent": "자동화된 취약점 스캐너를 이용한 CVE 탐침 공격입니다. (MITRE T1595.002)",
        "kill_chain": "Reconnaissance 단계. 노출된 설정 파일이나 취약한 엔드포인트를 찾는 시도입니다.",
        "actions": [
            "해당 경로가 실제로 노출되어 있는지 즉시 확인하세요.",
            ".env, .git 등 민감한 파일을 웹 루트 밖으로 이동하세요.",
            "해당 IP를 차단하고 WAF 규칙을 추가하세요.",
            "서버 응답에서 불필요한 헤더(Server, X-Powered-By)를 제거하세요.",
        ],
    },
    "NET-001": {
        "title": "HTTP Flood (DDoS 의심)",
        "summary": "{source_ip}에서 단시간 내 대량의 HTTP 요청이 탐지되었습니다. DDoS 또는 자동화된 스크레이핑 공격입니다.",
        "intent": "서비스 가용성을 저하시키기 위한 HTTP Flood 공격입니다. (MITRE T1595)",
        "kill_chain": "Impact 단계. 과도한 요청으로 서버 자원을 고갈시켜 서비스 거부를 유발합니다.",
        "actions": [
            "해당 IP를 즉시 차단하세요.",
            "nginx의 limit_req_zone 설정으로 요청 속도를 제한하세요.",
            "CDN 또는 WAF의 DDoS 보호 기능을 활성화하세요.",
            "요청 패턴을 분석하여 봇 특징(User-Agent, 요청 경로)을 확인하세요.",
        ],
    },
}

# 이전 명칭 호환 별칭
_PLAYBOOK["AUTH-CS-A"] = _PLAYBOOK["AUTH-006A"]
_PLAYBOOK["AUTH-CS-B"] = _PLAYBOOK["AUTH-006B"]

# 기본 Playbook (알 수 없는 룰)
_DEFAULT_PLAYBOOK = {
    "title": "보안 이벤트 탐지",
    "summary": "{source_ip}에서 보안 이벤트가 탐지되었습니다. 로그를 확인하여 조치하세요.",
    "intent": "자동 분류되지 않은 보안 이벤트입니다.",
    "kill_chain": "단계 미분류",
    "actions": [
        "상세 로그를 확인하세요.",
        "의심스러운 경우 해당 IP를 차단하세요.",
        "보안 담당자에게 보고하세요.",
    ],
}


def get_first_alert_summary(
    *,
    rule_id: str,
    severity: str,
    source_ip: str | None = None,
    username: str | None = None,
) -> str:
    """Discord 1차 즉시 알림용 한 줄 요약 반환."""
    entry = _PLAYBOOK.get(rule_id, _DEFAULT_PLAYBOOK)
    title = entry["title"]
    summary = _render(entry["summary"], source_ip=source_ip, username=username)
    return f"[{severity.upper()}] {title}\n{summary}"


def summarize_with_playbook(
    *,
    rule_ids: list[str],
    severity: str,
    source_ip: str | None = None,
    username: str | None = None,
) -> LLMResult:
    """LLM 비가용 시 Static Playbook 기반 LLMResult 반환 (fallback)."""
    # 첫 번째 매칭 룰로 Playbook 선택
    entry = _DEFAULT_PLAYBOOK
    matched_rule = "UNKNOWN"
    for rule_id in rule_ids:
        if rule_id in _PLAYBOOK:
            entry = _PLAYBOOK[rule_id]
            matched_rule = rule_id
            break

    plain_summary = _render(entry["summary"], source_ip=source_ip, username=username)
    attack_intent = entry["intent"]
    kill_chain_analysis = entry["kill_chain"]
    recommended_actions = entry["actions"]
    confidence_note = f"Static Playbook 기반 응답 (룰: {matched_rule}). AI 분석 없이 사전 정의된 대응 지침입니다."

    return LLMResult(
        incident_id="",
        model="static-playbook",
        plain_summary=plain_summary,
        attack_intent=attack_intent,
        kill_chain_analysis=kill_chain_analysis,
        recommended_actions=recommended_actions,
        confidence_note=confidence_note,
        cached=False,
        status="fallback",
    )
