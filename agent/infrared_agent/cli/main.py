"""
InfraRed Agent CLI 진입점
==========================
설치 후 `infrared` 명령으로 실행.

서브커맨드:
    infrared canary install  --profile web-server
    infrared canary install  --profile aws --dry-run
    infrared canary status
    infrared canary uninstall

setup (pyproject.toml / setup.py) 에서:
    [project.scripts]
    infrared = "infrared_agent.cli.main:main"
"""
from __future__ import annotations

import sys

try:
    import typer
    _TYPER_OK = True
except ImportError:
    _TYPER_OK = False

from infrared_agent.cli.canary import app as canary_app


def main() -> None:
    if not _TYPER_OK:
        print(
            "❌ typer가 설치되지 않았습니다.\n"
            "   pip install 'infrared-agent[cli]' 또는 pip install typer 를 실행하세요.",
            file=sys.stderr,
        )
        sys.exit(1)

    # 최상위 CLI 앱 구성
    root = typer.Typer(
        name="infrared",
        help="InfraRed Agent CLI",
        no_args_is_help=True,
    )

    # 서브커맨드 그룹 등록
    root.add_typer(canary_app, name="canary")

    root()


if __name__ == "__main__":
    main()
