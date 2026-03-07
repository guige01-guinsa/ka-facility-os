"""IAM guide HTML renderer."""

from __future__ import annotations

import html


def build_iam_guide_html(service_info: dict[str, str]) -> str:
    constraint_rows = [
        ("owner", "전체 사용자/IAM 기능 관리 가능"),
        ("manager", "자기 site_scope 안의 사용자만 관리 가능"),
        ("manager 제한", "owner 계정 관리 불가, owner 역할 부여 불가"),
        ("owner 보호", "활성 owner는 항상 최소 1명 유지"),
        ("자기 보호", "현재 로그인한 자기 자신은 비활성화 불가"),
        ("토큰 보호", "현재 로그인한 자기 사용자 토큰은 서버 폐기 불가"),
        ("legacy env token", "서버 revoke 대상이 아님"),
        ("토큰 표시", "신규 평문 토큰은 발급/회전 직후 1회만 표시"),
    ]
    step_cards = [
        (
            "1) 내 권한 조회",
            "먼저 `내 권한 조회`와 `토큰 정책 조회`를 눌러 현재 role, permissions, site_scope와 토큰 만료/회전 정책을 확인합니다.",
        ),
        (
            "2) 사용자 목록 확인",
            "`사용자 조회`로 대상을 찾고, 목록의 선택 기능으로 아래 수정 폼과 토큰 폼에 연동합니다.",
        ),
        (
            "3) 사용자 생성 또는 수정",
            "신규 계정은 `사용자 생성`, 기존 계정 변경은 `사용자 수정`, 비밀번호만 바꾸면 `비밀번호 변경`, 종료 대상은 `비활성화`를 우선 사용합니다.",
        ),
        (
            "4) 토큰 처리",
            "`토큰 조회` 후 `토큰 발급`, `토큰 회전`, `토큰 폐기`를 실행합니다. label과 site_scope를 용도별로 분리하는 편이 좋습니다.",
        ),
        (
            "5) 감사 로그 검증",
            "변경 직후 `감사 로그 조회`를 실행해 `admin_user_*`, `admin_token_*` action과 detail JSON이 맞는지 확인합니다.",
        ),
    ]
    button_rows = [
        ("내 권한 조회", "현재 로그인 사용자, role, permissions, site_scope 확인"),
        ("토큰 정책 조회", "TTL, rotate, idle, 활성 토큰 수 제한 확인"),
        ("사용자 조회", "role/active/search 기준 사용자 목록 조회"),
        ("사용자 생성", "새 사용자 계정 생성"),
        ("사용자 수정", "표시명, 역할, 권한, site_scope, 활성 상태 수정"),
        ("비밀번호 변경", "선택한 사용자 비밀번호만 변경"),
        ("비활성화", "삭제 전 우선 적용하는 계정 중지 조치"),
        ("사용자 삭제", "정말 제거가 필요할 때만 사용"),
        ("토큰 조회", "사용자별 관리자 토큰 목록 조회"),
        ("토큰 발급", "새 토큰 1회 발급"),
        ("토큰 회전", "기존 토큰 비활성화 후 새 토큰 발급"),
        ("토큰 폐기", "선택한 토큰 즉시 비활성화"),
        ("감사 로그 조회", "action/actor 기준 변경 이력 조회"),
    ]
    playbook_rows = [
        (
            "신규 운영자 등록",
            "내 권한 조회 -> 사용자 생성 -> 사용자 조회 확인 -> 토큰 발급 -> 감사 로그 조회",
        ),
        (
            "운영자 권한 변경",
            "사용자 조회 -> 사용자 선택 -> 사용자 수정 -> 필요 시 비밀번호 변경 -> 감사 로그 조회",
        ),
        (
            "퇴사/종료 처리",
            "사용자 조회 -> 사용자 선택 -> 비활성화 -> 필요 시 토큰 폐기 -> 감사 로그 조회",
        ),
        (
            "토큰 분실 신고",
            "토큰 조회 -> 토큰 선택 -> 토큰 회전 -> 새 토큰 안전 전달 -> 감사 로그 조회",
        ),
    ]
    failure_rows = [
        ("User management requires owner or manager role", "현재 계정은 IAM 사용자 관리 권한이 없습니다."),
        ("Manager cannot manage owner accounts", "manager는 owner 계정을 수정하거나 삭제할 수 없습니다."),
        ("Manager cannot assign owner role", "owner 승격은 owner가 직접 처리해야 합니다."),
        ("At least one active owner must remain", "마지막 활성 owner를 비활성화/삭제하려는 상태입니다."),
        ("Cannot revoke token of current admin user", "현재 로그인 중인 자기 토큰은 폐기 대상이 아닙니다."),
        ("Inactive user cannot rotate token", "먼저 사용자 활성 상태를 확인해야 합니다."),
    ]

    constraint_html = "".join(
        f"<tr><th>{html.escape(title)}</th><td>{html.escape(body)}</td></tr>"
        for title, body in constraint_rows
    )
    step_html = "".join(
        f"""
        <article class="card step-card">
          <h3>{html.escape(title)}</h3>
          <p>{html.escape(body)}</p>
        </article>
        """
        for title, body in step_cards
    )
    button_html = "".join(
        f"<tr><th>{html.escape(title)}</th><td>{html.escape(body)}</td></tr>"
        for title, body in button_rows
    )
    playbook_html = "".join(
        f"<tr><th>{html.escape(title)}</th><td>{html.escape(body)}</td></tr>"
        for title, body in playbook_rows
    )
    failure_html = "".join(
        f"<tr><th>{html.escape(title)}</th><td>{html.escape(body)}</td></tr>"
        for title, body in failure_rows
    )

    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KA Facility OS - IAM 탭 사용자 매뉴얼</title>
  <style>
    :root {{
      --ink: #10213a;
      --muted: #4d6381;
      --line: #d8e3f0;
      --card: #ffffff;
      --bg: #f3f7ff;
      --brand: #0c6a55;
      --accent: #c9551b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(860px 360px at 0% -20%, #dff5ff 0%, transparent 58%),
        radial-gradient(760px 340px at 100% -20%, #ffeddc 0%, transparent 58%),
        var(--bg);
    }}
    .wrap {{ max-width: 1120px; margin: 0 auto; padding: 18px 14px 48px; }}
    .hero {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(145deg, #ffffff 0%, #eef8f5 52%, #fff6eb 100%);
      box-shadow: 0 12px 28px rgba(14, 38, 70, 0.08);
      padding: 16px;
    }}
    .hero h1 {{ margin: 0; font-size: 26px; }}
    .hero p {{ margin: 8px 0 0; color: var(--muted); font-size: 14px; line-height: 1.6; }}
    .hero-links {{
      margin-top: 12px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .hero-links a {{
      text-decoration: none;
      border: 1px solid #b7cde7;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
      font-weight: 800;
      color: #1f4e7d;
      background: #f3f8ff;
    }}
    .grid {{
      margin-top: 14px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      align-items: start;
    }}
    .card {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--card);
      padding: 14px;
    }}
    .card h2 {{
      margin: 0 0 10px;
      font-size: 18px;
      border-left: 4px solid var(--accent);
      padding-left: 8px;
    }}
    .card h3 {{
      margin: 0 0 8px;
      font-size: 15px;
      color: var(--brand);
    }}
    .card p, .card li {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }}
    .step-grid {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 10px;
    }}
    .step-card {{
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }}
    .table th, .table td {{
      border-bottom: 1px solid #e8eff8;
      text-align: left;
      padding: 8px;
      vertical-align: top;
      word-break: break-word;
    }}
    .table th {{
      background: #f6f9ff;
      color: #24486d;
      width: 34%;
    }}
    .callout {{
      margin-top: 10px;
      border: 1px solid #cce0cf;
      border-radius: 12px;
      background: #eefaf4;
      padding: 10px 12px;
      color: #245345;
      font-size: 13px;
      line-height: 1.6;
    }}
    code {{
      font-family: "Consolas", "D2Coding", "IBM Plex Mono", monospace;
      font-size: 12px;
      background: #f3f7ff;
      border: 1px solid #d7e3f1;
      border-radius: 6px;
      padding: 1px 5px;
      color: #1e446e;
    }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .hero h1 {{ font-size: 22px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <h1>IAM 탭 사용자 매뉴얼</h1>
      <p>서비스: {html.escape(service_info.get("service", "ka-facility-os"))} | <code>/?tab=iam</code> 화면에서 owner/manager가 권한 확인, 사용자 관리, 토큰 처리, 감사 검증을 한 흐름으로 수행할 수 있도록 정리한 운영 가이드입니다.</p>
      <div class="hero-links">
        <a href="/?tab=iam">IAM 탭 열기</a>
        <a href="/web/console/guide">운영 콘솔 가이드</a>
        <a href="/api/service-info">서비스 정보 API</a>
        <a href="/web/tutorial-simulator">튜토리얼</a>
      </div>
    </header>

    <section class="grid">
      <article class="card">
        <h2>먼저 알아둘 제약</h2>
        <table class="table">
          <tbody>
            {constraint_html}
          </tbody>
        </table>
        <div class="callout">
          안전한 운영 순서는 항상 <code>내 권한 조회 -> 사용자 변경 -> 토큰 처리 -> 감사 로그 조회</code>입니다.
        </div>
      </article>

      <article class="card">
        <h2>권장 운영 순서</h2>
        <div class="step-grid">
          {step_html}
        </div>
      </article>

      <article class="card">
        <h2>버튼별 의미</h2>
        <table class="table">
          <tbody>
            {button_html}
          </tbody>
        </table>
      </article>

      <article class="card">
        <h2>실무 플레이북</h2>
        <table class="table">
          <tbody>
            {playbook_html}
          </tbody>
        </table>
      </article>

      <article class="card">
        <h2>자주 보는 오류</h2>
        <table class="table">
          <tbody>
            {failure_html}
          </tbody>
        </table>
      </article>
    </section>
  </div>
</body>
</html>
"""
