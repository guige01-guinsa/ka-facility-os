"""Lightweight HTML shells for split deployment entrypoints."""

from __future__ import annotations

import html
from typing import Any


def build_split_home_html(
    service_info: dict[str, Any],
    modules_payload: dict[str, Any],
    *,
    badge: str,
    title: str,
    description: str,
    quick_links: list[dict[str, str]] | None = None,
    note: str = "",
) -> str:
    modules = modules_payload.get("modules", [])
    quick_links = quick_links or []

    link_html = "".join(
        f'<a href="{html.escape(str(item.get("href", "#")))}">{html.escape(str(item.get("label", "Open")))}</a>'
        for item in quick_links
    )

    module_cards: list[str] = []
    for item in modules:
        links = "".join(
            f'<a href="{html.escape(str(link.get("href", "#")))}">{html.escape(str(link.get("label", "Open")))}</a>'
            for link in item.get("links", [])
        )
        module_cards.append(
            f"""
            <article class="module-card">
              <div class="module-kicker">{html.escape(str(item.get("name", "")))}</div>
              <h3>{html.escape(str(item.get("name_ko", "")))}</h3>
              <p>{html.escape(str(item.get("description", "")))}</p>
              <p class="hint"><strong>KPI Hint:</strong> {html.escape(str(item.get("kpi_hint", "")))}</p>
              <div class="module-links">{links}</div>
            </article>
            """
        )

    module_cards_html = "".join(module_cards) or '<p class="empty">표시할 모듈이 없습니다.</p>'
    note_html = (
        f'<div class="note">{html.escape(note)}</div>'
        if note.strip()
        else ""
    )
    service_label = html.escape(str(service_info.get("service", "")))
    docs_href = html.escape(str(service_info.get("docs", "/docs")))

    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{service_label}</title>
  <style>
    :root {{
      --ink: #0f223d;
      --muted: #4b6283;
      --line: #d5e1ef;
      --bg: #f3f8ff;
      --card: #ffffff;
      --brand: #0d6a58;
      --accent: #c95b22;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(860px 320px at 8% -20%, #dff7ff 0%, transparent 58%),
        radial-gradient(760px 320px at 95% -20%, #ffedd9 0%, transparent 58%),
        var(--bg);
    }}
    .wrap {{ max-width: 1220px; margin: 0 auto; padding: 18px 14px 44px; }}
    .hero {{
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
      background: linear-gradient(145deg, #ffffff 0%, #eef8f5 54%, #fff4e8 100%);
      box-shadow: 0 12px 28px rgba(12, 34, 64, 0.08);
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border-radius: 999px;
      padding: 6px 12px;
      background: #e7f4ef;
      color: #0a5d4d;
      font-size: 12px;
      font-weight: 900;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    h1 {{ margin: 14px 0 0; font-size: 36px; line-height: 1.08; }}
    .subtitle {{ margin: 10px 0 0; color: var(--muted); font-size: 15px; line-height: 1.7; }}
    .links {{
      margin-top: 14px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .links a, .module-links a, .utility-links a {{
      text-decoration: none;
      border: 1px solid #b8cee8;
      border-radius: 999px;
      padding: 7px 11px;
      font-size: 12px;
      font-weight: 800;
      color: #1f4f7e;
      background: #f4f8ff;
    }}
    .links a:hover, .module-links a:hover, .utility-links a:hover {{
      border-color: #89afd9;
      background: #e8f2ff;
    }}
    .note {{
      margin-top: 12px;
      border: 1px solid #cfe1d6;
      border-radius: 12px;
      background: #eefaf4;
      padding: 10px 12px;
      color: #255446;
      font-size: 13px;
      line-height: 1.6;
    }}
    .utility {{
      margin-top: 16px;
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 12px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--card);
      padding: 14px;
    }}
    .panel h2 {{
      margin: 0 0 8px;
      font-size: 17px;
      border-left: 4px solid var(--accent);
      padding-left: 8px;
    }}
    .panel p {{ margin: 0; color: var(--muted); font-size: 13px; line-height: 1.6; }}
    .utility-links {{
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
    }}
    .module-grid {{
      margin-top: 16px;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }}
    .module-card {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--card);
      padding: 12px;
    }}
    .module-card h3 {{ margin: 4px 0 8px; font-size: 18px; color: var(--brand); }}
    .module-card p {{ margin: 0; color: var(--muted); font-size: 13px; line-height: 1.6; }}
    .module-kicker {{
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.08em;
      color: #29557f;
      text-transform: uppercase;
    }}
    .hint {{ margin-top: 8px; color: #244a74; }}
    .module-links {{
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }}
    .empty {{
      border: 1px dashed #bed0e8;
      border-radius: 12px;
      background: #f8fbff;
      padding: 18px;
      color: var(--muted);
      text-align: center;
    }}
    @media (max-width: 980px) {{
      h1 {{ font-size: 30px; }}
      .utility {{ grid-template-columns: 1fr; }}
      .module-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <span class="badge">{html.escape(badge)}</span>
      <h1>{html.escape(title)}</h1>
      <p class="subtitle">{html.escape(description)}</p>
      <div class="links">
        {link_html}
      </div>
      {note_html}
    </header>

    <section class="utility">
      <article class="panel">
        <h2>서비스 정보</h2>
        <p>현재 분리 엔트리포인트는 필요한 도메인만 올려서 운영면과 기능면을 분리합니다. 자세한 API는 Swagger에서 바로 확인할 수 있습니다.</p>
        <div class="utility-links">
          <a href="/">홈</a>
          <a href="/api/service-info">서비스 정보 JSON</a>
          <a href="/api/public/modules">모듈 목록 JSON</a>
          <a href="{docs_href}">Swagger Docs</a>
        </div>
      </article>
      <article class="panel">
        <h2>운영 메모</h2>
        <p>이 화면은 큰 메인 셸 대신 가벼운 모듈 허브만 렌더링합니다. 현장/관리 사용자는 필요한 모듈로 바로 이동하는 방식으로 쓰는 것이 좋습니다.</p>
      </article>
    </section>

    <section class="module-grid">
      {module_cards_html}
    </section>
  </div>
</body>
</html>
"""
