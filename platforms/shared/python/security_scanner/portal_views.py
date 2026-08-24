from __future__ import annotations

import html
import json


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def script_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def page(title: str, body: str, *, admin: bool = False) -> str:
    admin_link = "<a data-nav='admin' href='/koda/admin/subjects'><span>⚙</span>관리자 설정</a>" if admin else ""
    return f"""<!doctype html><html lang='ko'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'><link rel='icon' href='/koda/assets/KODA.ico'><title>{esc(title)} · KODA</title>
<style>
:root{{--nav:#081b31;--nav2:#123b5d;--bg:#f3f6fa;--surface:#fff;--surface-soft:#f7fafc;--ink:#14263d;--muted:#687a90;--line:#dbe4ed;--line-strong:#c6d2df;--teal:#008f83;--teal-dark:#00766d;--teal2:#e8f7f4;--red:#c9362b;--orange:#c85b00;--yellow:#9b7300;--blue:#276fbd;--green:#197a3a;--radius-sm:8px;--radius-md:12px;--shadow-sm:0 2px 8px rgba(8,27,49,.05);--shadow-md:0 10px 30px rgba(8,27,49,.08)}}
*{{box-sizing:border-box}}html,body{{margin:0;min-height:100%;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans KR",sans-serif;-webkit-font-smoothing:antialiased}}body{{letter-spacing:-.01em}}button,input,select,textarea{{font:inherit}}a{{color:inherit}}
.sidebar{{position:fixed;inset:0 auto 0 0;width:240px;background:var(--nav);color:#dce8f3;display:flex;flex-direction:column;z-index:20;box-shadow:8px 0 24px rgba(8,27,49,.08)}}
.brand{{height:80px;display:flex;align-items:center;gap:12px;padding:0 22px;color:#fff;text-decoration:none;font-size:22px;font-weight:800;letter-spacing:.02em;border-bottom:1px solid rgba(255,255,255,.1)}}.brand img{{width:34px;height:34px;object-fit:contain}}
.side-nav{{display:flex;flex-direction:column;padding:18px 12px;gap:6px}}.side-nav a{{display:flex;align-items:center;gap:12px;min-height:44px;color:#cbd9e6;text-decoration:none;padding:10px 14px;border-radius:var(--radius-sm);font-weight:650;transition:background .18s ease,color .18s ease,transform .18s ease}}.side-nav a span{{width:22px;text-align:center;color:#92adc4;font-size:17px}}.side-nav a:hover{{background:rgba(255,255,255,.08);color:#fff}}.side-nav a.active{{background:var(--nav2);color:#fff;box-shadow:inset 3px 0 var(--teal);transform:translateX(2px)}}
.side-bottom{{margin-top:auto;padding:16px 18px 20px;border-top:1px solid rgba(255,255,255,.1)}}.side-bottom button{{width:100%;min-height:44px;background:transparent;color:#fff;border:1px solid rgba(255,255,255,.12);border-radius:var(--radius-sm);text-align:left;padding:10px 13px;cursor:pointer;transition:background .18s ease,border-color .18s ease}}.side-bottom button:hover{{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.24)}}
.workspace{{min-height:100vh;margin-left:240px}}.topbar{{position:sticky;top:0;height:72px;background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 36px;z-index:10;backdrop-filter:blur(12px)}}.topbar strong{{font-size:17px;font-weight:750}}main{{max-width:1440px;margin:0 auto;padding:34px 36px 64px}}h1{{font-size:30px;line-height:1.2;letter-spacing:-.03em;margin:0 0 26px}}h2{{font-size:19px;line-height:1.35;margin:0;font-weight:750}}h3{{font-size:15px;line-height:1.4;margin:0;font-weight:750}}p{{margin:.45rem 0}}.muted{{color:var(--muted)}}.error{{color:var(--red)}}
.panel{{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius-md);box-shadow:var(--shadow-sm);overflow:hidden}}.panel-head{{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:20px 24px;border-bottom:1px solid var(--line);min-height:72px}}.panel-body{{padding:24px}}
.dashboard-top{{display:grid;grid-template-columns:minmax(380px,1.05fr) minmax(520px,1.95fr);gap:20px;margin-bottom:20px}}.start-panel{{display:flex;align-items:center;gap:24px;padding:28px}}.upload-mark{{width:112px;height:112px;flex:0 0 auto;border:1px dashed var(--teal);border-radius:var(--radius-md);display:grid;place-items:center;color:var(--teal);font-size:44px;background:var(--teal2)}}.start-copy{{flex:1;min-width:0}}.start-copy h2{{font-size:21px;margin-bottom:8px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr)}}.stat{{min-height:128px;padding:24px;border-right:1px solid var(--line);display:flex;flex-direction:column;justify-content:center}}.stat:last-child{{border:0}}.stat small{{color:var(--muted);font-weight:650}}.stat strong{{display:block;font-size:30px;line-height:1;margin-top:14px;letter-spacing:-.02em}}.stat.danger strong{{color:var(--red)}}.stat.high strong{{color:var(--orange)}}
.button,button{{min-height:42px;border:1px solid var(--line-strong);border-radius:var(--radius-sm);background:#fff;color:var(--ink);padding:9px 16px;text-decoration:none;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:8px;font-weight:650;line-height:1.2;transition:background .18s ease,border-color .18s ease,color .18s ease,box-shadow .18s ease,transform .18s ease}}.button:hover,button:hover{{border-color:#9eb1c4;background:#f8fafc}}.button:active,button:active{{transform:translateY(1px)}}.button.primary,button.primary{{background:var(--teal);border-color:var(--teal);color:#fff;font-weight:750;box-shadow:0 4px 10px rgba(0,143,131,.18)}}.button.primary:hover,button.primary:hover{{background:var(--teal-dark);border-color:var(--teal-dark)}}.button:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{{outline:3px solid rgba(0,143,131,.22);outline-offset:2px}}
.toolbar{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}.toolbar-between{{justify-content:space-between}}.toolbar-spaced{{margin-bottom:20px}}.toolbar-submit{{margin-top:18px}}input,select,textarea{{min-height:42px;border:1px solid var(--line-strong);border-radius:var(--radius-sm);background:#fff;color:var(--ink);padding:9px 12px;transition:border-color .18s ease,box-shadow .18s ease}}input:hover,select:hover,textarea:hover{{border-color:#9eb1c4}}input[type=search]{{min-width:260px}}input[type=checkbox]{{min-height:auto;width:18px;height:18px;accent-color:var(--teal)}}label{{display:block;font-weight:650}}label input,label select,label textarea{{display:block;width:100%;margin-top:7px}}.toolbar label{{display:flex;align-items:center;gap:8px;white-space:nowrap;font-size:13px}}.toolbar label input,.toolbar label select,.toolbar label textarea{{display:inline-block;width:auto;min-width:180px;margin-top:0}}textarea{{resize:vertical}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:separate;border-spacing:0}}th,td{{padding:14px 16px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap;line-height:1.45}}th{{background:var(--surface-soft);color:#526277;font-size:12px;font-weight:750;letter-spacing:.01em}}tbody tr:last-child td,tbody tr:last-child th{{border-bottom:0}}tbody tr:hover{{background:#f5fbfa}}td.wrap{{white-space:normal;min-width:220px}}code,.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;color:#526277}}.role-head{{text-align:center;min-width:145px}}.role-head strong,.role-head small,.role-head code{{display:block}}.role-head small{{white-space:normal;font-weight:400;margin-top:4px}}.permission-check{{text-align:center;vertical-align:middle}}
.status{{display:inline-flex;align-items:center;gap:7px;min-height:24px;font-weight:650}}.status:before{{content:"";width:8px;height:8px;flex:0 0 auto;border-radius:50%;background:#7b8794}}.status-completed:before{{background:var(--green)}}.status-running:before,.status-queued:before,.status-preparing:before,.status-scanning:before,.status-finalizing:before{{background:var(--blue)}}.status-failed:before,.status-cancelled:before{{background:var(--red)}}.status-warning:before,.status-cancelling:before{{background:var(--orange)}}.status-skipped:before{{background:var(--muted)}}
.sev{{font-weight:750}}.sev-critical{{color:var(--red)}}.sev-high{{color:var(--orange)}}.sev-medium{{color:var(--yellow)}}.sev-low{{color:var(--blue)}}
.form-grid{{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:24px}}.steps{{padding:28px}}.step{{padding:0 0 28px;margin-bottom:28px;border-bottom:1px solid var(--line)}}.step:last-child{{border-bottom:0;margin-bottom:0;padding-bottom:0}}.step h2{{margin-bottom:14px}}.drop-zone{{border:1px dashed var(--teal);border-radius:var(--radius-md);background:#fbfefe;padding:28px;text-align:center}}.drop-zone input{{max-width:100%}}.option-row{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}.choice{{border:1px solid var(--line);border-radius:var(--radius-sm);padding:15px;transition:border-color .18s ease,background .18s ease}}.choice:has(input:checked){{border-color:var(--teal);background:var(--teal2)}}.summary-list{{margin:0;padding:0;list-style:none}}.summary-list li{{padding:15px 0;border-bottom:1px solid var(--line)}}.summary-list li:last-child{{border:0}}.summary-list span{{display:block;color:var(--muted);font-size:12px;font-weight:650}}.summary-list strong{{display:block;margin-top:4px;overflow-wrap:anywhere}}
.project-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}}.project-card{{padding:20px;text-decoration:none;transition:border-color .18s ease,box-shadow .18s ease,transform .18s ease}}.project-card h2{{margin-bottom:7px}}.project-card:hover{{border-color:var(--teal);box-shadow:0 8px 22px rgba(0,143,131,.12);transform:translateY(-2px)}}
.result-layout{{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(340px,.75fr);gap:20px}}.summary-strip{{display:grid;grid-template-columns:repeat(5,1fr);margin-bottom:20px}}.summary-strip div{{padding:18px 20px;border-right:1px solid var(--line)}}.summary-strip div:last-child{{border:0}}.summary-strip strong{{display:block;font-size:25px;line-height:1.1;margin-top:5px}}.finding-row{{cursor:pointer}}.finding-row.selected{{background:var(--teal2)}}.inspector{{position:sticky;top:92px;align-self:start}}.inspector pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0c1d2e;color:#e7f0f7;padding:16px;border-radius:var(--radius-sm);max-height:260px;overflow:auto}}.detail-section{{padding:18px 0;border-bottom:1px solid var(--line)}}
.tabs{{display:flex;gap:26px;border-bottom:1px solid var(--line);padding:0 24px;overflow:auto}}.tabs button{{min-height:52px;border:0;border-radius:0;padding:14px 2px;background:transparent;white-space:nowrap;color:var(--muted)}}.tabs button:hover{{background:transparent;color:var(--ink);border-color:transparent}}.tabs button.active{{color:var(--teal);box-shadow:inset 0 -3px var(--teal)}}
.progress{{height:10px;background:#e8edf2;border-radius:999px;overflow:hidden}}.progress span{{display:block;height:100%;background:var(--teal);transition:width .25s}}.progress-panel{{padding:18px 20px;margin-bottom:20px}}.stage-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}}.stage-card{{padding:20px}}.stage-card strong{{display:block;font-size:18px;margin:8px 0}}
.admin-subnav{{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}}details{{margin-top:18px;border:1px solid var(--line);border-radius:var(--radius-sm);padding:0 16px;background:var(--surface)}}details summary{{cursor:pointer;padding:14px 0;font-weight:700}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.empty{{padding:48px;text-align:center;color:var(--muted)}}
@media(max-width:1100px){{.dashboard-top,.form-grid,.result-layout{{grid-template-columns:1fr}}.inspector{{position:static}}}}
@media(max-width:1000px){{.sidebar{{position:static;width:auto;min-height:auto}}.brand{{height:64px}}.side-nav{{flex-direction:row;overflow:auto}}.side-nav a{{white-space:nowrap}}.side-bottom{{display:none}}.workspace{{margin-left:0}}main{{padding:28px 24px 48px}}.topbar{{height:64px;padding:0 24px}}.stats{{grid-template-columns:repeat(2,1fr)}}}}
@media(max-width:700px){{main{{padding:24px 16px 40px}}h1{{font-size:26px;margin-bottom:20px}}.panel-head{{align-items:flex-start;flex-direction:column;padding:18px}}.panel-head>.toolbar{{width:100%}}.toolbar label{{width:100%}}.toolbar label input,.toolbar label select,.toolbar label textarea{{flex:1;min-width:0}}input[type=search]{{min-width:0;width:100%}}.start-panel{{align-items:flex-start;flex-direction:column;padding:22px}}.upload-mark{{width:72px;height:72px;font-size:30px}}.summary-strip{{grid-template-columns:repeat(2,1fr)}}.summary-strip div:nth-child(2n){{border-right:0}}.summary-strip div:nth-last-child(-n+1){{border-top:1px solid var(--line)}}.option-row{{grid-template-columns:1fr}}.steps,.panel-body{{padding:20px}}.table-wrap{{margin:0 -1px}}th,td{{padding:12px}}}}
</style><script>const json=async(url,options={{}})=>{{const r=await fetch(url,{{credentials:'include',...options,headers:{{'Content-Type':'application/json',...(options.headers||{{}})}}}});if(!r.ok)throw new Error((await r.json().catch(()=>({{}}))).detail||`HTTP ${{r.status}}`);return r.status===204?null:r.json()}};</script></head><body>
<aside class='sidebar'><a class='brand' href='/koda/'><img src='/koda/assets/KODA.ico' alt=''><span>KODA</span></a><nav class='side-nav'>
<a data-nav='dashboard' href='/koda/'><span>▦</span>대시보드</a><a data-nav='library' href='/koda/scans/library'><span>◈</span>라이브러리 취약점</a><a data-nav='source' href='/koda/scans/source'><span>⌘</span>소스코드 취약점</a><a data-nav='runs' href='/koda/runs'><span>☷</span>점검 결과</a><a data-nav='compare' href='/koda/compare'><span>⇄</span>비교</a><a data-nav='projects' href='/koda/projects'><span>□</span>프로젝트</a>{admin_link}</nav>
<div class='side-bottom'><button id='logout' type='button'>↪ &nbsp;로그아웃</button></div></aside><div class='workspace'><header class='topbar'><strong>{esc(title)}</strong></header><main><h1>{esc(title)}</h1>{body}</main></div>
<script>
const path=location.pathname;let key=path==='/koda/'||path==='/koda'?'dashboard':path.startsWith('/koda/scans/library')?'library':path.startsWith('/koda/scans/source')?'source':path.startsWith('/koda/runs')?'runs':path.startsWith('/koda/compare')?'compare':path.startsWith('/koda/projects')?'projects':path.startsWith('/koda/admin')?'admin':'';document.querySelector(`[data-nav="${{key}}"]`)?.classList.add('active');
document.querySelector('#logout')?.addEventListener('click',async()=>{{try{{const r=await fetch('/api/v1/auth/logout-current',{{method:'POST',credentials:'include',headers:{{'X-KODA-Logout':'current-browser'}}}});if(!r.ok)throw new Error(`HTTP ${{r.status}}`);location='/koda/login'}}catch(e){{alert('로그아웃하지 못했습니다: '+e.message)}}}});
</script></body></html>"""


def login_page(next_path: str = "/koda/") -> str:
    return f"""<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><link rel='icon' href='/koda/assets/KODA.ico'><title>KODA 로그인</title>
<style>:root{{--nav:#081b31;--bg:#f3f6fa;--surface:#fff;--ink:#14263d;--muted:#687a90;--line:#dbe4ed;--line-strong:#c6d2df;--teal:#008f83;--teal-dark:#00766d;--red:#c9362b;--radius:14px;--shadow:0 18px 44px rgba(8,27,49,.12)}}*{{box-sizing:border-box}}body{{font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans KR",sans-serif;background:linear-gradient(145deg,#edf4f8 0%,var(--bg) 55%,#e8f4f2 100%);margin:0;min-height:100vh;color:var(--ink);display:grid;place-items:center;padding:24px;-webkit-font-smoothing:antialiased}}main{{width:min(100%,440px);background:var(--surface);padding:40px;border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}}.brand{{display:flex;align-items:center;gap:13px;margin-bottom:26px}}.brand img{{width:46px;height:46px;object-fit:contain}}h1{{margin:0;font-size:28px;letter-spacing:-.03em}}p{{margin:.5rem 0}}label{{display:block;margin:18px 0;font-weight:650}}input:not([type=checkbox]),button{{width:100%;min-height:44px;padding:10px 12px;box-sizing:border-box;border:1px solid var(--line-strong);border-radius:8px;font:inherit}}input:not([type=checkbox]){{display:block;margin-top:8px}}input:focus-visible{{outline:3px solid rgba(0,143,131,.22);outline-offset:2px;border-color:var(--teal)}}input[type=checkbox]{{width:18px;height:18px;accent-color:var(--teal);vertical-align:-4px;margin-right:6px}}button{{background:var(--teal);color:white;border-color:var(--teal);font-weight:750;cursor:pointer;transition:background .18s ease,transform .18s ease}}button:hover{{background:var(--teal-dark);border-color:var(--teal-dark)}}button:active{{transform:translateY(1px)}}button:focus-visible{{outline:3px solid rgba(0,143,131,.22);outline-offset:2px}}button.secondary{{margin-top:10px;background:white;color:var(--ink);border-color:var(--line-strong)}}button.secondary:hover{{background:#f7fafc;border-color:#9eb1c4}}.error{{color:var(--red)}}.notice{{color:#006b63}}[hidden]{{display:none!important}}@media(max-width:480px){{body{{padding:16px}}main{{padding:28px 22px}}}}</style></head><body><main><div class='brand'><img src='/koda/assets/KODA.ico' alt=''><h1>KODA</h1></div><p>공유 계정으로 로그인합니다.</p>
<form id='login'><label>계정<input name='username' autocomplete='username' required></label><label>비밀번호<input name='password' type='password' autocomplete='current-password' required></label><label><input name='useLdap' type='checkbox'> LDAP 계정</label><button>로그인</button><button id='show-register' class='secondary' type='button'>회원가입</button><p id='message' class='error' role='alert'></p></form>
<form id='register' hidden><label>계정<input name='username' autocomplete='username' pattern='[A-Za-z0-9][A-Za-z0-9._-]{{2,63}}' required></label><label>비밀번호<input name='password' type='password' autocomplete='new-password' minlength='12' required></label><label>비밀번호 확인<input name='passwordConfirm' type='password' autocomplete='new-password' minlength='12' required></label><button>가입 신청</button><button id='show-login' class='secondary' type='button'>로그인으로 돌아가기</button><p id='register-message' class='error' role='alert'></p></form>
<script>
const login=document.querySelector('#login'),register=document.querySelector('#register'),message=document.querySelector('#message');
document.querySelector('#show-register').onclick=()=>{{login.hidden=true;register.hidden=false}};document.querySelector('#show-login').onclick=()=>{{register.hidden=true;login.hidden=false}};
login.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget);message.className='error';message.textContent='';const r=await fetch('/api/v1/auth/login',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:f.get('username'),password:f.get('password'),useLdap:f.get('useLdap')==='on'}})}});if(r.ok)location={script_json(next_path)};else{{const x=await r.json().catch(()=>({{}}));message.textContent=x.detail||'로그인하지 못했습니다.'}}}});
register.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget),m=document.querySelector('#register-message');m.textContent='';const r=await fetch('/api/v1/auth/register',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:f.get('username'),password:f.get('password'),passwordConfirm:f.get('passwordConfirm')}})}}),x=await r.json().catch(()=>({{}}));if(r.ok){{register.hidden=true;login.hidden=false;message.className='notice';message.textContent=x.detail}}else m.textContent=x.detail||'가입 신청을 처리하지 못했습니다.'}});
</script></main></body></html>"""


def _severity_counts(runs: list[dict]) -> dict[str, int]:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for run in runs:
        result = run.get("result") if isinstance(run.get("result"), dict) else {}
        for finding in result.get("findings", []):
            key = str(finding.get("severity", "info")).lower()
            counts[key if key in counts else "info"] += 1
    return counts


def _finding_group(category: object) -> str:
    category = str(category).lower()
    if category == "dependencies":
        return "library"
    if category in {"quality", "screen_quality"}:
        return "quality"
    return "source"


_CATEGORY_LABELS = {
    "dependencies": "라이브러리",
    "code": "소스코드",
    "secrets": "비밀정보",
    "configuration": "보안설정",
    "prevention": "예방통제",
    "screen_quality": "화면품질",
    "quality": "품질",
    "host": "호스트",
    "security": "소스코드",
}

ROLE_LABELS = {
    "admin": "프로젝트 관리자",
    "manager": "점검 운영자",
    "analyst": "분석 담당자",
    "uploader": "입력·점검 담당자",
    "viewer": "조회 전용",
}

ROLE_DESCRIPTIONS = {
    "admin": "프로젝트·입력·점검을 모두 관리합니다.",
    "manager": "입력을 등록하고 점검을 운영합니다.",
    "analyst": "점검을 실행하고 결과를 조회합니다.",
    "uploader": "입력을 등록하고 점검을 실행합니다.",
    "viewer": "프로젝트와 점검 결과만 조회합니다.",
}

PERMISSION_METADATA = {
    "project.view": ("프로젝트·결과", "조회", "프로젝트 목록과 입력·회차 결과를 조회합니다."),
    "project.manage": ("프로젝트", "관리", "프로젝트를 생성하고 기본 정보를 관리합니다."),
    "input.manage": ("입력 파일", "등록", "SBOM·소스코드 입력 파일을 등록합니다."),
    "scan.create": ("보안 점검", "실행", "라이브러리·소스코드 점검을 실행하고 진행 중인 점검을 취소합니다."),
}

_SCAN_SCOPE_LABELS = {
    "all": "전체 점검",
    "library": "라이브러리 취약점",
    "source": "소스코드 취약점",
}


def _scan_scope(run: dict) -> str:
    snapshot = run.get("snapshot") if isinstance(run.get("snapshot"), dict) else {}
    return str(run.get("scan_scope") or snapshot.get("scan_scope") or "all")


def dashboard(identity, projects: list[dict], project_runs: list[tuple[dict, list[dict]]], *, admin: bool) -> str:
    all_runs = [(project, run) for project, runs in project_runs for run in runs]
    all_runs.sort(key=lambda item: item[1].get("created_at", ""), reverse=True)
    completed = [run for _, run in all_runs if run.get("status") == "completed"]
    counts = _severity_counts(completed)
    rows = "".join(
        f"<tr><td><a href='/koda/runs/{esc(run['run_id'])}'>#{run['round_number']}</a></td><td>{esc(project['name'])}</td><td>{esc(run.get('standard',''))} / {esc(run.get('standard_category',''))}</td><td><span class='status status-{esc(run.get('status',''))}'>{esc(run.get('status',''))}</span></td><td class='sev sev-critical'>{_severity_counts([run])['critical']}</td><td class='sev sev-high'>{_severity_counts([run])['high']}</td><td>{esc(run.get('created_at',''))}</td></tr>"
        for project, run in all_runs[:8]
    ) or "<tr><td colspan='7' class='empty'>아직 점검 결과가 없습니다.</td></tr>"
    body = f"""
<div class='dashboard-top'><section class='panel start-panel'><div class='upload-mark'>↑</div><div class='start-copy'><h2>보안취약점 점검</h2><p class='muted'>점검 유형을 선택하면 라이브러리와 소스코드 결과를 별도 회차로 관리합니다.</p><p class='toolbar'><a class='button primary' href='/koda/scans/library'>라이브러리 점검</a><a class='button' href='/koda/scans/source'>소스코드 점검</a></p></div></section>
<section class='panel stats'><div class='stat'><small>전체 점검</small><strong>{len(all_runs)}</strong></div><div class='stat'><small>완료</small><strong>{len(completed)}</strong></div><div class='stat danger'><small>심각</small><strong>{counts['critical']}</strong></div><div class='stat high'><small>높음</small><strong>{counts['high']}</strong></div></section></div>
<section class='panel'><div class='panel-head'><div><h2>최근 점검 결과</h2><p class='muted'>{esc(identity.display)} 계정이 접근할 수 있는 프로젝트 기준</p></div><div class='toolbar'><input id='recent-search' type='search' placeholder='프로젝트, 기준 검색'><a class='button' href='/koda/runs'>전체 결과</a></div></div><div class='table-wrap'><table id='recent-table'><thead><tr><th>회차</th><th>프로젝트</th><th>점검 기준</th><th>상태</th><th>심각</th><th>높음</th><th>실행일</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<script>document.querySelector('#recent-search')?.addEventListener('input',e=>document.querySelectorAll('#recent-table tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(e.target.value.toLowerCase())))</script>"""
    return page("대시보드", body, admin=admin)


def new_scan_page(projects: list[dict], *, admin: bool, scan_scope: str = "all") -> str:
    available = [p for p in projects if p.get("can_scan")]
    project_options = "".join(f"<option value='{esc(p['project_id'])}'>{esc(p['name'])}</option>" for p in available)
    scope_labels = {"all": "새 점검", "library": "라이브러리 보안취약점 점검", "source": "소스코드 보안취약점 점검"}
    scope_categories = {
        "all": ["secrets", "dependencies", "configuration", "code", "prevention"],
        "library": ["dependencies"],
        "source": ["secrets", "configuration", "code", "prevention"],
    }.get(scan_scope, [])
    title = scope_labels.get(scan_scope, scope_labels["all"])
    input_help = "SBOM, manifest, lockfile, JAR/WAR 또는 의존성 파일" if scan_scope == "library" else "소스 폴더·압축파일 또는 소스가 포함된 입력"
    intro = "라이브러리 구성요소와 오프라인 취약점 DB를 점검합니다." if scan_scope == "library" else "코드, 비밀정보, 보안설정, 예방통제를 점검합니다." if scan_scope == "source" else "점검 유형과 검사 기준을 선택합니다."
    body = f"""<div class='form-grid'><section class='panel steps'><div class='step'><h2>1. 프로젝트 선택</h2><p class='muted'>{esc(intro)}</p><select id='project'>{project_options}</select></div>
<div class='step'><h2>2. 입력 등록</h2><div class='drop-zone'><p><strong>{esc(input_help)}</strong></p><input id='file' type='file'><p id='file-note' class='muted'>최대 1 GiB</p><div class='progress' aria-label='업로드 진행률'><span id='upload-progress' style='width:0'></span></div><p id='upload-state' class='muted'></p><button id='upload' type='button'>선택 파일 등록</button></div><label>등록된 입력<select id='input'></select></label><small class='muted'>점검이 끝난 입력은 자동 삭제됩니다. 새 점검은 파일을 다시 등록하세요.</small></div>
<div class='step'><h2>3. 검사 기준 선택</h2><label>검사 기준<select id='standards'></select></label><label>범위(카테고리)<select id='category'></select></label></div>
<div class='step'><h2>4. 점검 실행</h2><p class='muted'>사용자는 검사 기준과 범위만 선택합니다. 세부 규칙 활성화 여부는 관리자가 설정합니다.</p><button id='scan' class='primary' type='button'>▶ {esc(title)} 실행</button></div></section>
<aside class='panel inspector'><div class='panel-head'><h2>실행 전 확인</h2></div><div class='panel-body'><ul class='summary-list'><li><span>점검 유형</span><strong>{esc(title)}</strong></li><li><span>프로젝트</span><strong id='sum-project'>—</strong></li><li><span>입력</span><strong id='sum-input'>—</strong></li><li><span>검사 기준</span><strong id='sum-standard'>—</strong></li><li><span>범위</span><strong id='sum-category'>—</strong></li><li><span>오프라인 취약점 DB</span><strong id='vuln-db'>확인 중…</strong><small id='vuln-db-detail' class='muted'></small></li><li><span>정책</span><strong>관리자 설정 최신 버전</strong></li></ul></div></aside></div>
<script>
const projects={script_json(available)},scope={script_json(scan_scope)},scopeCategories={script_json(scope_categories)},project=document.querySelector('#project'),input=document.querySelector('#input'),standardBox=document.querySelector('#standards'),category=document.querySelector('#category');let standards=[];
function activeProject(){{return projects.find(x=>x.project_id===project.value)}}function renderInputs(){{const p=activeProject();input.innerHTML=(p?.inputs||[]).filter(x=>x.available!==false).map(x=>`<option value="${{x.input_id}}">${{x.name}}</option>`).join('');document.querySelector('#sum-project').textContent=p?.name||'—';syncSummary()}}
function compatibleCategory(x){{return x.supported&&(x.scanner_categories||[]).some(v=>scopeCategories.includes(v))}}function compatibleStandard(x){{return (x.categories||[]).some(compatibleCategory)}}function activeStandard(){{return standards.find(x=>x.id===standardBox.value)}}function renderCategories(){{const s=activeStandard();category.innerHTML=(s?.categories||[]).filter(compatibleCategory).map(x=>`<option value="${{x.id}}">${{x.labels.ko||x.labels.en||x.id}}</option>`).join('');syncSummary()}}
function syncSummary(){{document.querySelector('#sum-input').textContent=input.selectedOptions[0]?.textContent||'입력을 등록하세요';const s=activeStandard();document.querySelector('#sum-standard').textContent=s?.labels.ko||s?.labels.en||'—';document.querySelector('#sum-category').textContent=category.selectedOptions[0]?.textContent||'—'}}
project?.addEventListener('change',renderInputs);input?.addEventListener('change',syncSummary);standardBox?.addEventListener('change',renderCategories);category?.addEventListener('change',syncSummary);
json('/koda/api/v1/standards').then(x=>{{standards=x.filter(compatibleStandard);standardBox.innerHTML=standards.map(v=>`<option value="${{v.id}}">${{v.labels.ko||v.labels.en||v.id}}</option>`).join('');renderCategories()}});
json('/koda/api/v1/vulnerability-db').then(x=>{{document.querySelector('#vuln-db').textContent=x.available?'점검 가능':'점검 불가';document.querySelector('#vuln-db-detail').textContent=[x.version,x.database?.built,x.warning].filter(Boolean).join(' · ')}}).catch(()=>document.querySelector('#vuln-db').textContent='상태 확인 실패');renderInputs();
document.querySelector('#file')?.addEventListener('change',e=>{{const f=e.target.files[0];document.querySelector('#file-note').textContent=f?`${{f.name}} · ${{(f.size/1048576).toFixed(2)}} MiB`:'최대 1 GiB'}});
function uploadInput(url,file){{return new Promise((resolve,reject)=>{{const x=new XMLHttpRequest();x.open('POST',url);x.withCredentials=true;x.setRequestHeader('Content-Type','application/octet-stream');x.upload.onprogress=e=>{{if(e.lengthComputable){{const n=Math.round(e.loaded/e.total*100);document.querySelector('#upload-progress').style.width=n+'%';document.querySelector('#upload-state').textContent=`업로드 중 ${{n}}%`}}}};x.onload=()=>x.status<300?resolve(JSON.parse(x.responseText)):reject(new Error(JSON.parse(x.responseText||'{{}}').detail||`HTTP ${{x.status}}`));x.onerror=()=>reject(new Error('업로드 연결에 실패했습니다.'));x.send(file)}})}}
document.querySelector('#upload')?.addEventListener('click',async()=>{{const f=document.querySelector('#file').files[0],p=activeProject();if(!f||!p)return alert('프로젝트와 파일을 선택하세요.');if(f.size>1024*1024*1024)return alert('파일은 1 GiB 이하여야 합니다.');try{{await uploadInput(`/koda/api/v1/projects/${{p.project_id}}/inputs?name=${{encodeURIComponent(f.name)}}`,f);document.querySelector('#upload-state').textContent='등록 완료';p.inputs=await json(`/koda/api/v1/projects/${{p.project_id}}/inputs`);renderInputs()}}catch(e){{document.querySelector('#upload-state').textContent='등록 실패';alert(e.message)}}}});
document.querySelector('#scan')?.addEventListener('click',async()=>{{const p=activeProject(),s=activeStandard();if(!p||!input.value||!s||!category.value)return alert('프로젝트, 입력, 검사 기준을 확인하세요.');try{{const r=await json('/koda/api/v1/scans',{{method:'POST',body:JSON.stringify({{project_id:p.project_id,input_id:input.value,standard:s.id,standard_category:category.value,scan_scope:scope}})}});location=`/koda/runs/${{r.run_id}}`}}catch(e){{alert(e.message)}}}});
</script>"""
    if available:
        content = body
    elif admin:
        content = "<section class='panel empty'><h2>점검할 프로젝트가 없습니다.</h2><p>먼저 프로젝트를 생성한 뒤 입력 파일을 등록하세요.</p><p><a class='button primary' href='/koda/projects'>프로젝트 생성으로 이동</a></p></section>"
    else:
        content = "<section class='panel empty'><h2>점검 권한이 있는 프로젝트가 없습니다.</h2><p>Tracker 계정 승인만으로는 KODA 프로젝트 권한이 부여되지 않습니다.</p><p>KODA 관리자에게 프로젝트 생성 및 <code>scan.create</code> 역할 배정을 요청하세요.</p><p><a class='button' href='/koda/projects'>프로젝트 권한 확인</a></p></section>"
    return page(title, content, admin=admin)


def projects_page(projects: list[dict], *, admin: bool) -> str:
    create = "<form id='create' class='toolbar'><input name='name' placeholder='새 프로젝트 이름' required maxlength='128'><button class='primary'>프로젝트 생성</button></form>" if admin else ""
    if projects:
        cards = "".join(f"<a class='panel project-card' href='/koda/projects/{esc(p['project_id'])}'><h2>{esc(p['name'])}</h2><p class='muted'>입력 {len(p.get('inputs', []))}개 · 점검 {len(p.get('runs', []))}회</p></a>" for p in projects)
    elif admin:
        cards = "<div class='panel empty'>프로젝트를 생성하면 새 점검과 회차별 결과를 관리할 수 있습니다.</div>"
    else:
        cards = "<div class='panel empty'>접근 가능한 프로젝트가 없습니다.<br>Tracker 승인 후에도 KODA 관리자가 프로젝트 역할을 배정해야 합니다.</div>"
    script = "<script>document.querySelector('#create')?.addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await json('/koda/api/v1/projects',{method:'POST',body:JSON.stringify({name:f.get('name')})});location.reload()}catch(x){alert(x.message)}})</script>" if admin else ""
    return page("프로젝트", f"<section class='panel'><div class='panel-head'><div><h2>점검 대상 관리</h2><p class='muted'>입력 파일과 회차별 결과를 프로젝트 단위로 보관합니다.</p></div>{create}</div><div class='panel-body project-grid'>{cards}</div></section>{script}", admin=admin)


def project_page(project: dict, inputs: list[dict], runs: list[dict], *, can_upload: bool, can_scan: bool, admin: bool) -> str:
    input_rows = "".join(f"<tr><td>{esc(i['name'])}</td><td>{esc(i['created_at'])}</td><td>{'원본 보관 중' if i.get('available', True) else '원본 삭제됨 · 재업로드 필요'}</td></tr>" for i in inputs) or "<tr><td colspan='3' class='empty'>등록된 입력이 없습니다.</td></tr>"
    run_rows = "".join(f"<tr><td><a href='/koda/runs/{esc(r['run_id'])}'>#{r['round_number']}</a></td><td>{esc(_SCAN_SCOPE_LABELS.get(_scan_scope(r), _scan_scope(r)))}</td><td>{esc(r['standard'])} / {esc(r['standard_category'])}</td><td><span class='status status-{esc(r['status'])}'>{esc(r['status'])}</span></td><td>{esc(r['created_at'])}</td></tr>" for r in runs) or "<tr><td colspan='5' class='empty'>점검 회차가 없습니다.</td></tr>"
    action = "<a class='button primary' href='/koda/scans/library'>라이브러리 점검</a><a class='button' href='/koda/scans/source'>소스코드 점검</a>" if can_scan else ""
    return page(str(project['name']), f"<div class='toolbar toolbar-spaced'>{action}</div><section class='panel'><div class='panel-head'><h2>등록된 입력</h2><p class='muted'>점검 완료 후 원본 파일은 삭제되고 결과 회차만 보관됩니다.</p></div><div class='table-wrap'><table><tr><th>이름</th><th>등록일</th><th>보관 상태</th></tr>{input_rows}</table></div></section><section class='panel'><div class='panel-head'><h2>점검 회차</h2></div><div class='table-wrap'><table><tr><th>회차</th><th>점검 유형</th><th>기준</th><th>상태</th><th>요청일</th></tr>{run_rows}</table></div></section>", admin=admin)


def runs_page(projects: list[tuple[dict, list[dict]]], *, admin: bool) -> str:
    rows = "".join(
        f"<tr><td><a href='/koda/runs/{esc(run['run_id'])}'>#{run['round_number']}</a></td><td>{esc(project['name'])}</td><td>{esc(_SCAN_SCOPE_LABELS.get(_scan_scope(run), _scan_scope(run)))}</td><td>{esc(run['standard'])} / {esc(run['standard_category'])}</td><td><span class='status status-{esc(run['status'])}'>{esc(run['status'])}</span></td><td>{esc(run['created_at'])}</td></tr>"
        for project, runs in projects for run in runs
    ) or "<tr><td colspan='6' class='empty'>점검 결과가 없습니다.</td></tr>"
    body = f"<section class='panel'><div class='panel-head'><h2>회차별 점검 결과</h2><div class='toolbar'><input id='run-search' type='search' placeholder='프로젝트, 점검 유형, 기준, 상태 검색'><select id='run-status'><option value=''>모든 상태</option><option value='queued'>대기</option><option value='running'>진행 중</option><option value='cancelling'>취소 중</option><option value='completed'>완료</option><option value='failed'>실패</option><option value='cancelled'>취소됨</option></select></div></div><div class='table-wrap'><table id='runs-table'><thead><tr><th>회차</th><th>프로젝트</th><th>점검 유형</th><th>점검 기준</th><th>상태</th><th>실행일</th></tr></thead><tbody>{rows}</tbody></table></div></section><script>function filterRuns(){{const q=document.querySelector('#run-search').value.toLowerCase(),s=document.querySelector('#run-status').value;document.querySelectorAll('#runs-table tbody tr').forEach(r=>r.hidden=(q&&!r.textContent.toLowerCase().includes(q))||(s&&!r.querySelector('.status')?.classList.contains('status-'+s)))}}document.querySelector('#run-search').addEventListener('input',filterRuns);document.querySelector('#run-status').addEventListener('change',filterRuns)</script>"
    return page("점검 결과", body, admin=admin)


def run_page(run: dict, *, admin: bool) -> str:
    result = run.get("result") if isinstance(run.get("result"), dict) else {}
    findings = result.get("findings", []) if isinstance(result.get("findings"), list) else []
    scan_scope = _scan_scope(run)
    scope_label = _SCAN_SCOPE_LABELS.get(scan_scope, scan_scope)
    counts = _severity_counts([run])
    groups = [_finding_group(f.get("category")) for f in findings]
    group_counts = {group: 0 for group in ("library", "source", "quality")}
    for group in groups:
        group_counts[group] += 1
    rows = "".join(
        f"<tr class='finding-row' data-index='{i}' data-group='{groups[i]}'><td class='sev sev-{esc(f.get('severity','info'))}'>{esc(f.get('severity',''))}</td><td><code>{esc(f.get('rule_id',''))}</code></td><td>{esc(_CATEGORY_LABELS.get(str(f.get('category','')).lower(), f.get('category','')))}</td><td>{esc(f.get('path',''))}</td><td>{esc(f.get('line',''))}</td><td class='wrap'>{esc(f.get('title',''))}</td></tr>"
        for i, f in enumerate(findings)
    ) or "<tr><td colspan='6' class='empty'>발견된 항목이 없습니다.</td></tr>"
    filtered_empty = "<tr id='filtered-empty' hidden><td colspan='6' class='empty'>선택한 분류에 발견된 항목이 없습니다.</td></tr>" if findings else ""
    exports = ""
    if run.get("status") == "completed":
        base = f"/koda/api/v1/runs/{esc(run['run_id'])}/report"
        sbom = f"/koda/api/v1/runs/{esc(run['run_id'])}/sbom"
        exports = f"<a class='button primary' href='{base}.html' target='_blank'>보고서 보기</a><a class='button' href='{base}?format=html'>HTML ZIP</a><a class='button' href='{base}?format=pdf'>PDF</a><a class='button' href='{base}?format=xlsx'>Excel</a><a class='button' href='{base}?format=hwpx'>HWPX</a><a class='button' href='{base}?format=json'>JSON</a><a class='button' href='{base}?format=markdown'>Markdown</a><a class='button' href='{sbom}?format=cyclonedx'>CycloneDX 1.6</a><a class='button' href='{sbom}?format=nis-sbom'>국정원 NIS-SBOM 1.0 (CSV)</a>"
    stages = result.get("analysis_stages", {}) if isinstance(result.get("analysis_stages"), dict) else {}
    legacy_stage_note = "<p class='muted'>이전 회차에는 단계별 상태 메타데이터가 없습니다.</p>" if run.get("status") == "completed" and not stages else ""
    stage_cards = []
    for key, label in (("source", "소스코드"), ("library", "라이브러리"), ("quality", "품질")):
        stage = stages.get(key, {})
        stage_status = stage.get("status", "completed" if run.get("status") == "completed" else run.get("status", "queued"))
        detail = ""
        if key == "library" and stage:
            detail = f"<small class='muted'>Grype {esc(stage.get('version') or '확인 불가')} · 조회 {esc(stage.get('queried_components', 0))}개</small><p class='error'>{esc(stage.get('warning') or '')}</p>"
        stage_cards.append(f"<section class='panel stage-card'><span>{label}</span><strong class='status status-{esc(stage_status)}'>{esc(stage_status)}</strong><p>{esc(stage.get('finding_count', 0))}건</p>{detail}</section>")
    terminal = run.get("status") in {"completed", "failed", "cancelled"}
    run_action = "<button id='cancel' type='button'>취소</button>" if not terminal else ""
    body = f"""<div class='toolbar toolbar-between toolbar-spaced'><div><strong>{esc(scope_label)}</strong> · <span id='run-status' class='status status-{esc(run['status'])}'>{esc(run['status'])}</span> · {esc(run['standard'])} / {esc(run['standard_category'])}</div><div class='toolbar'>{run_action}<a class='button' href='/koda/compare?right={esc(run['run_id'])}'>이전 회차와 비교</a><a class='button' href='/koda/scans/library'>라이브러리 점검</a><a class='button' href='/koda/scans/source'>소스코드 점검</a>{exports}</div></div>
<section class='panel progress-panel'><div class='toolbar toolbar-between'><strong id='run-stage'>{esc(run.get('stage', run.get('status', 'queued')))}</strong><span id='run-progress-text'>{esc(run.get('progress', 0))}%</span></div><div class='progress'><span id='run-progress' style='width:{esc(run.get('progress', 0))}%'></span></div></section>
{legacy_stage_note}<div class='stage-grid'>{''.join(stage_cards)}</div>
<section class='panel summary-strip'><div><small>심각</small><strong class='sev-critical'>{counts['critical']}</strong></div><div><small>높음</small><strong class='sev-high'>{counts['high']}</strong></div><div><small>보통</small><strong>{counts['medium']}</strong></div><div><small>낮음</small><strong>{counts['low']}</strong></div><div><small>전체</small><strong>{len(findings)}</strong></div></section>
<div class='result-layout'><section class='panel'><div class='tabs' role='tablist' aria-label='점검 결과 분류'><button class='active' type='button' role='tab' aria-selected='true' data-tab=''>전체 {len(findings)}</button><button type='button' role='tab' aria-selected='false' data-tab='library'>라이브러리 취약점 {group_counts['library']}</button><button type='button' role='tab' aria-selected='false' data-tab='source'>소스코드 취약점 {group_counts['source']}</button><button type='button' role='tab' aria-selected='false' data-tab='quality'>품질 점검 {group_counts['quality']}</button></div><div class='panel-head'><div class='toolbar'><input id='finding-search' type='search' placeholder='제목, 규칙 ID, 파일 검색'><select id='severity'><option value=''>모든 심각도</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div></div><div class='table-wrap'><table id='findings'><thead><tr><th>심각도</th><th>규칙 ID</th><th>구분</th><th>파일</th><th>위치</th><th>제목</th></tr></thead><tbody>{rows}{filtered_empty}</tbody></table></div></section>
<aside class='panel inspector'><div class='panel-head'><h2 id='detail-title'>점검 항목 상세</h2></div><div class='panel-body' id='detail'><p class='muted'>왼쪽 목록에서 항목을 선택하세요.</p></div><div class='panel-body'><h3>실행 정보 (변경 불가)</h3><ul class='summary-list'><li><span>정책 버전</span><strong>{esc(run['policy_version'])}</strong></li><li><span>요청 계정</span><strong class='mono'>{esc(run['snapshot'].get('requested_by',''))}</strong></li><li><span>스캐너 버전</span><strong>{esc(run['snapshot'].get('scanner_version',''))}</strong></li></ul></div></aside></div>
<details><summary>불변 실행 스냅샷</summary><pre>{esc(json.dumps(run['snapshot'], ensure_ascii=False, indent=2))}</pre></details><p class='error'>{esc(run.get('error') or '')}</p>
<script>const runId={script_json(run['run_id'])},terminal={str(terminal).lower()},findings={script_json(findings)},h=v=>String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));let tab='',selectedSeverity='';function show(i){{const f=findings[i];if(!f)return;const sev=['critical','high','medium','low','info'].includes(f.severity)?f.severity:'info';document.querySelectorAll('.finding-row').forEach(x=>x.classList.toggle('selected',x.dataset.index==i));document.querySelector('#detail-title').textContent=f.title||'점검 항목 상세';document.querySelector('#detail').innerHTML=`<div class="detail-section"><span class="sev sev-${{sev}}">${{h(f.severity)}}</span> · <code>${{h(f.rule_id)}}</code><p>${{h(f.description||'설명이 없습니다.')}}</p></div><div class="detail-section"><h3>위치</h3><p><code>${{h(f.path||'—')}}${{f.line?':'+h(f.line):''}}</code></p><pre>${{h(f.evidence||f.target||'표시할 증거가 없습니다.')}}</pre></div><div class="detail-section"><h3>조치 방법</h3><p>${{h(f.recommendation||'권장 조치가 없습니다.')}}</p></div>`}}function filter(){{const q=document.querySelector('#finding-search').value.toLowerCase();let visible=0;document.querySelectorAll('.finding-row').forEach(r=>{{const f=findings[Number(r.dataset.index)];r.hidden=(q&&!r.textContent.toLowerCase().includes(q))||(selectedSeverity&&f.severity!==selectedSeverity)||(tab&&r.dataset.group!==tab);if(!r.hidden)visible++}});const empty=document.querySelector('#filtered-empty');if(empty)empty.hidden=visible>0}}document.querySelectorAll('.finding-row').forEach(r=>r.addEventListener('click',()=>show(r.dataset.index)));document.querySelector('#finding-search').addEventListener('input',filter);document.querySelector('#severity').addEventListener('change',e=>{{selectedSeverity=e.target.value;filter()}});document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>{{document.querySelectorAll('[data-tab]').forEach(x=>{{x.classList.toggle('active',x===b);x.setAttribute('aria-selected',x===b)}});tab=b.dataset.tab;filter()}}));document.querySelector('#cancel')?.addEventListener('click',async()=>{{if(confirm('이 점검을 취소할까요?')){{await json(`/koda/api/v1/runs/${{runId}}/cancel`,{{method:'POST',body:'{{}}'}});location.reload()}}}});if(!terminal)setInterval(async()=>{{try{{const r=await json(`/koda/api/v1/runs/${{runId}}`),status=document.querySelector('#run-status');status.textContent=r.status;status.className='status status-'+r.status;document.querySelector('#run-stage').textContent=r.stage;document.querySelector('#run-progress').style.width=r.progress+'%';document.querySelector('#run-progress-text').textContent=r.progress+'%';if(['completed','failed','cancelled'].includes(r.status))location.reload()}}catch(e){{console.warn(e)}}}},2000);if(findings.length)show(0)</script>"""
    return page(f"{scope_label} 결과 #{run['round_number']}", body, admin=admin)


def admin_page(title: str, body: str) -> str:
    subnav = "<nav class='admin-subnav'><a class='button' href='/koda/admin/subjects'>KODA 접근</a><a class='button' href='/koda/admin/roles'>역할</a><a class='button' href='/koda/admin/rules'>점검 설정</a><a class='button' href='/koda/admin/vulnerability-db'>취약점 DB</a><a class='button' href='/koda/admin/audit'>감사 로그</a></nav>"
    return page(title, subnav + body, admin=True)
