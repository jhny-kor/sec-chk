from __future__ import annotations

import html
import json


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def script_json(value: object) -> str:
    return json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def page(title: str, body: str, *, admin: bool = False) -> str:
    admin_links = (
        "<a href='/koda/admin/subjects'>계정</a><a href='/koda/admin/roles'>역할</a>"
        "<a href='/koda/admin/rules'>점검 설정</a><a href='/koda/admin/audit'>감사</a>"
        if admin else ""
    )
    return f"""<!doctype html><html lang='ko'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'><title>{esc(title)} · KODA</title>
<style>
:root{{--bg:#f5f7fb;--card:#fff;--ink:#172033;--line:#d8deea;--accent:#3157d5}}*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}}nav{{display:flex;gap:1rem;align-items:center;padding:.9rem 1.5rem;background:#111a2d;color:white;flex-wrap:wrap}}nav a{{color:white;text-decoration:none}}nav .brand{{display:flex;align-items:center;gap:.45rem}}nav button{{margin-left:auto}}main{{max-width:1180px;margin:2rem auto;padding:0 1rem}}section,.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1rem;margin:1rem 0}}table{{width:100%;border-collapse:collapse}}th,td{{padding:.55rem;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}label{{display:block;margin:.6rem 0}}input,select,textarea,button{{font:inherit;padding:.55rem;border:1px solid #aeb8cc;border-radius:6px}}button{{cursor:pointer;background:white}}button.primary{{background:var(--accent);color:white;border-color:var(--accent)}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}}.muted{{color:#647089}}.error{{color:#a41424}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}@media(max-width:700px){{table{{display:block;overflow:auto}}}}
</style><script>const json=async(url,options={{}})=>{{const r=await fetch(url,{{credentials:'include',...options,headers:{{'Content-Type':'application/json',...(options.headers||{{}})}}}});if(!r.ok)throw new Error((await r.json().catch(()=>({{}}))).detail||`HTTP ${{r.status}}`);return r.status===204?null:r.json()}};</script></head><body><nav><a class='brand' href='/koda/'><img src='/koda/assets/KODA.ico' width='28' height='28' alt='KODA'><strong>KODA</strong></a><a href='/koda/'>대시보드</a><a href='/koda/projects'>프로젝트</a><a href='/koda/runs'>분석 회차</a><a href='/koda/compare'>비교</a>{admin_links}<button id='logout' type='button'>로그아웃</button></nav>
<main><h1>{esc(title)}</h1>{body}</main><script>
document.querySelector('#logout')?.addEventListener('click',async()=>{{try{{const r=await fetch('/api/v1/auth/logout-current',{{method:'POST',credentials:'include',headers:{{'X-KODA-Logout':'current-browser'}}}});if(!r.ok)throw new Error(`HTTP ${{r.status}}`);location='/koda/login'}}catch(e){{alert('로그아웃하지 못했습니다: '+e.message)}}}});
</script></body></html>"""


def login_page(next_path: str = "/koda/") -> str:
    return f"""<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>KODA 로그인</title>
<style>body{{font:16px system-ui;background:#f3f6fb;margin:0}}main{{max-width:420px;margin:10vh auto;background:white;padding:2rem;border:1px solid #dce2ed;border-radius:12px}}.brand{{display:flex;align-items:center;gap:.6rem;margin-bottom:1.2rem}}label{{display:block;margin:1rem 0}}input:not([type=checkbox]),button{{width:100%;padding:.7rem;box-sizing:border-box}}.error{{color:#a41424}}</style></head><body><main><div class='brand'><img src='/koda/assets/KODA.ico' width='48' height='48' alt='KODA'><h1>KODA</h1></div><p>공유 계정으로 로그인합니다.</p>
<form id='login'><label>계정<input name='username' autocomplete='username' required></label><label>비밀번호<input name='password' type='password' autocomplete='current-password' required></label><label><input name='useLdap' type='checkbox'> LDAP 계정</label><button>로그인</button><p id='message' class='error' role='alert'></p></form>
<script>document.querySelector('#login').addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget),m=document.querySelector('#message');m.textContent='';const r=await fetch('/api/v1/auth/login',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:f.get('username'),password:f.get('password'),useLdap:f.get('useLdap')==='on'}})}});if(r.ok)location={script_json(next_path)};else{{const x=await r.json().catch(()=>({{}}));m.textContent=x.detail||'로그인하지 못했습니다.'}}}});</script></main></body></html>"""


def dashboard(identity, projects: list[dict], runs: int, *, admin: bool) -> str:
    cards = "".join(
        f"<section><h2><a href='/koda/projects/{esc(item['project_id'])}'>{esc(item['name'])}</a></h2><p class='muted'>{esc(item['project_id'])}</p></section>"
        for item in projects
    ) or "<p>접근 가능한 프로젝트가 없습니다.</p>"
    return page(
        "대시보드",
        f"<p><strong>{esc(identity.display)}</strong>님, 로그인되었습니다.</p><div class='grid'><section><h2>프로젝트</h2><strong>{len(projects)}</strong></section><section><h2>분석 회차</h2><strong>{runs}</strong></section></div><h2>내 프로젝트</h2><div class='grid'>{cards}</div>",
        admin=admin,
    )


def projects_page(projects: list[dict], *, admin: bool) -> str:
    create = """
<section><h2>프로젝트 만들기</h2><form id='create'><label>이름<input name='name' required maxlength='128'></label><button class='primary'>생성</button></form><script>document.querySelector('#create')?.addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await json('/koda/api/v1/projects',{method:'POST',body:JSON.stringify({name:f.get('name')})});location.reload()}catch(x){alert(x.message)}})</script></section>""" if admin else ""
    rows = "".join(f"<tr><td><a href='/koda/projects/{esc(p['project_id'])}'>{esc(p['name'])}</a></td><td>{esc(p['created_at'])}</td></tr>" for p in projects)
    return page("프로젝트", create + f"<section><table><thead><tr><th>이름</th><th>생성</th></tr></thead><tbody>{rows}</tbody></table></section>", admin=admin)


def project_page(project: dict, inputs: list[dict], runs: list[dict], *, can_upload: bool, can_scan: bool, admin: bool) -> str:
    input_rows = "".join(f"<tr><td>{esc(i['name'])}</td><td><code>{esc(i['content_hash'][:16])}</code></td><td>{esc(i['created_at'])}</td></tr>" for i in inputs)
    run_rows = "".join(f"<tr><td><a href='/koda/runs/{esc(r['run_id'])}'>#{r['round_number']}</a></td><td>{esc(r['standard'])}</td><td>{esc(r['status'])}</td></tr>" for r in runs)
    upload = """
<section><h2>입력 업로드</h2><form id='upload'><label>파일<input name='file' type='file' required></label><button class='primary'>업로드</button></form></section>""" if can_upload else ""
    scan = """
<section><h2>분석 시작</h2><form id='scan'><label>입력<select name='input_id' required>""" + "".join(f"<option value='{esc(i['input_id'])}'>{esc(i['name'])}</option>" for i in inputs) + """</select></label><label>검사 기준<select name='standard' id='standard'></select></label><label>기준 범위<select name='standard_category' id='category'></select></label><button class='primary'>분석</button></form></section>""" if can_scan and inputs else ""
    script = f"""<script>
const projectId={json.dumps(project['project_id'])};
document.querySelector('#upload')?.addEventListener('submit',async e=>{{e.preventDefault();const f=e.currentTarget.file.files[0];if(!f)return;const bytes=new Uint8Array(await f.arrayBuffer());let s='';for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));try{{await json(`/koda/api/v1/projects/${{projectId}}/inputs`,{{method:'POST',body:JSON.stringify({{name:f.name,contentBase64:btoa(s)}})}});location.reload()}}catch(x){{alert(x.message)}}}});
let standards=[];const st=document.querySelector('#standard'),cat=document.querySelector('#category');function cats(){{const x=standards.find(v=>v.id===st.value);cat.innerHTML=(x?.categories||[]).filter(v=>v.supported).map(v=>`<option value="${{v.id}}">${{v.labels.ko||v.labels.en||v.id}}</option>`).join('')}}
if(st)json('/koda/api/v1/standards').then(x=>{{standards=x;st.innerHTML=x.map(v=>`<option value="${{v.id}}">${{v.labels.ko||v.labels.en||v.id}}</option>`).join('');cats()}});st?.addEventListener('change',cats);
document.querySelector('#scan')?.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget);try{{const r=await json('/koda/api/v1/scans',{{method:'POST',body:JSON.stringify({{project_id:projectId,input_id:f.get('input_id'),standard:f.get('standard'),standard_category:f.get('standard_category')}})}});location=`/koda/runs/${{r.run_id}}`}}catch(x){{alert(x.message)}}}});
</script>"""
    return page(str(project["name"]), upload + scan + f"<section><h2>입력</h2><table><tr><th>이름</th><th>SHA-256</th><th>등록</th></tr>{input_rows}</table></section><section><h2>분석 회차</h2><table><tr><th>회차</th><th>기준</th><th>상태</th></tr>{run_rows}</table></section>" + script, admin=admin)


def runs_page(projects: list[tuple[dict, list[dict]]], *, admin: bool) -> str:
    body = ""
    for project, runs in projects:
        rows = "".join(f"<tr><td><a href='/koda/runs/{esc(r['run_id'])}'>#{r['round_number']}</a></td><td>{esc(r['standard'])} / {esc(r['standard_category'])}</td><td>{esc(r['status'])}</td><td>{esc(r['created_at'])}</td></tr>" for r in runs)
        body += f"<section><h2>{esc(project['name'])}</h2><table><tr><th>회차</th><th>기준</th><th>상태</th><th>요청</th></tr>{rows}</table></section>"
    return page("분석 회차", body or "<p>분석 회차가 없습니다.</p>", admin=admin)


def run_page(run: dict, *, admin: bool) -> str:
    result = run.get("result") or {}
    findings = result.get("findings", []) if isinstance(result, dict) else []
    rows = "".join(f"<tr><td>{esc(f.get('severity',''))}</td><td>{esc(f.get('rule_id',''))}</td><td>{esc(f.get('title',''))}</td></tr>" for f in findings[:500])
    sbom = ""
    if run["status"] == "completed":
        available = bool((result.get("nis_sbom") or {}).get("rows") or result.get("components")) if isinstance(result, dict) else False
        disabled = "" if available else " disabled"
        note = "" if available else "<p class='muted'>SBOM으로 내보낼 의존성 컴포넌트가 없습니다.</p>"
        sbom = f"<section><h2>SBOM 다운로드</h2><form method='get' action='/koda/api/v1/runs/{esc(run['run_id'])}/sbom'><label for='sbom-format'>생성 형식</label><select id='sbom-format' name='format'><option value='cyclonedx'>CycloneDX 1.6 (JSON)</option><option value='nis-sbom'>국정원 NIS-SBOM 1.0 (CSV)</option></select> <button type='submit'{disabled}>다운로드</button></form>{note}</section>"
    return page(
        f"분석 #{run['round_number']}",
        f"<section><p>상태: <strong>{esc(run['status'])}</strong></p><p>기준: {esc(run['standard'])} / {esc(run['standard_category'])}</p><p>정책 버전: {esc(run['policy_version'])}</p><p class='error'>{esc(run.get('error') or '')}</p></section>{sbom}<section><h2>결과 ({len(findings)})</h2><table><tr><th>심각도</th><th>규칙</th><th>제목</th></tr>{rows}</table></section><details><summary>불변 실행 스냅샷</summary><pre>{esc(json.dumps(run['snapshot'], ensure_ascii=False, indent=2))}</pre></details>",
        admin=admin,
    )


def admin_page(title: str, body: str) -> str:
    return page(title, body, admin=True)
