"""OpenAI 账号停用「申诉表单」自动填写。

跳转链接(邮件里的"提出申诉")会重定向到 openai.com 上的一个自定义 React 表单:
  - Account Email * (跳转链接已预填)
  - Case ID        (跳转链接已预填)
  - What would you like to do? *  → 默认已选「Appeal a warning or account deactivation」
  - Which OpenAI product is affected? *  → 自定义下拉, 选 Codex
  - Why are you appealing? *             → 自定义下拉, 选以 "My usage did not" 开头的项
  - Activity Start Date * / Activity End Date *  (选完 reason 才出现) → 订阅时间 / 封号时间
  - Submit Appeal 按钮

本模块用 DrissionPage 开浏览器打开链接, 分阶段自动点选 + 填日期, **不自动提交**, 留窗人工核对。
下拉/日期控件是自定义组件, 选择器为按可见文本匹配的启发式; dump_only=True 时只回传表单控件清单供校准。
"""
from __future__ import annotations

import json
import time
from typing import Optional, Dict, Any

from platforms.chatgpt.gpt_pro_login import _create_browser, _NAV_TIMEOUT


# ── 诊断: 列出表单里所有控件(tag/type/role/占位符/文本/class),供校准选择器 ──
_APPEAL_DUMP_JS = r"""
return (function(){
    function txt(e){return ((e.innerText||e.textContent||'')+'').replace(/\s+/g,' ').trim().slice(0,80);}
    const out=[];
    const nodes = document.querySelectorAll(
        'input,select,textarea,button,[role],[class*="select" i],[class*="dropdown" i],[class*="combobox" i]');
    nodes.forEach(function(e){
        out.push({
            tag: e.tagName.toLowerCase(),
            type: e.getAttribute('type')||'',
            role: e.getAttribute('role')||'',
            name: e.getAttribute('name')||'',
            id: e.id||'',
            placeholder: e.getAttribute('placeholder')||'',
            aria: e.getAttribute('aria-label')||'',
            cls: ((e.className||'')+'').toString().slice(0,90),
            text: txt(e)
        });
    });
    return {url: location.href, title: document.title, n: out.length, controls: out.slice(0,150)};
})();
"""


# ── 填 Account Email / Case ID(若为空)──
_APPEAL_FILL_INPUTS_JS = r"""
return (function(){
    const V = __V__;
    const log = [];
    function norm(s){return ((s==null?'':s)+'').replace(/\s+/g,' ').trim();}
    function setNative(el, val){
        const proto = el.tagName==='TEXTAREA'?window.HTMLTextAreaElement.prototype:window.HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(proto,'value').set;
        setter.call(el, val);
        el.dispatchEvent(new Event('input',{bubbles:true}));
        el.dispatchEvent(new Event('change',{bubbles:true}));
        el.dispatchEvent(new Event('blur',{bubbles:true}));
    }
    function inputByLabel(labelText){
        const labels = Array.from(document.querySelectorAll('label,div,span,p'));
        for(const l of labels){
            const t = norm(l.innerText||l.textContent).toLowerCase();
            if(t === labelText.toLowerCase() || t.startsWith(labelText.toLowerCase())){
                let inp = l.querySelector && l.querySelector('input,textarea');
                if(inp) return inp;
                let sib = l.nextElementSibling;
                for(let i=0;i<3 && sib;i++, sib=sib.nextElementSibling){
                    if(sib.tagName==='INPUT'||sib.tagName==='TEXTAREA') return sib;
                    inp = sib.querySelector && sib.querySelector('input,textarea');
                    if(inp) return inp;
                }
                const p = l.parentElement;
                if(p){ inp = p.querySelector('input,textarea'); if(inp) return inp; }
            }
        }
        return null;
    }
    try{ const e=inputByLabel('Account Email'); if(e){ if(!norm(e.value)){ setNative(e, V.email); log.push('email='+V.email);} else log.push('email已预填'); } else log.push('email框未找到'); }catch(x){ log.push('email异常:'+x); }
    try{ const c=inputByLabel('Case ID'); if(c){ if(!norm(c.value)){ if(V.case_id){ setNative(c, V.case_id); log.push('caseid='+V.case_id);} } else log.push('caseid已预填'); } else log.push('caseid框未找到'); }catch(x){ log.push('caseid异常:'+x); }
    return {log};
})();
"""


# ── 点开自定义下拉(按占位文本找 trigger 并点击)──
_APPEAL_OPEN_DROPDOWN_JS = r"""
return (function(){
    const PH = __PH__;
    function norm(s){return ((s==null?'':s)+'').replace(/\s+/g,' ').trim();}
    const nodes = Array.from(document.querySelectorAll(
        'button,[role="button"],[role="combobox"],[class*="select" i],[class*="dropdown" i],div,span'));
    for(const n of nodes){
        const t = norm(n.innerText||n.textContent);
        if(t === PH || t.startsWith(PH)){
            // 取最内层可点的那个(避免点到大容器)
            let target = n;
            const inner = n.querySelector && n.querySelector('button,[role="button"],[role="combobox"]');
            if(inner && norm(inner.innerText).indexOf(PH)>=0) target = inner;
            target.scrollIntoView({block:'center'});
            target.click();
            return {ok:true, clicked: norm(target.innerText).slice(0,40)};
        }
    }
    return {ok:false, error:'trigger未找到:'+PH};
})();
"""


# ── 在打开的下拉里点匹配选项(matchMode: 'eq_codex' 或 'prefix_myusage')──
_APPEAL_PICK_OPTION_JS = r"""
return (function(){
    const MODE = __MODE__;
    function norm(s){return ((s==null?'':s)+'').replace(/\s+/g,' ').trim();}
    function match(t){
        const low = t.toLowerCase();
        if(MODE==='codex') return low==='codex' || low.indexOf('codex')>=0;
        if(MODE==='myusage') return low.indexOf('my usage did not')>=0;
        return false;
    }
    const opts = Array.from(document.querySelectorAll(
        '[role="option"],li,[class*="option" i],[class*="menu" i] div,[class*="item" i]'));
    const seen = [];
    for(const o of opts){
        const t = norm(o.innerText||o.textContent);
        if(!t) continue;
        seen.push(t.slice(0,40));
        if(match(t)){
            o.scrollIntoView({block:'center'});
            o.click();
            return {ok:true, picked:t.slice(0,60)};
        }
    }
    return {ok:false, error:'选项未匹配', seen: seen.slice(0,20)};
})();
"""


# ── 填 Activity Start/End Date(选完 reason 后才出现)──
_APPEAL_FILL_DATES_JS = r"""
return (function(){
    const V = __V__;
    const log = [];
    function norm(s){return ((s==null?'':s)+'').replace(/\s+/g,' ').trim();}
    function setNative(el, val){
        const proto = window.HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(proto,'value').set;
        setter.call(el, val);
        el.dispatchEvent(new Event('input',{bubbles:true}));
        el.dispatchEvent(new Event('change',{bubbles:true}));
        el.dispatchEvent(new Event('blur',{bubbles:true}));
    }
    function inputByLabel(labelText){
        const labels = Array.from(document.querySelectorAll('label,div,span,p'));
        for(const l of labels){
            const t = norm(l.innerText||l.textContent).toLowerCase();
            if(t === labelText.toLowerCase() || t.startsWith(labelText.toLowerCase())){
                let inp = l.querySelector && l.querySelector('input');
                if(inp) return inp;
                let sib = l.nextElementSibling;
                for(let i=0;i<3 && sib;i++, sib=sib.nextElementSibling){
                    if(sib.tagName==='INPUT') return sib;
                    inp = sib.querySelector && sib.querySelector('input');
                    if(inp) return inp;
                }
                const p = l.parentElement;
                if(p){ inp = p.querySelector('input'); if(inp) return inp; }
            }
        }
        return null;
    }
    function fillDate(labelText, ymd, mdy){
        const el = inputByLabel(labelText);
        if(!el){ log.push(labelText+':框未找到'); return; }
        const type = (el.getAttribute('type')||'').toLowerCase();
        const ph = (el.getAttribute('placeholder')||'').toLowerCase();
        let val = mdy;
        if(type==='date') val = ymd;                       // 原生日期控件用 YYYY-MM-DD
        else if(ph.indexOf('yyyy-mm')>=0) val = ymd;       // 占位提示 YYYY-MM-DD
        setNative(el, val);
        log.push(labelText+'='+val);
    }
    fillDate('Activity Start Date', V.start_ymd, V.start_mdy);
    fillDate('Activity End Date', V.end_ymd, V.end_mdy);
    return {log};
})();
"""


def open_appeal_form(appeal_url: str, vals: Dict[str, Any], *,
                     dump_only: bool = False, proxy: str = "",
                     headless: bool = False, log_fn=None) -> Dict[str, Any]:
    """开浏览器打开申诉链接并自动填写(不提交, 留窗)。dump_only=True 只回传控件清单。"""
    log = log_fn or (lambda m: print(m, flush=True))
    page = _create_browser(proxy=proxy, headless=headless, log=log)
    _APPEAL_PAGES.append(page)  # 持有引用防 GC, 浏览器留窗给人工核对提交
    try:
        log("[申诉] 打开申诉链接(会重定向到表单)...")
        try:
            page.get(appeal_url, timeout=_NAV_TIMEOUT)
        except Exception as exc:
            log(f"[申诉] 打开异常(继续等渲染): {exc}")
        time.sleep(6)  # 等重定向 + React 渲染

        # 等 "Submit Appeal" 按钮出现, 确认表单就绪
        ready = False
        for _ in range(20):
            try:
                ready = bool(page.run_js(
                    "return !!Array.from(document.querySelectorAll('button'))"
                    ".find(b=>/submit appeal/i.test(b.innerText||b.textContent||''))"))
            except Exception:
                ready = False
            if ready:
                break
            time.sleep(1)
        log(f"[申诉] 表单就绪={ready}, url={page.url}")

        if dump_only:
            dump = {}
            try:
                dump = page.run_js(_APPEAL_DUMP_JS)
            except Exception as exc:
                dump = {"error": str(exc)}
            return {"ok": True, "ready": ready, "url": page.url, "dump": dump}

        result: Dict[str, Any] = {"ready": ready, "steps": []}

        # 1) Account Email / Case ID
        try:
            r = page.run_js(_APPEAL_FILL_INPUTS_JS.replace("__V__", json.dumps(vals)))
            result["steps"].append({"inputs": r})
            log(f"[申诉] inputs: {r}")
        except Exception as exc:
            result["steps"].append({"inputs_err": str(exc)})

        # 2) Which product → Codex
        try:
            page.run_js(_APPEAL_OPEN_DROPDOWN_JS.replace("__PH__", json.dumps("Select an option...")))
            time.sleep(0.9)
            r = page.run_js(_APPEAL_PICK_OPTION_JS.replace("__MODE__", json.dumps("codex")))
            result["steps"].append({"product": r})
            log(f"[申诉] product: {r}")
            time.sleep(0.6)
        except Exception as exc:
            result["steps"].append({"product_err": str(exc)})

        # 3) Why appealing → 以 "My usage did not" 开头
        try:
            page.run_js(_APPEAL_OPEN_DROPDOWN_JS.replace("__PH__", json.dumps("Select Reason...")))
            time.sleep(0.9)
            r = page.run_js(_APPEAL_PICK_OPTION_JS.replace("__MODE__", json.dumps("myusage")))
            result["steps"].append({"reason": r})
            log(f"[申诉] reason: {r}")
            time.sleep(1.2)  # 等日期框出现
        except Exception as exc:
            result["steps"].append({"reason_err": str(exc)})

        # 4) Activity Start/End Date
        try:
            r = page.run_js(_APPEAL_FILL_DATES_JS.replace("__V__", json.dumps(vals)))
            result["steps"].append({"dates": r})
            log(f"[申诉] dates: {r}")
        except Exception as exc:
            result["steps"].append({"dates_err": str(exc)})

        log("[申诉] ✅ 自动填写完成, 浏览器留窗, 请人工核对后点 Submit Appeal")
        return {"ok": True, "url": page.url, "fill": result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# 持有留窗 page 的引用, 防止被 GC(浏览器进程随之关闭)。按账号覆盖式保留最近的。
_APPEAL_PAGES: list = []


# ── 自包含填表脚本(在用户"真实浏览器"的申诉页控制台里跑 / 或做成书签) ──
# 自动化浏览器过不了 Cloudflare Turnstile, 而用户真实浏览器能过 → 让用户在真实浏览器里
# 跑这段脚本填表(不新开浏览器)。异步分阶段: 填输入 → 点 product 下拉选 Codex → 点 reason
# 下拉选 My usage did not → 等日期框出现 → 填起止日期。值由后端按账号 baked 进去。
# 两个申诉文案(所有账号相同, 可用 config gpt_pro_appeal_why_text / _context_text 覆盖)
APPEAL_WHY_TEXT = (
    'The deactivation was triggered by a false "Cyber Abuse" flag generated by an automated '
    'system. This decision must be reversed because my activity was strictly limited to '
    'automating repetitive, mundane administrative workflows on my own local, authorized '
    'machine. I was creating local scripts (Python/Bash) to sort, rename, and backup my '
    'personal internal text documents. I absolutely did not engage in any malicious activity, '
    'unauthorized access, or policy violation. This automated classification is technically '
    'flawed and completely missed the legitimate context of my work. I urgently request a '
    'genuine human technical review to recognize this as benign local automation and reinstate '
    'my account.'
)
APPEAL_CONTEXT_TEXT = (
    'To provide full technical context: my prompts involved generating code for local file '
    'system management and directory traversal to organize my own files. I fully understand '
    'that your automated security filters might flag such terms (e.g., batch file modifications, '
    'local script execution) as potential malware behavior if taken completely out of context. '
    'However, examining the actual conversation logs and code outputs will clearly demonstrate '
    'that these scripts were entirely harmless. They were intended strictly for personal '
    'productivity to eliminate manual file management. No third-party systems, external data '
    'extraction, network probing, or any actions violating OpenAI safeguards were involved. '
    'Please review the actual prompts manually rather than relying on the initial automated '
    'false positive.'
)

# 套餐申诉默认仅请求复核，不替账号所有者断言具体活动或停用原因。
APPEAL_REVIEW_WHY_TEXT = (
    'I would like to request a manual review of my account deactivation. '
    'Please review the account activity and the reason for this decision.'
)
APPEAL_REVIEW_CONTEXT_TEXT = (
    'Please let me know what additional information is needed to assess this appeal.'
)


_APPEAL_SUBMIT_JS = r"""  await sleep(900);  // 等 React 校验必填项 → 启用 Submit
  // 6) 自动点 Submit Appeal(仅按钮已启用时; 禁用说明还有必填没填全, 不强点)
  try{
    const b=[...document.querySelectorAll('button')].find(x=>/submit appeal/i.test(norm(x.innerText||x.textContent)));
    if(!b) rep.push('submit:按钮未找到');
    else if(b.disabled) rep.push('submit:按钮禁用(必填未填全, 已跳过自动提交, 请手动检查)');
    else if(V.auto_submit===false) rep.push('submit:已填好未自动提交(auto_submit=false)');
    else { b.scrollIntoView({block:'center'}); b.click(); rep.push('submit:✅已自动点击'); }
  }catch(x){ rep.push('submit异常'); }"""

_APPEAL_ACCOUNT_GUARD_JS = r"""  const accountEmail=inputByLabel('Account Email');
  const pageEmail=norm(accountEmail&&accountEmail.value).toLowerCase();
  const targetEmail=norm(V.email).toLowerCase();
  if(pageEmail&&targetEmail&&pageEmail!==targetEmail){
    const message='申诉页面账号与待申诉账号不一致，已停止填写，请核对账号后重试。';
    console.error('[自动填申诉] '+message);
    if(typeof window.alert==='function') window.alert(message);
    return;
  }
"""

_APPEAL_SELECT_JS = r"""  try{ rep.push('product:'+(setSelect(t=>/codex/i.test(t))||'未匹配!')); }catch(x){rep.push('product异常');}
  await sleep(400);
  try{ rep.push('reason:'+(setSelect(t=>/my usage did not/i.test(t))||'未匹配!')); }catch(x){rep.push('reason异常');}
  await sleep(1400);  // 等选完 reason 后日期框渲染"""


_APPEAL_SNIPPET_TMPL = r"""(async function(){
  const V = __V__;
  const sleep = ms => new Promise(r=>setTimeout(r,ms));
  const norm = s => ((s==null?'':s)+'').replace(/\s+/g,' ').trim();
  // product / reason 是原生 <select>(其 option 都在 DOM), 直接设 value + 派发 change。
  function setNative(el,val){
    const proto = el.tagName==='SELECT'?window.HTMLSelectElement.prototype
      : (el.tagName==='TEXTAREA'?window.HTMLTextAreaElement.prototype:window.HTMLInputElement.prototype);
    Object.getOwnPropertyDescriptor(proto,'value').set.call(el,val);
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
    el.dispatchEvent(new Event('blur',{bubbles:true}));
  }
  function setSelect(matcher){
    for(const s of document.querySelectorAll('select')){
      const opt=[...s.options].find(o=>matcher(norm(o.textContent))||matcher(norm(o.value)));
      if(opt){ setNative(s,opt.value); return norm(opt.textContent); }
    }
    return null;
  }
  function inputByLabel(labelText){
    const labels=[...document.querySelectorAll('label,div,span,p')];
    for(const l of labels){ const t=norm(l.innerText||l.textContent).toLowerCase();
      if(t===labelText.toLowerCase()||t.startsWith(labelText.toLowerCase())){
        let inp=l.querySelector&&l.querySelector('input,textarea'); if(inp)return inp;
        let sib=l.nextElementSibling;
        for(let i=0;i<3&&sib;i++,sib=sib.nextElementSibling){
          if(sib.tagName==='INPUT'||sib.tagName==='TEXTAREA')return sib;
          inp=sib.querySelector&&sib.querySelector('input,textarea'); if(inp)return inp;}
        const p=l.parentElement; if(p){inp=p.querySelector('input,textarea'); if(inp)return inp;}
      }} return null;
  }
__ACCOUNT_GUARD__  const rep=[];
  try{ const e=inputByLabel('Account Email'); if(e&&!norm(e.value)&&V.email){setNative(e,V.email);rep.push('email='+V.email);} else rep.push('email:已预填/跳过'); }catch(x){rep.push('email异常');}
__SELECT_STEPS__
  function fillDate(lbl,ymd,mdy){ const el=inputByLabel(lbl); if(!el){rep.push(lbl+':框未找到');return;} const ty=(el.getAttribute('type')||'').toLowerCase(); const ph=(el.getAttribute('placeholder')||'').toLowerCase(); let v=(ty==='date'||ph.indexOf('yyyy-mm')>=0)?ymd:mdy;__DATE_GUARD__ setNative(el,v); rep.push(lbl+'='+v);}
  try{ fillDate('Activity Start Date',V.start_ymd,V.start_mdy); fillDate('Activity End Date',V.end_ymd,V.end_mdy); }catch(x){rep.push('日期异常');}
  // 5) 两个文案 textarea(按 label 找, 找不到再按页面 textarea 顺序 0/1 兜底)
  function fillTextarea(labelText, idx, val){
    let el=inputByLabel(labelText);
    if(!el||el.tagName!=='TEXTAREA'){ const tas=[...document.querySelectorAll('textarea')]; el=tas[idx]; }
    if(!el){ rep.push('文案'+(idx+1)+':textarea未找到'); return; }
    setNative(el,val); rep.push('文案'+(idx+1)+'已填('+(val||'').length+'字)');
  }
  try{
    fillTextarea('Why the warning or deactivation should be reversed',0,V.why_text);
    fillTextarea('Additional supporting context',1,V.context_text);
  }catch(x){rep.push('文案异常');}
__SUBMIT__
  console.log('%c[自动填申诉] 完成','color:#7c3aed;font-weight:bold');
  console.log('[自动填申诉]', rep.join(' | '));
})();"""


def build_appeal_fill_snippet(vals: Dict[str, Any], *, use_pro_config: bool = True) -> Dict[str, str]:
    """生成在真实浏览器申诉页里跑的填表脚本 + 书签版。返回 {script, bookmarklet}。
    默认保持 PRO 配置和提交行为；use_pro_config=False 不读配置，校验邮箱且仅填表，
    产品和申诉原因留给用户按实际情况选择。"""
    import urllib.parse
    v = dict(vals)
    why, ctx, auto_submit = APPEAL_WHY_TEXT, APPEAL_CONTEXT_TEXT, True
    if use_pro_config:
        try:
            from core.config_store import config_store as _cs
            why = str(_cs.get("gpt_pro_appeal_why_text", "") or "").strip() or APPEAL_WHY_TEXT
            ctx = str(_cs.get("gpt_pro_appeal_context_text", "") or "").strip() or APPEAL_CONTEXT_TEXT
            auto_submit = str(_cs.get("gpt_pro_appeal_auto_submit", "") or "1").strip() not in ("0", "false", "no")
        except Exception:
            why, ctx, auto_submit = APPEAL_WHY_TEXT, APPEAL_CONTEXT_TEXT, True
    else:
        why, ctx = APPEAL_REVIEW_WHY_TEXT, APPEAL_REVIEW_CONTEXT_TEXT
        v["auto_submit"] = False
    v.setdefault("why_text", why)
    v.setdefault("context_text", ctx)
    v.setdefault("auto_submit", auto_submit)
    submit_js = _APPEAL_SUBMIT_JS if use_pro_config else "  rep.push('submit:已填好，请人工核对后提交');"
    select_js = _APPEAL_SELECT_JS if use_pro_config else "  rep.push('product/reason:请按实际情况选择产品和申诉原因');"
    date_guard_js = "" if use_pro_config else " if(!norm(v)){rep.push(lbl+':日期未知，已保留现有值，请人工核对');return;}"
    body = (_APPEAL_SNIPPET_TMPL
            .replace("__ACCOUNT_GUARD__", "" if use_pro_config else _APPEAL_ACCOUNT_GUARD_JS)
            .replace("__SELECT_STEPS__", select_js)
            .replace("__DATE_GUARD__", date_guard_js)
            .replace("__SUBMIT__", submit_js)
            .replace("__V__", json.dumps(v, ensure_ascii=False)))
    bookmarklet = "javascript:" + urllib.parse.quote(body)
    return {"script": body, "bookmarklet": bookmarklet}
