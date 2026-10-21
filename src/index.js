// uptime-monitor — Cloudflare Worker
// Cron 每 5 分钟探测目标 → D1 落库 + KV 快照 → 状态翻转邮件告警
// GET /            状态板（公开，自动刷新）
// GET /api/status  JSON
// GET /api/check?key=SECRET  手动触发一轮探测

import { EmailMessage } from "cloudflare:email";
import { sendMail } from "./smtp.js";

// 默认监视目标（管理员可在 /diamond_dia 后台增删改，存 KV 覆盖）
const DEFAULT_TARGETS = [
  { name: "webui (tunnel)",     url: "https://www.cloudflare.com" },
  { name: "v6webui (direct)",   url: "https://www.github.com" },
  { name: "home direct :8080",  url: "https://httpbin.org" },
  { name: "VPS x-ui :8443",     url: "https://api.github.com" },
  { name: "root site",          url: "https://example.com" },
];

const RETENTION_DAYS = 7;

// 监控项读取：KV 覆盖 → 默认列表
async function getTargets(env) {
  try {
    const raw = await env.KV.get("targets");
    if (raw) {
      const list = JSON.parse(raw);
      if (Array.isArray(list) && list.length && list.every((t) => t?.name && t?.url)) return list;
    }
  } catch (_) {}
  return DEFAULT_TARGETS;
}

// ---------- 管理员鉴权 ----------

async function adminToken(env) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.ADMIN_PASSWORD),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("uptime-admin-v1"));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// 为「重启 X-ui」签发短时密钥：算法须与 vps/xui-restart-server.py 的 verify() 完全一致
//   sig = hex(HMAC-SHA256(RESTART_KEY, "xui-restart:" + ts)).slice(0,24)
async function issueRestartKey(env) {
  const ts = Math.floor(Date.now() / 1000);
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.RESTART_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`xui-restart:${ts}`));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 24);
  return { ts, key: hex };
}

// 前端直连 VPS 重启服务的地址（https://<host>:<port>）
function restartVpsUrl(env) {
  return `https://${env.SSH_HOST || "example.com"}:${env.SSH_PORT || "39332"}`;
}


function getCookie(request, name) {
  const c = request.headers.get("cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return m ? m[1] : null;
}

// ---------- Cloudflare Zero Trust（Access）管理员登录 ----------
// Access 在边缘拦截 /diamond_dia*，邮箱 OTP 通过后注入 Cf-Access-Jwt-Assertion 头；
// 此处验证签名 + aud + 邮箱白名单，通过即视为管理员。vars 未配置时自动回退密码登录。
let accessCertsCache = { keys: null, ts: 0 };

function b64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}

async function verifyAccessJWT(env, token) {
  const team = (env.ACCESS_TEAM_DOMAIN || "").trim();
  const aud = (env.ACCESS_AUD || "").trim();
  const allow = (env.ACCESS_EMAILS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (!team || !aud || !token) return null;
  const domain = team.includes(".") ? team : `${team}.cloudflareaccess.com`;
  try {
    if (!accessCertsCache.keys || Date.now() - accessCertsCache.ts > 3600000) {
      const r = await fetch(`https://${domain}/cdn-cgi/access/certs`);
      if (!r.ok) return null;
      accessCertsCache = { keys: await r.json(), ts: Date.now() };
    }
    const [h, p, sig] = token.split(".");
    if (!h || !p || !sig) return null;
    const header = JSON.parse(b64url(h));
    const jwk = (accessCertsCache.keys.keys || []).find((k) => k.kid === header.kid && k.kty === "RSA");
    if (!jwk) return null;
    const ckey = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const sigBytes = Uint8Array.from(b64url(sig), (c) => c.charCodeAt(0));
    const okSig = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", ckey, sigBytes, new TextEncoder().encode(`${h}.${p}`));
    if (!okSig) return null;
    const payload = JSON.parse(b64url(p));
    if ((payload.exp || 0) * 1000 < Date.now()) return null;
    const audOk = payload.aud === aud || (Array.isArray(payload.aud) && payload.aud.includes(aud));
    if (!audOk) return null;
    const email = String(payload.email || "").toLowerCase();
    if (allow.length && !allow.includes(email)) return null;
    return email;
  } catch (_) {
    return null;
  }
}

async function isAdmin(request, env) {
  // ① Cloudflare Zero Trust：边缘注入的 JWT 验证通过即管理员
  const at = request.headers.get("cf-access-jwt-assertion");
  if (at && env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD) {
    const email = await verifyAccessJWT(env, at);
    if (email) return true;
  }
  // ② 回退：密码登录的 HMAC cookie（worker.dev 直连 / 未启用 Access 时）
  if (!env.ADMIN_PASSWORD) return false;
  return getCookie(request, "admin") === (await adminToken(env));
}

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runChecks(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/check") {
      if (!env.API_KEY || url.searchParams.get("key") !== env.API_KEY) {
        return json({ error: "unauthorized" }, 401);
      }
      const results = await runChecks(env);
      return json({ ok: true, results });
    }

    // 家宽探测节点上报（diana PC）：只入库展示，不触发告警、不写 KV
    if (url.pathname === "/api/report" && request.method === "POST") {
      if (!env.API_KEY || url.searchParams.get("key") !== env.API_KEY) {
        return json({ error: "unauthorized" }, 401);
      }
      if ((await getProbeMode(env)) === "worker") {
        return json({ error: "home probe disabled (probes=worker)" }, 403);
      }
      let body = null;
      try { body = await request.json(); } catch (_) {}
      const items = Array.isArray(body?.results) ? body.results.slice(0, 50) : null;
      if (!items || !items.length) return json({ error: "bad payload" }, 400);
      let inserted = 0;
      for (const r of items) {
        if (!r?.name) continue;
        try {
          await env.DB.prepare(
            "INSERT INTO checks (target, ok, status, latency_ms, error, probe) VALUES (?, ?, ?, ?, ?, 'home')"
          ).bind(
            String(r.name).slice(0, 80), r.ok ? 1 : 0,
            Number(r.status) || 0, Math.max(0, Number(r.latency) || 0),
            String(r.error || "").slice(0, 160)
          ).run();
          inserted++;
        } catch (_) {}
      }
      return json({ ok: true, inserted });
    }

    if (url.pathname === "/api/status") {
      return json(await buildStatus(env));
    }

    if (url.pathname === "/" || url.pathname === "/status") {
      const offset = Math.max(0, parseInt(url.searchParams.get("offset") || "0", 10) || 0);
      return html(await buildStatus(env, offset));
    }

    if (url.pathname === "/api/email-test") {
      if (!env.API_KEY || url.searchParams.get("key") !== env.API_KEY) {
        return json({ error: "unauthorized" }, 401);
      }
      try {
        await notify(env, {
          name: "uptime-monitor 测试邮件", url: "https://example.com",
          ok: true, status: 200, latency: 0, error: "",
        }, { ok: false });
        return json({ ok: true, sent_to: env.ALERT_TO });
      } catch (e) {
        return json({ ok: false, error: String(e?.message || e) }, 500);
      }
    }

    // ---------- 管理后台 /diamond_dia ----------
    if (url.pathname === "/diamond_dia" || url.pathname.startsWith("/diamond_dia/")) {
      return handleAdmin(request, env, url);
    }

    const tm = url.pathname.match(/^\/target\/(.+)$/);
    if (tm) {
      const name = decodeURIComponent(tm[1]);
      if (!(await getTargets(env)).some((t) => t.name === name)) {
        return json({ error: "unknown target" }, 404);
      }
      const offset = Math.max(0, parseInt(url.searchParams.get("offset") || "0", 10) || 0);
      return htmlTarget(await buildTargetDetail(env, name, offset), name);
    }

    return json({ error: "not found" }, 404);
  },
};

// ---------- 核心探测 ----------

// 探测超时（ms）：管理员可在 /diamond_dia 后台修改，存 KV config:timeout_ms，默认 8000
async function getTimeoutMs(env) {
  try {
    const v = parseInt(await env.KV.get("config:timeout_ms"), 10);
    if (v >= 1000 && v <= 30000) return v;
  } catch (_) {}
  return 8000;
}

// 探测来源：worker（仅 CF 边缘）/ home（仅家宽节点）/ both（默认，双路并行）
const PROBE_LABELS = { worker: "仅 Worker（CF 边缘）", home: "仅 Home（家宽节点）", both: "两者同时" };

async function getProbeMode(env) {
  try {
    const v = await env.KV.get("config:probes");
    if (v === "worker" || v === "home" || v === "both") return v;
  } catch (_) {}
  return "both";
}

async function runChecks(env) {
  // 探测来源开关：仅 home 时 Worker 侧暂停探测与告警，数据清理照常
  const probeMode = await getProbeMode(env);
  const targets = await getTargets(env);
  // 每轮探测只读一次超时配置（KV 读 288 次/天，额度无忧）
  const timeoutMs = await getTimeoutMs(env);
  if (probeMode === "home") {
    try {
      await env.DB.prepare(
        "DELETE FROM checks WHERE ts < strftime('%s','now') - ?"
      ).bind(RETENTION_DAYS * 86400).run();
    } catch (_) {}
    return [];
  }
  const results = [];
  for (const t of targets) {
    const start = Date.now();
    let ok = false, status = 0, err = "", colo = "";
    try {
      const resp = await fetch(t.url, {
        redirect: "follow",
        signal: AbortSignal.timeout(timeoutMs),
        headers: { "user-agent": "uptime-monitor/1.0 (+cloudflare-worker)" },
      });
      status = resp.status;
      ok = status < 500;
      // 本次执行所在 CF 数据中心（IATA 机场码）：从探测响应的 cf-ray 提取，零额外请求
      // 格式 <hex>-<COLO>，如 "8a1b...c-SIN"；目标未走 CF 代理时无此头，留空
      colo = (resp.headers.get("cf-ray") || "").split("-")[1] || "";
    } catch (e) {
      err = String(e?.message || e).slice(0, 160);
    }
    const latency = Date.now() - start;

    const rec = { name: t.name, url: t.url, ok, status, latency, error: err };
    results.push(rec);

    try {
      await env.DB.prepare(
        "INSERT INTO checks (target, ok, status, latency_ms, error, probe, colo) VALUES (?, ?, ?, ?, ?, 'cf', ?)"
      ).bind(t.name, ok ? 1 : 0, status, latency, err, colo).run();

      // 状态翻转 → 邮件告警；仅首次或状态变化时写 KV，避免 KV 写放大超免费额度
      const prevRaw = await env.KV.get("state:" + t.name);
      const prev = prevRaw ? JSON.parse(prevRaw) : null;
      if (!prev || prev.ok !== ok) {
        // 首次探测或状态翻转：更新最新快照（KV 写操作仅在状态变化时发生）
        await env.KV.put("state:" + t.name, JSON.stringify({ ok, status, latency, ts: Date.now() }));
        // 状态翻转（非首次）才发告警
        if (prev && prev.ok !== ok) {
          ctx?.waitUntil?.(notify(env, rec, prev));
          await notify(env, rec, prev).catch(() => {});
        }
      }
    } catch (e) {
      console.error("persist/alert failed:", e?.message || e);
    }
  }

  // 数据保留清理（7 天）
  try {
    await env.DB.prepare(
      "DELETE FROM checks WHERE ts < strftime('%s','now') - ?"
    ).bind(RETENTION_DAYS * 86400).run();
  } catch (_) {}

  return results;
}

// ---------- 邮件告警（Email Routing send_email 绑定） ----------

async function notify(env, rec, prev) {
  const state = rec.ok ? "RECOVERED ✓" : "DOWN ✗";
  const subj = `[${state}] ${rec.name} — uptime-monitor`;
  const body = [
    `目标:   ${rec.name}`,
    `地址:   ${rec.url}`,
    `状态:   ${rec.ok ? "恢复" : "宕机"} (HTTP ${rec.status || "N/A"})`,
    `延迟:   ${rec.latency} ms`,
    rec.error ? `错误:   ${rec.error}` : "",
    `前态:   ${prev.ok ? "up" : "down"} → 现态: ${rec.ok ? "up" : "down"}`,
    `时间:   ${new Date().toISOString()}`,
    "",
    "— uptime-monitor (Cloudflare Worker)",
  ].filter(Boolean).join("\n");

  // 主通道：QQ SMTP（QQ→QQ 站内投递）
  if (env.SMTP_USER && env.SMTP_PASS) {
    await sendMail({
      user: env.SMTP_USER,
      pass: env.SMTP_PASS,
      from: env.SMTP_USER,
      to: env.ALERT_TO,
      subject: subj,
      text: body,
    });
    return;
  }

  // 备用通道：Email Routing send_email 绑定（无 DKIM，可能被判垃圾）
  if (env.SEND_EMAIL) {
    const mime = [
      `From: ${env.ALERT_FROM}`,
      `To: ${env.ALERT_TO}`,
      `Subject: ${subj}`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "",
      body,
    ].join("\r\n");
    await env.SEND_EMAIL.send(
      new EmailMessage(env.ALERT_FROM, env.ALERT_TO, new Response(mime).body)
    );
  }
}

// ---------- 状态数据 ----------

const VIEW_DAYS = 90;

async function buildStatus(env, offset = 0) {
  // 总览统计主视角跟随探测来源：仅 home 时以家宽数据为准，否则以 CF 边缘为准
  const probeMode = await getProbeMode(env);
  const mainProbe = probeMode === "home" ? "home" : "cf";
  const endTs = Math.floor(Date.now() / 1000) - offset * VIEW_DAYS * 86400;
  const startTs = endTs - VIEW_DAYS * 86400;

  // 最新快照
  const targets = await getTargets(env);
  const states = [];
  for (const t of targets) {
    const raw = await env.KV.get("state:" + t.name);
    states.push({ name: t.name, url: t.url, latest: raw ? JSON.parse(raw) : null });
  }

  // 24h 统计（明细表用）
  let stats = {};
  try {
    const { results } = await env.DB.prepare(
      `SELECT target, COUNT(*) AS total, SUM(ok) AS up,
              CAST(AVG(latency_ms) AS INTEGER) AS avg_latency
       FROM checks WHERE ts > strftime('%s','now') - 86400 AND probe = '${mainProbe}'
       GROUP BY target`
    ).all();
    for (const row of results) stats[row.target] = row;
  } catch (_) {}

  // 窗口内逐日聚合（按北京时区分日）
  const byTarget = {};
  for (const t of targets) byTarget[t.name] = {};
  try {
    const { results } = await env.DB.prepare(
      `SELECT target, date(ts,'unixepoch','+8 hours') AS d,
              COUNT(*) AS total, SUM(ok) AS up
       FROM checks WHERE ts >= ? AND ts < ? AND probe = '${mainProbe}' GROUP BY target, d`
    ).bind(startTs, endTs).all();
    for (const r of results) if (byTarget[r.target]) byTarget[r.target][r.d] = { total: r.total, up: r.up };
  } catch (_) {}

  // 连续日轴（北京日历日，最后一天 = 今天）
  const days = [];
  for (let i = VIEW_DAYS - 1; i >= 0; i--) {
    days.push(new Date((endTs - i * 86400 + 8 * 3600) * 1000).toISOString().slice(0, 10));
  }

  const list = [];
  for (const s of states) {
    const per = byTarget[s.name] || {};
    let wTotal = 0, wUp = 0;
    const dayStats = days.map((d) => {
      const st = per[d];
      if (!st || !st.total) return { d, cls: "nodata", checks: 0, up: null, ratio: null };
      const ratio = st.up / st.total;
      wTotal += st.total;
      wUp += st.up;
      const cls = ratio >= 0.999 ? "up" : ratio >= 0.95 ? "degraded" : "down";
      return { d, cls, checks: st.total, up: st.up, ratio };
    });
    const st = stats[s.name];
    list.push({
      name: s.name,
      url: s.url,
      latest: s.latest,
      uptime24h: st ? (st.up * 100 / st.total).toFixed(2) : null,
      avg_latency: st ? st.avg_latency : null,
      checks24h: st ? st.total : 0,
      dayStats,
      uptimeWindow: wTotal ? (wUp * 100 / wTotal).toFixed(2) : null,
    });
  }

  return {
    generated_at: new Date().toISOString(),
    probeMode,
    range: { start: days[0], end: days[days.length - 1], offset, days: VIEW_DAYS },
    targets: list,
  };
}

// ---------- HTTP helpers ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// ---------- 页面模板（共享样式） ----------

// Cloudflare 横版 logo（源自官方图，白底已透明化；dark 版字标提亮适配深色主题）
const CF_LOGO_LIGHT = "data:image/png;base64,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";
const CF_LOGO_DARK = "data:image/png;base64,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";

// 动效层：所有页面共享（首页内联样式与 PAGE_CSS 都引用它）
const FX_CSS = `
  /* 跨页面视图过渡（Chrome 126+ MPA，其它浏览器自动降级为普通跳转） */
  @view-transition { navigation: auto; }
  ::view-transition-old(root) { animation: vt-out .18s ease both; }
  ::view-transition-new(root) { animation: vt-in .3s ease both; }
  @keyframes vt-out { to { opacity: 0; transform: translateY(-8px); } }
  @keyframes vt-in  { from { opacity: 0; transform: translateY(10px); } }

  /* 按钮与链接：hover 提亮抬升、active 按压缩放 */
  button, .navlink, .tbtn, .back, .more { transition: transform .12s ease,
      box-shadow .2s ease, filter .18s ease, background-color .18s ease, opacity .18s ease; }
  button:hover, .navlink:hover, .tbtn:hover { filter: brightness(1.15); }
  button:active, .navlink:active, .back:active { transform: scale(.955); filter: brightness(.9); }
  .tbtn:active { transform: scale(.88) rotate(24deg); }
  button:disabled { opacity: .55; cursor: wait; filter: none; }
  .loginbox button:hover, .rowform button:hover { box-shadow: 0 3px 14px rgba(88,166,255,.35); }
  .rowform button.danger:hover, button.danger:hover { box-shadow: 0 3px 14px rgba(248,81,73,.4); }

  /* 入场：wrap 直接子元素瀑布上浮（--i 由脚本注入） */
  @keyframes rise { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }
  .wrap > * { animation: rise .4s ease both; animation-delay: calc(var(--i, 0) * 55ms); }

  /* 状态点呼吸 / 告警闪烁 */
  @keyframes dotpulse { 0% { box-shadow: 0 0 0 0 rgba(63,185,80,.55); }
    70% { box-shadow: 0 0 0 7px rgba(63,185,80,0); } 100% { box-shadow: 0 0 0 0 rgba(63,185,80,0); } }
  .dot.green { animation: dotpulse 2.2s ease-out infinite; }
  @keyframes dotalert { 0%,100% { box-shadow: 0 0 6px #f85149; } 50% { box-shadow: 0 0 13px 3px #f85149; } }
  .dot.red { animation: dotalert 1.2s ease-in-out infinite; }

  /* uptime 条：逐根生长 + hover 提亮 */
  @keyframes bargrow { from { transform: scaleY(0); } to { transform: scaleY(1); } }
  .bar { transform-origin: bottom; animation: bargrow .5s ease both;
         animation-delay: calc(var(--i, 0) * 7ms); }
  .bar { transition: filter .15s ease, transform .15s ease; }
  .bar:hover { filter: brightness(1.4); transform: scaleY(1.12); }

  /* 状态码分布条：从 0 填充到目标宽度 */
  @keyframes fillgrow { from { width: 0; } to { width: var(--w, 0%); } }
  .srow .fill { animation: fillgrow .8s .2s cubic-bezier(.2,.7,.3,1) both; }

  /* 表格行渐入 */
  table tr { animation: rise .35s ease both; animation-delay: calc(var(--i, 0) * 28ms); }

  /* 无障碍：用户偏好减少动效时全部关闭 */
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: .01ms !important;
      animation-delay: 0ms !important; transition-duration: .01ms !important; }
  }

  /* Cloudflare 横版 logo：按主题切换浅色/深色版（默认深色） */
  .cflogo { height:22px; width:auto; flex:none; }
  .cflogo-light { display:none; }
  html[data-theme="light"] .cflogo-light { display:block; }
  html[data-theme="light"] .cflogo-dark { display:none; }
`;

// 动效脚本：为瀑布/生长动画注入序号变量（--i）
const FX_JS = `
(function () {
  try {
    if (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    var groups = [
      [document.querySelectorAll(".wrap > *"), 1],
      [document.querySelectorAll(".bars .bar"), 1],
      [document.querySelectorAll(".srow .fill"), 1],
      [document.querySelectorAll("table tr")]
    ];
    groups.forEach(function (g) {
      var step = g[1] || 1;
      Array.prototype.forEach.call(g[0], function (el, i) {
        el.style.setProperty("--i", Math.floor(i * step));
      });
    });
  } catch (e) {}
})();
`;

const PAGE_CSS = `
  :root, html[data-theme="dark"] { --bg:#0d1117; --text:#c9d1d9; --muted:#8b949e;
    --border:#30363d; --title:#e6edf3; --link:#58a6ff; --nodata:#21262d; }
  html[data-theme="light"] { --bg:#ffffff; --text:#24292f; --muted:#57606a;
    --border:#d0d7de; --title:#24292f; --link:#0969da; --nodata:#eaeef2; }
  body { background:var(--bg); color:var(--text); font-family:ui-monospace,Consolas,monospace;
         margin:0; padding:36px 20px; transition:background .2s,color .2s; }
  .wrap { max-width:900px; margin:0 auto; }
  h1 { font-size:20px; color:var(--title); margin:0 0 6px; display:inline-block; }
  h2 { font-size:15px; color:var(--title); margin:30px 0 4px; }
  .sub { color:var(--muted); font-size:12px; margin-bottom:22px; }
  .tbtn { float:right; background:var(--nodata); color:var(--text);
          border:1px solid var(--border); border-radius:6px; padding:6px 12px;
          cursor:pointer; font-size:14px; }
  .back { color:var(--link); text-decoration:none; font-size:12px; }
  .nav { display:flex; align-items:center; gap:12px; margin:6px 0 18px; font-size:13px;
         flex-wrap:wrap; }
  .nav b { color:var(--title); }
  .navlink { color:var(--link); text-decoration:none; font-size:12px;
             border:1px solid var(--border); border-radius:6px; padding:3px 10px; }
  .navlink.dim { color:var(--muted); }
  .banner { padding:12px 18px; border-radius:8px; font-size:14px; margin-bottom:26px;
            border:1px solid; }
  .banner.ok  { color:#3fb950; border-color:#238636; background:rgba(35,134,54,.12); }
  .banner.bad { color:#f85149; border-color:#b62324; background:rgba(182,35,36,.12); }
  .comp { border:1px solid var(--border); border-radius:10px; padding:14px 16px;
          margin-bottom:16px; }
  .comp-head { display:flex; align-items:center; gap:8px; font-size:13px; margin-bottom:10px; }
  .comp-head b { color:var(--title); }
  .comp-head .right { margin-left:auto; color:var(--muted); font-size:12px; }
  .comp-head .right b { color:var(--text); }
  .comp-sub { color:var(--muted); font-size:11px; margin-top:8px; }
  .comp-sub b { color:var(--text); }
  .loginbox { display:flex; gap:10px; }
  .loginbox input { flex:1; padding:10px 12px; background:var(--nodata); color:var(--text);
                    border:1px solid var(--border); border-radius:6px; font-family:inherit; }
  .loginbox button, .rowform button { padding:10px 16px; background:var(--link); color:#fff;
                    border:none; border-radius:6px; cursor:pointer; font-family:inherit; }
  .rowform { display:flex; gap:8px; margin-top:10px; flex-wrap:wrap; }
  .rowform input { flex:1 1 160px; padding:8px 10px; background:var(--nodata);
                   color:var(--text); border:1px solid var(--border); border-radius:6px;
                   font-family:inherit; font-size:12px; }
  .rowform button.danger, button.danger { background:#b62324; }
  button.danger { padding:10px 16px; color:#fff; border:none; border-radius:6px;
                  cursor:pointer; font-family:inherit; }
  .sshout { background:var(--nodata); color:var(--text); padding:10px 12px;
            border-radius:6px; font-size:12px; white-space:pre-wrap;
            word-break:break-all; margin:0; }
  .more { color:var(--link); text-decoration:none; }
  .chartbox { margin-top:10px; border:1px solid var(--border); border-radius:8px;
              padding:10px 12px; }
  .chart-head { display:flex; justify-content:space-between; font-size:11px;
                color:var(--muted); margin-bottom:6px; flex-wrap:wrap; gap:4px; }
  .chart-head b { color:var(--text); }
  svg.lat { width:100%; height:130px; display:block; }
  .srow { display:flex; align-items:center; gap:8px; font-size:11px; margin-top:6px; }
  .srow .code { width:90px; color:var(--text); }
  .srow .track { flex:1; background:var(--nodata); border-radius:4px; height:12px;
                 overflow:hidden; }
  .srow .fill { height:100%; border-radius:4px; }
  .srow .cnt { width:100px; text-align:right; color:var(--muted); }
  .srow .code { white-space:nowrap; }
  .colo-badge { display:inline-block; padding:0 6px; border:1px solid; border-radius:4px;
                font-size:10px; font-weight:bold; line-height:18px; margin-right:4px; }
  /* 边缘节点行：比状态码行更宽松 */
  .srow.cololine { margin-top:14px; font-size:12px; align-items:center; }
  .srow.cololine .code { width:180px; display:inline-flex; align-items:center; white-space:nowrap; }
  .srow.cololine .track { height:14px; }
  .srow.cololine .cnt { width:150px; line-height:1.55; text-align:right; }
  .bars { display:flex; gap:2px; height:28px; align-items:stretch; }
  .bar { flex:1 1 0; min-width:2px; border-radius:2px; }
  .bar.up       { background:#2da44e; }
  .bar.degraded { background:#d4a72c; }
  .bar.down     { background:#cf222e; }
  .bar.nodata   { background:var(--nodata); }
  .bar-days { display:flex; justify-content:space-between; color:var(--muted);
              font-size:10px; margin-top:4px; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-top:10px; }
  th { text-align:left; color:var(--muted); font-weight:normal; padding:8px 10px;
       border-bottom:1px solid var(--border); }
  td { padding:10px; border-bottom:1px solid var(--border); }
  .url { color:var(--muted); font-size:11px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:4px; }
  .green { background:#3fb950; box-shadow:0 0 6px #3fb950; }
  .red   { background:#f85149; box-shadow:0 0 6px #f85149; }
  .gray  { background:#6e7681; }
  .red { color:#f85149; }
  .foot { margin-top:26px; color:var(--muted); font-size:11px; }
  a { color:var(--link); text-decoration:none; }
  /* 延迟曲线描边动画（pathLength=100 归一化） */
  @keyframes drawline { to { stroke-dashoffset: 0; } }
  svg.lat .lat-line { stroke-dasharray: 100; stroke-dashoffset: 100;
                      animation: drawline 1.1s .15s ease-out forwards; }
${FX_CSS}
`;

const THEME_JS = `
(function () {
  var root = document.documentElement;
  var saved = localStorage.getItem("theme");
  var theme = saved || (window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  root.dataset.theme = theme;
  var btn = document.getElementById("themeBtn");
  if (btn) btn.addEventListener("click", function () {
    theme = (root.dataset.theme === "dark") ? "light" : "dark";
    root.dataset.theme = theme;
    localStorage.setItem("theme", theme);
  });
})();
`;

function pageShell(title, content, extraHead = "") {
  return `<!doctype html>
<html lang="zh"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>${esc(title)} — uptime-monitor</title>
${extraHead}
<style>${PAGE_CSS}</style>
</head><body><div class="wrap">
<button class="tbtn" id="themeBtn" title="切换深浅色">🌓</button>
${content}
<div class="foot">powered by Cloudflare Workers · ${esc(new Date().toISOString())} ·
json: <a href="/api/status">/api/status</a></div>
</div>
<script>${THEME_JS}${FX_JS}</script>
</body></html>`;
}

// ---------- 管理后台 ----------

function htmlLogin(err, status = 200, showAccess = false) {
  const content = `
<h1>管理后台登录</h1>
<div class="sub">uptime-monitor · /diamond_dia</div>
${err ? `<div class="banner bad">${esc(err)}</div>` : ""}
<div class="comp">
  <form method="post" action="/diamond_dia/login" class="loginbox">
    <input type="password" name="password" placeholder="管理密码" required autocomplete="current-password">
    <button type="submit">登录</button>
  </form>
  ${showAccess ? `
  <div style="display:flex; align-items:center; gap:10px; margin-top:16px; color:var(--muted); font-size:11px">
    <span style="flex:1; height:1px; background:var(--border)"></span>或<span style="flex:1; height:1px; background:var(--border)"></span>
  </div>
  <div style="margin-top:14px; text-align:center">
    <a href="/diamond_dia/access" style="display:inline-flex; align-items:center; gap:8px; padding:8px 18px; border:1px solid var(--border); border-radius:8px; color:inherit; text-decoration:none; font-size:13px">
      <img src="${CF_LOGO_LIGHT}" class="cflogo cflogo-light" style="height:15px" alt="Cloudflare">
      <img src="${CF_LOGO_DARK}" class="cflogo cflogo-dark" style="height:15px" alt="Cloudflare">
      通过 Cloudflare Zero Trust 登录
    </a>
  </div>` : ""}
</div>`;
  return new Response(pageShell("Admin Login", content), {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function htmlAdmin(targets, env, msg, sshOut, timeoutMs = 8000, probeMode = "both") {
  const rows = targets.map((t) => `
    <div class="comp">
      <div class="comp-head"><b>${esc(t.name)}</b>
        <span class="right"><span class="url">${esc(t.url)}</span></span></div>
      <form method="post" action="/diamond_dia/targets/update" class="rowform">
        <input type="hidden" name="orig" value="${esc(t.name)}">
        <input name="name" value="${esc(t.name)}" required>
        <input name="url" value="${esc(t.url)}" required>
        <button type="submit">保存修改</button>
      </form>
      <form method="post" action="/diamond_dia/targets/delete" class="rowform">
        <input type="hidden" name="name" value="${esc(t.name)}">
        <button type="submit" class="danger">删除</button>
      </form>
    </div>`).join("\n");

  const content = `
<h1>管理后台</h1>
<div class="sub"><a class="back" href="/">← 返回状态页</a> · /diamond_dia</div>
${msg ? `<div class="banner ok">${esc(msg)}</div>` : ""}
${sshOut ? `<div class="banner bad"><pre class="sshout">${esc(sshOut)}</pre></div>` : ""}
<div class="comp">
  <div class="comp-head"><b>重启 X-ui</b>
    <span class="right">https://${esc(env.SSH_HOST || "")}:${esc(env.SSH_PORT || "39332")} · 浏览器直连</span></div>
  <button type="button" class="danger" id="restartBtn">重启 X-ui（x-ui restart）</button>
  <pre class="sshout" id="restartOut" style="display:none"></pre>
</div>
<h2>探测设置</h2>
<div class="comp">
  <div class="comp-head"><b>探测超时</b>
    <span class="right">当前 ${esc(String(timeoutMs / 1000))} 秒</span></div>
  <form method="post" action="/diamond_dia/timeout/set" class="rowform">
    <input type="number" name="seconds" min="1" max="30" step="1" value="${esc(String(timeoutMs / 1000))}" required>
    <button type="submit">保存超时</button>
  </form>
</div>
<div class="comp">
  <div class="comp-head"><b>探测来源</b>
    <span class="right">当前 ${esc(PROBE_LABELS[probeMode] || probeMode)}</span></div>
  <form method="post" action="/diamond_dia/probes/set" class="rowform">
    <button type="submit" name="mode" value="worker"${probeMode === "worker" ? ' style="outline:2px solid #3fb950"' : ""}>仅 Worker（CF 边缘）</button>
    <button type="submit" name="mode" value="home"${probeMode === "home" ? ' style="outline:2px solid #3fb950"' : ""}>仅 Home（家宽节点）</button>
    <button type="submit" name="mode" value="both"${probeMode === "both" ? ' style="outline:2px solid #3fb950"' : ""}>两者同时</button>
  </form>
  <div class="comp-sub">仅 Worker：家宽上报将被拒绝 · 仅 Home：Worker 暂停探测与告警（告警由 Worker 视角触发，此时无告警）· 总览统计跟随所选来源的主视角</div>
</div>
<h2>监控项管理（${targets.length}）</h2>
${rows}
<h2>添加监控项</h2>
<div class="comp">
  <form method="post" action="/diamond_dia/targets/add" class="rowform">
    <input name="name" placeholder="名称" required>
    <input name="url" placeholder="https://example.com" required>
    <button type="submit">添加</button>
  </form>
</div>
<form method="post" action="/diamond_dia/logout"><button type="submit">退出登录</button></form>`;

  // 前端：重启按钮 → 先向本 Worker 取短时密钥（校验 admin cookie）→ 浏览器直连 VPS:39332 调重启 API
  const adminScript = `
<script>
document.addEventListener("DOMContentLoaded", function () {
  var mr = document.querySelector('meta[http-equiv="refresh"]');
  if (mr) mr.remove();
  function esc2(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  var btn = document.getElementById("restartBtn");
  if (btn) btn.addEventListener("click", async function () {
    var out = document.getElementById("restartOut");
    btn.disabled = true; btn.textContent = "重启中…";
    out.style.display = "block"; out.textContent = "正在获取密钥…";
    try {
      var res = await fetch("/diamond_dia/action/xui-restart", { method: "POST" });
      var j = await res.json();
      if (!j.ok) { out.textContent = "获取密钥失败: " + (j.error || res.status); return; }
      out.textContent = "正在直连 VPS " + j.vpsUrl + " …";
      var r2 = await fetch(j.vpsUrl + "/restart", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ts: j.ts, key: j.key })
      });
      var t = await r2.text();
      var rj = null; try { rj = JSON.parse(t); } catch (e) {}
      if (rj && rj.ok) out.textContent = "重启成功（exit " + rj.code + "）:\\n" + esc2(rj.output || "");
      else out.textContent = "重启失败: " + (rj && rj.error ? rj.error : t);
    } catch (e) {
      out.textContent = "异常: " + (e && e.message ? e.message : e);
    } finally {
      btn.disabled = false; btn.textContent = "重启 X-ui（x-ui restart）";
    }
  });
});
</script>`;

  return new Response(pageShell("Admin", content, adminScript), {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

async function handleAdmin(request, env, url) {
  const path = url.pathname;
  const sub = path === "/diamond_dia" ? "/" : path.slice("/diamond_dia".length);

  // Zero Trust 登录入口：Access 应用仅拦截此路径。邮箱 OTP 通过后边缘注入
  // Cf-Access-Jwt-Assertion，验证通过即签发与密码登录一致的 admin cookie——
  // 两种登录方式并存，密码登录不受任何影响。
  if (sub === "/access" && request.method === "GET") {
    const at = request.headers.get("cf-access-jwt-assertion");
    const email = (at && env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD) ? await verifyAccessJWT(env, at) : null;
    if (email && env.ADMIN_PASSWORD) {
      const token = await adminToken(env);
      return new Response(null, {
        status: 302,
        headers: {
          "set-cookie": `admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`,
          location: "/diamond_dia",
        },
      });
    }
    // OTP 刚完成时的首次回跳，边缘会话可能尚未同步而缺失 JWT 头：带计数自动重试
    //（1 秒/次，最多 3 次）；已带 JWT 但验证失败（未授权邮箱等）则直接回登录页，不重试。
    const retry = Math.min(Number(url.searchParams.get("r") || "0") || 0, 3);
    if (!at && retry < 3) {
      return new Response(
        `<!doctype html><meta charset="utf-8"><title>登录中…</title><meta http-equiv="refresh" content="1;url=/diamond_dia/access?r=${retry + 1}"><body style="font-family:system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;color:#8b949e;background:#0d1117">正在完成 Zero Trust 登录…</body>`,
        { headers: { "content-type": "text/html; charset=utf-8" } }
      );
    }
    return new Response(null, { status: 302, headers: { location: "/diamond_dia" } });
  }

  if (sub === "/" && request.method === "GET") {
    if (await isAdmin(request, env)) {
      return htmlAdmin(await getTargets(env), env, "", "", await getTimeoutMs(env), await getProbeMode(env));
    }
    return htmlLogin("", 200, !!(env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD));
  }

  if (sub === "/login" && request.method === "POST") {
    const form = await request.formData();
    const pw = String(form.get("password") || "");
    if (!env.ADMIN_PASSWORD || pw !== env.ADMIN_PASSWORD) {
      return htmlLogin("密码错误", 401);
    }
    const token = await adminToken(env);
    return new Response(null, {
      status: 302,
      headers: {
        "set-cookie": `admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`,
        location: "/diamond_dia",
      },
    });
  }

  if (sub === "/logout" && request.method === "POST") {
    return new Response(null, {
      status: 302,
      headers: {
        "set-cookie": "admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
        location: "/diamond_dia",
      },
    });
  }

  if (!(await isAdmin(request, env))) return htmlLogin("请先登录", 401);

  const targets = await getTargets(env);
  const timeoutMs = await getTimeoutMs(env);
  const probeMode = await getProbeMode(env);
  let form = null;
  if (request.method === "POST") {
    try { form = await request.formData(); } catch (_) { form = null; }
  }

  if (sub === "/targets/add" && form) {
    const name = String(form.get("name") || "").trim();
    const turl = String(form.get("url") || "").trim();
    if (!name || !/^https?:\/\//.test(turl)) return htmlAdmin(targets, env, "添加失败：名称和 http(s) URL 都必填", "", timeoutMs, probeMode);
    if (targets.some((t) => t.name === name)) return htmlAdmin(targets, env, "添加失败：同名监控项已存在", "", timeoutMs, probeMode);
    targets.push({ name, url: turl });
    await env.KV.put("targets", JSON.stringify(targets));
    return htmlAdmin(targets, env, `已添加 ${name}`, "", timeoutMs, probeMode);
  }

  if (sub === "/targets/delete" && form) {
    const name = String(form.get("name") || "");
    const next = targets.filter((t) => t.name !== name);
    await env.KV.put("targets", JSON.stringify(next));
    return htmlAdmin(next, env, `已删除 ${name}（历史数据保留在数据库中）`, "", timeoutMs, probeMode);
  }

  if (sub === "/targets/update" && form) {
    const orig = String(form.get("orig") || "");
    const name = String(form.get("name") || "").trim();
    const turl = String(form.get("url") || "").trim();
    const i = targets.findIndex((t) => t.name === orig);
    if (i < 0 || !name || !/^https?:\/\//.test(turl)) return htmlAdmin(targets, env, "修改失败：参数不完整", "", timeoutMs, probeMode);
    if (name !== orig && targets.some((t) => t.name === name)) return htmlAdmin(targets, env, "修改失败：同名监控项已存在", "", timeoutMs, probeMode);
    targets[i] = { name, url: turl };
    await env.KV.put("targets", JSON.stringify(targets));
    return htmlAdmin(targets, env, `已更新 ${orig} → ${name}（旧名历史数据保留）`, "", timeoutMs, probeMode);
  }

  if (sub === "/timeout/set" && form) {
    const sec = parseInt(String(form.get("seconds") || ""), 10);
    if (!sec || sec < 1 || sec > 30) return htmlAdmin(targets, env, "设置失败：超时需为 1-30 的整数秒", "", timeoutMs, probeMode);
    await env.KV.put("config:timeout_ms", String(sec * 1000));
    return htmlAdmin(targets, env, `探测超时已设为 ${sec} 秒（下一轮探测生效）`, "", sec * 1000, probeMode);
  }

  if (sub === "/probes/set" && form) {
    const mode = String(form.get("mode") || "");
    if (!["worker", "home", "both"].includes(mode)) {
      return htmlAdmin(targets, env, "设置失败：未知探测来源", "", timeoutMs, probeMode);
    }
    await env.KV.put("config:probes", mode);
    return htmlAdmin(targets, env, `探测来源已切换为「${PROBE_LABELS[mode]}」（下一轮探测生效）`, "", timeoutMs, mode);
  }

  if (sub === "/action/xui-restart" && request.method === "POST") {
    // 管理员已登录（line 574 已校验 cookie）：签发短时密钥，前端拿到后直连 VPS 调重启 API
    if (!env.RESTART_KEY) return json({ ok: false, error: "RESTART_KEY 未配置（wrangler secret put RESTART_KEY）" }, 500);
    const { ts, key } = await issueRestartKey(env);
    return json({ ok: true, ts, key, vpsUrl: restartVpsUrl(env), expiresIn: 60 });
  }

  return htmlLogin("未知操作", 404);
}

// ---------- 目标详情页 ----------

async function buildTargetDetail(env, name, offset = 0) {
  const t = (await getTargets(env)).find((x) => x.name === name);
  const endTs = Math.floor(Date.now() / 1000) - offset * VIEW_DAYS * 86400;
  const startTs = endTs - VIEW_DAYS * 86400;

  const raw = await env.KV.get("state:" + name);
  const latest = raw ? JSON.parse(raw) : null;

  // 90d 逐日（uptime 主条以 CF 边缘视角为准）
  const per = {};
  try {
    const { results } = await env.DB.prepare(
      `SELECT date(ts,'unixepoch','+8 hours') AS d, COUNT(*) AS total, SUM(ok) AS up
       FROM checks WHERE target = ? AND ts >= ? AND ts < ? AND probe = 'cf' GROUP BY d`
    ).bind(name, startTs, endTs).all();
    for (const r of results) per[r.d] = { total: r.total, up: r.up };
  } catch (_) {}

  const days = [];
  for (let i = VIEW_DAYS - 1; i >= 0; i--) {
    days.push(new Date((endTs - i * 86400 + 8 * 3600) * 1000).toISOString().slice(0, 10));
  }
  let wTotal = 0, wUp = 0;
  const dayStats = days.map((d) => {
    const st = per[d];
    if (!st || !st.total) return { d, cls: "nodata", checks: 0, up: null, ratio: null };
    const ratio = st.up / st.total;
    wTotal += st.total;
    wUp += st.up;
    const cls = ratio >= 0.999 ? "up" : ratio >= 0.95 ? "degraded" : "down";
    return { d, cls, checks: st.total, up: st.up, ratio };
  });

  // 24h 统计（CF 与家宽视角分开算）
  const statsBy = { cf: null, home: null };
  try {
    const { results } = await env.DB.prepare(
      "SELECT probe, COUNT(*) AS total, SUM(ok) AS up, CAST(AVG(latency_ms) AS INTEGER) AS avg_latency FROM checks WHERE target = ? AND ts > strftime('%s','now') - 86400 GROUP BY probe"
    ).bind(name).all();
    for (const row of results) {
      const key = row.probe === "home" ? "home" : "cf";
      statsBy[key] = row;
    }
  } catch (_) {}
  const st = statsBy.cf;
  const stHome = statsBy.home;

  // 24h 明细点 + 状态码（按来源分组，两条曲线分隔展示）
  let detail = { points: [], counts: {}, pointsHome: [], countsHome: {} };
  try {
    const { results } = await env.DB.prepare(
      "SELECT ts, ok, status, latency_ms, error, probe FROM checks WHERE target = ? AND ts > strftime('%s','now') - 86400 ORDER BY ts"
    ).bind(name).all();
    const mkCounts = (rows) => {
      const counts = {};
      for (const r of rows) {
        const code = r.status && r.status > 0 ? String(r.status) : "timeout";
        counts[code] = (counts[code] || 0) + 1;
      }
      return counts;
    };
    const cfRows = results.filter((r) => (r.probe || "cf") === "cf");
    const homeRows = results.filter((r) => r.probe === "home");
    detail = { points: cfRows, counts: mkCounts(cfRows), pointsHome: homeRows, countsHome: mkCounts(homeRows) };
  } catch (_) {}

  // 24h 边缘节点（colo）分布：仅统计 CF 视角且记录到 colo 的行
  let coloStats = [];
  try {
    const { results } = await env.DB.prepare(
      "SELECT colo, COUNT(*) AS n, SUM(ok) AS up, CAST(AVG(latency_ms) AS INTEGER) AS avg_latency FROM checks WHERE target = ? AND ts > strftime('%s','now') - 86400 AND probe = 'cf' AND colo != '' GROUP BY colo ORDER BY n DESC"
    ).bind(name).all();
    coloStats = results;
  } catch (_) {}

  // 最近 20 条原始记录
  let recent = [];
  try {
    const { results } = await env.DB.prepare(
      "SELECT ts, ok, status, latency_ms, error, probe FROM checks WHERE target = ? ORDER BY ts DESC LIMIT 20"
    ).bind(name).all();
    recent = results;
  } catch (_) {}

  return {
    name,
    url: t.url,
    latest,
    dayStats,
    range: { start: days[0], end: days[days.length - 1], offset, days: VIEW_DAYS },
    uptimeWindow: wTotal ? (wUp * 100 / wTotal).toFixed(2) : null,
    uptime24h: st ? (st.up * 100 / st.total).toFixed(2) : null,
    avg_latency: st ? st.avg_latency : null,
    checks24h: st ? st.total : 0,
    uptime24hHome: stHome ? (stHome.up * 100 / stHome.total).toFixed(2) : null,
    avg_latency_home: stHome ? stHome.avg_latency : null,
    checks24hHome: stHome ? stHome.total : 0,
    coloStats,
    detail,
    recent,
  };
}

function htmlTarget(data, name) {
  const up = data.latest ? data.latest.ok : null;
  const dot = up === null ? '<span class="dot gray"></span>'
    : up ? '<span class="dot green"></span>' : '<span class="dot red"></span>';
  const state = up === null ? "waiting" : up ? "UP" : "DOWN";
  const banner = up === null
    ? '<div class="banner ok">● WAITING FOR FIRST CHECK</div>'
    : up ? '<div class="banner ok">● TARGET OPERATIONAL</div>'
         : '<div class="banner bad">● TARGET DOWN</div>';

  const bars = data.dayStats.map((d) => {
    const tip = d.checks
      ? `${d.d} · ${d.checks} checks · ${(d.ratio * 100).toFixed(1)}% up`
      : `${d.d} · no data`;
    return `<span class="bar ${d.cls}" title="${tip}"></span>`;
  }).join("");
  const labels = `<div class="bar-days"><span>${esc(data.dayStats[0].d)}</span><span>${esc(data.dayStats[Math.floor(data.dayStats.length / 2)].d)}</span><span>${esc(data.dayStats[data.dayStats.length - 1].d)}</span></div>`;

  const recentRows = data.recent.map((r) => {
    const cn = new Date((r.ts + 8 * 3600) * 1000).toISOString().replace("T", " ").slice(0, 19);
    const cls = r.ok ? "green" : "red";
    const probe = r.probe === "home"
      ? '<span style="color:#d4a72c">家宽</span>'
      : '<span style="color:var(--muted)">CF</span>';
    return `<tr>
      <td>${cn}</td>
      <td>${probe}</td>
      <td><span class="dot ${cls}"></span>${r.ok ? "up" : "down"}</td>
      <td>${r.status || "—"}</td>
      <td>${r.latency_ms != null ? r.latency_ms + " ms" : "—"}</td>
      <td class="url">${esc(r.error || "")}</td>
    </tr>`;
  }).join("");

  const o = data.range.offset;
  const older = `<a class="navlink" href="?offset=${o + 1}">‹ 更早</a>`;
  const newer = o > 0
    ? `<a class="navlink" href="?offset=${o - 1}">更新 ›</a> <a class="navlink" href="/target/${encodeURIComponent(name)}">最新</a>`
    : '<span class="navlink dim">最新</span>';

  const content = `
<h1>${esc(name)}</h1> ${dot} <b class="${up === false ? "red" : ""}" style="font-size:16px">${state}</b>
<div class="sub"><a class="back" href="/">← 返回总览</a> · <span class="url">${esc(data.url)}</span></div>
${banner}
<div class="nav">
  <b>90 天可用率</b> <b>${data.uptimeWindow !== null ? esc(data.uptimeWindow) + "%" : "no data"}</b>
  ${older}
  <span>${esc(data.range.start)} ~ ${esc(data.range.end)}（北京时间）</span>
  ${newer}
</div>
<div class="comp">
  <div class="bars">${bars}</div>
  ${labels}
</div>
<h2>延迟曲线（24h · 真实 HTTP 请求往返）</h2>
<div class="comp-sub" style="margin:0 0 6px"><b>① Cloudflare 边缘视角</b>${data.checks24h ? ` · ${data.checks24h} 次 · 24h 可用率 ${data.uptime24h}%` : " · 数据积累中"}</div>
${latencySVG(data.detail.points)}
<div class="comp-sub" style="margin:16px 0 6px"><b>② 家宽视角（diana PC · 国内真实访问）</b>${data.checks24hHome ? ` · ${data.checks24hHome} 次 · 24h 可用率 ${data.uptime24hHome}%` : " · 暂无数据（家宽节点仅探测远程目标）"}</div>
${data.detail.pointsHome.length ? latencySVG(data.detail.pointsHome) : '<div class="comp-sub">家宽数据积累中…</div>'}
<h2>HTTP 状态码分布（24h）</h2>
<div class="comp-sub" style="margin:0 0 6px"><b>① Cloudflare 边缘</b></div>
<div class="chartbox">${statusBarsHTML(data.detail.counts, data.detail.points.length)}</div>
${data.detail.pointsHome.length ? `<div class="comp-sub" style="margin:16px 0 6px"><b>② 家宽视角</b></div><div class="chartbox">${statusBarsHTML(data.detail.countsHome, data.detail.pointsHome.length)}</div>` : ""}
<h2>边缘节点分布（24h · Cloudflare 数据中心）</h2>
<div class="comp-sub" style="margin:0 0 6px">Worker cron 每次可能落在不同边缘节点，此处按探测所落数据中心聚合 · 颜色区分大洲</div>
<div class="chartbox">${edgeNodesHTML(data.coloStats)}</div>
<h2>最近 20 次探测</h2>
<table>
<tr><th>时间（北京）</th><th>来源</th><th>结果</th><th>HTTP 码</th><th>延迟</th><th>错误</th></tr>
${recentRows}
</table>`;

  return new Response(pageShell(name, content), {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

// ---------- 图表（无依赖，服务端渲染 SVG/HTML） ----------

function latencySVG(points, w = 720, h = 130) {
  const ok = points.filter((p) => p.ok && p.latency_ms > 0);
  if (ok.length < 2) return '<div class="comp-sub">延迟曲线数据积累中（至少需要 2 个成功探测点）</div>';

  const t0 = points[0].ts;
  const t1 = Math.max(points[points.length - 1].ts, t0 + 1);
  const lats = ok.map((p) => p.latency_ms);
  const sorted = [...lats].sort((a, b) => a - b);
  const peak = sorted[sorted.length - 1];
  const avg = Math.round(lats.reduce((a, b) => a + b, 0) / lats.length);
  const yMax = Math.max(sorted[Math.floor(sorted.length * 0.97)], Math.round(avg * 1.5), 10);

  const px = (ts) => 2 + ((ts - t0) / (t1 - t0)) * (w - 4);
  const py = (v) => h - 14 - (Math.min(v, yMax) / yMax) * (h - 30);

  let line = "";
  let area = `M ${px(points[0].ts).toFixed(1)},${h - 14}`;
  for (const p of ok) {
    const X = px(p.ts).toFixed(1), Y = py(p.latency_ms).toFixed(1);
    line += (line ? " L " : "M ") + X + "," + Y;
    area += " L " + X + "," + Y;
  }
  area += ` L ${px(points[points.length - 1].ts).toFixed(1)},${h - 14} Z`;

  const avgY = py(avg).toFixed(1);
  const fails = points.filter((p) => !p.ok).map((p) =>
    `<circle cx="${px(p.ts).toFixed(1)}" cy="${h - 14}" r="3" fill="#f85149" />`).join("");

  return `<div class="chartbox">
    <div class="chart-head">
      <span>均值 <b>${avg} ms</b></span>
      <span>${ok.length} 次成功探测 · 24h · 真实 HTTP 请求往返</span>
      <span>峰值 <b>${peak} ms</b></span>
    </div>
    <svg class="lat" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <line x1="0" y1="${h - 14}" x2="${w}" y2="${h - 14}" stroke="var(--border)" stroke-width="1"/>
      <line x1="0" y1="${avgY}" x2="${w}" y2="${avgY}" stroke="var(--muted)" stroke-width="1" stroke-dasharray="4 4"/>
      <path d="${area}" fill="rgba(88,166,255,.18)"/>
      <path class="lat-line" pathLength="100" d="${line}" fill="none" stroke="#58a6ff" stroke-width="1.6" vector-effect="non-scaling-stroke"/>
      ${fails}
      <text x="4" y="${Number(avgY) - 4}" fill="var(--muted)" font-size="10">avg ${avg} ms</text>
      <text x="${w - 60}" y="12" fill="var(--muted)" font-size="10">peak ${peak} ms</text>
    </svg>
  </div>`;
}

// IATA 机场码 → [城市, 大洲代码]；CF 边缘节点覆盖于此，未收录的显示 IATA 原码
const COLO_META = {
  SIN: ["新加坡", "AS"], HKG: ["香港", "AS"], TPE: ["台北", "AS"], NRT: ["东京", "AS"],
  KIX: ["大阪", "AS"], ICN: ["首尔", "AS"], PVG: ["上海", "AS"], PEK: ["北京", "AS"],
  KUL: ["吉隆坡", "AS"], BKK: ["曼谷", "AS"], MNL: ["马尼拉", "AS"], CGK: ["雅加达", "AS"],
  BOM: ["孟买", "AS"], MAA: ["金奈", "AS"], DEL: ["德里", "AS"], DAC: ["达卡", "AS"],
  CMB: ["科伦坡", "AS"], HAN: ["河内", "AS"], SGN: ["胡志明市", "AS"],
  FRA: ["法兰克福", "EU"], AMS: ["阿姆斯特丹", "EU"], LHR: ["伦敦", "EU"], CDG: ["巴黎", "EU"],
  DUB: ["都柏林", "EU"], MAD: ["马德里", "EU"], MXP: ["米兰", "EU"], ZRH: ["苏黎世", "EU"],
  ARN: ["斯德哥尔摩", "EU"], WAW: ["华沙", "EU"], VIE: ["维也纳", "EU"], CPH: ["哥本哈根", "EU"],
  LAX: ["洛杉矶", "NA"], SJC: ["圣何塞", "NA"], SEA: ["西雅图", "NA"], ORD: ["芝加哥", "NA"],
  DFW: ["达拉斯", "NA"], IAD: ["华盛顿", "NA"], ATL: ["亚特兰大", "NA"], MIA: ["迈阿密", "NA"],
  EWR: ["纽瓦克", "NA"], JFK: ["纽约", "NA"], YYZ: ["多伦多", "NA"], YVR: ["温哥华", "NA"],
  MEX: ["墨西哥城", "NA"], PHX: ["凤凰城", "NA"], DEN: ["丹佛", "NA"], SLC: ["盐湖城", "NA"],
  GRU: ["圣保罗", "SA"], EZE: ["布宜诺斯艾利斯", "SA"], SCL: ["圣地亚哥", "SA"], BOG: ["波哥大", "SA"],
  LIM: ["利马", "SA"], GIG: ["里约热内卢", "SA"],
  JNB: ["约翰内斯堡", "AF"], CPT: ["开普敦", "AF"], NBO: ["内罗毕", "AF"], CAI: ["开罗", "AF"],
  LOS: ["拉各斯", "AF"], CMN: ["卡萨布兰卡", "AF"],
  SYD: ["悉尼", "OC"], MEL: ["墨尔本", "OC"], AKL: ["奥克兰", "OC"], PER: ["珀斯", "OC"], BNE: ["布里斯班", "OC"],
};
const CONTINENT = { AS: "亚洲", EU: "欧洲", NA: "北美", SA: "南美", AF: "非洲", OC: "大洋洲" };
const CONTINENT_COLOR = { AS: "#58a6ff", EU: "#a371f7", NA: "#3fb950", SA: "#d4a72c", AF: "#f0883e", OC: "#39c5cf" };

// 边缘节点分布条：复用 srow 设计语言，徽章色按大洲
function edgeNodesHTML(coloStats) {
  if (!coloStats.length) return '<div class="comp-sub">节点数据积累中（仅统计经过 Cloudflare 代理的目标）</div>';
  const total = coloStats.reduce((a, b) => a + b.n, 0);
  return coloStats.map((s) => {
    const meta = COLO_META[s.colo] || [s.colo, ""];
    const cont = CONTINENT[meta[1]] || "未知";
    const color = CONTINENT_COLOR[meta[1]] || "#6e7681";
    const pct = (s.n * 100 / total).toFixed(1);
    const upPct = (s.up * 100 / s.n).toFixed(1);
    return `<div class="srow cololine">
      <span class="code"><span class="colo-badge" style="color:${color};border-color:${color}">${s.colo}</span> ${esc(meta[0])}<span style="color:var(--muted)"> · ${cont}</span></span>
      <div class="track"><div class="fill" style="--w:${pct}%;width:${pct}%;background:${color}"></div></div>
      <span class="cnt">${s.n} 次 · ${pct}%<br>${s.avg_latency} ms · up ${upPct}%</span>
    </div>`;
  }).join("");
}

function statusBarsHTML(counts, total) {
  if (!total) return '<div class="comp-sub">状态码数据积累中</div>';
  const color = (code) => code === "timeout" ? "#8b949e"
    : code[0] === "2" ? "#3fb950"
    : code[0] === "3" ? "#58a6ff"
    : code[0] === "4" ? "#d4a72c" : "#f85149";
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([code, n]) => {
    const pct = (n * 100 / total).toFixed(1);
    const label = code === "timeout" ? "超时/断连" : "HTTP " + code;
    return `<div class="srow">
      <span class="code">${label}</span>
      <div class="track"><div class="fill" style="--w:${pct}%;width:${pct}%;background:${color(code)}"></div></div>
      <span class="cnt">${n} 次 · ${pct}%</span>
    </div>`;
  }).join("");
}

function html(data) {
  // 每个目标的逐日 uptime 条 + 详情表
  const sections = data.targets.map((t) => {
    const up = t.latest ? t.latest.ok : null;
    const dot = up === null ? '<span class="dot gray"></span>'
      : up ? '<span class="dot green"></span>' : '<span class="dot red"></span>';
    const state = up === null ? "waiting" : up ? "UP" : "DOWN";

    const bars = t.dayStats.map((d) => {
      const tip = d.checks
        ? `${d.d} · ${d.checks} checks · ${(d.ratio * 100).toFixed(1)}% up`
        : `${d.d} · no data`;
      return `<span class="bar ${d.cls}" title="${tip}"></span>`;
    }).join("");
    const labels = `<div class="bar-days"><span>${esc(t.dayStats[0].d)}</span><span>${esc(t.dayStats[Math.floor(t.dayStats.length / 2)].d)}</span><span>${esc(t.dayStats[t.dayStats.length - 1].d)}</span></div>`;

    return `<div class="comp">
      <div class="comp-head">
        ${dot} <b><a href="/target/${encodeURIComponent(t.name)}">${esc(t.name)}</a></b>
        <span class="right">${t.uptimeWindow !== null ? `<b>${esc(t.uptimeWindow)}%</b> uptime` : "no data yet"}</span>
      </div>
      <div class="bars">${bars}</div>
      ${labels}
      <div class="comp-sub">当前 <b class="${up === false ? "red" : ""}">${state}</b> · 最近延迟 ${t.latest ? t.latest.latency + " ms" : "—"} · 24h 可用率 ${t.uptime24h !== null ? t.uptime24h + "%" : "—"} · <a class="more" href="/target/${encodeURIComponent(t.name)}">详情曲线 →</a></div>
    </div>`;
  }).join("\n");

  const rows = data.targets.map((t) => {
    const up = t.latest ? t.latest.ok : null;
    const dot = up === null ? '<span class="dot gray"></span>'
      : up ? '<span class="dot green"></span>' : '<span class="dot red"></span>';
    const state = up === null ? "waiting" : up ? "UP" : "DOWN";
    const lat = t.latest ? `${t.latest.latency} ms` : "—";
    return `<tr>
      <td>${esc(t.name)}</td>
      <td class="url">${esc(t.url)}</td>
      <td>${dot} <b class="${up === false ? "red" : ""}">${state}</b></td>
      <td>${lat}</td>
      <td>${t.uptime24h !== null ? t.uptime24h + "%" : "—"}</td>
      <td>${t.avg_latency !== null ? t.avg_latency + " ms" : "—"}</td>
    </tr>`;
  }).join("\n");

  const allUp = data.targets.length > 0 && data.targets.every((t) => t.latest?.ok);
  const banner = allUp
    ? '<div class="banner ok">● ALL SYSTEMS OPERATIONAL</div>'
    : '<div class="banner bad">● INCIDENT IN PROGRESS</div>';


  const o = data.range.offset;
  const older = `<a class="navlink" href="?offset=${o + 1}">‹ 更早</a>`;
  const newer = o > 0
    ? `<a class="navlink" href="?offset=${o - 1}">更新 ›</a> <a class="navlink" href="/">最新</a>`
    : '<span class="navlink dim">最新</span>';

  const page = `<!doctype html>
<html lang="zh"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>Home Lab Status — uptime-monitor</title>
<style>
  :root, html[data-theme="dark"] { --bg:#0d1117; --text:#c9d1d9; --muted:#8b949e;
    --border:#30363d; --title:#e6edf3; --link:#58a6ff; --nodata:#21262d; }
  html[data-theme="light"] { --bg:#ffffff; --text:#24292f; --muted:#57606a;
    --border:#d0d7de; --title:#24292f; --link:#0969da; --nodata:#eaeef2; }
  body { background:var(--bg); color:var(--text); font-family:ui-monospace,Consolas,monospace;
         margin:0; padding:36px 20px; transition:background .2s,color .2s; }
  .wrap { max-width:900px; margin:0 auto; }
  h1 { font-size:20px; color:var(--title); margin:0 0 6px; display:inline-block; }
  .sub { color:var(--muted); font-size:12px; margin-bottom:22px; }
  .tbtn { float:right; background:var(--card,var(--nodata)); color:var(--text);
          border:1px solid var(--border); border-radius:6px; padding:6px 12px;
          cursor:pointer; font-size:14px; }
  .nav { display:flex; align-items:center; gap:12px; margin:6px 0 18px; font-size:13px; }
  .nav b { color:var(--title); }
  .navlink { color:var(--link); text-decoration:none; font-size:12px;
             border:1px solid var(--border); border-radius:6px; padding:3px 10px; }
  .navlink.dim { color:var(--muted); }
  .banner { padding:12px 18px; border-radius:8px; font-size:14px; margin-bottom:26px;
            border:1px solid; }
  .banner.ok  { color:#3fb950; border-color:#238636; background:rgba(35,134,54,.12); }
  .banner.bad { color:#f85149; border-color:#b62324; background:rgba(182,35,36,.12); }
  .comp { border:1px solid var(--border); border-radius:10px; padding:14px 16px;
          margin-bottom:16px; background:transparent; }
  .comp-head { display:flex; align-items:center; gap:8px; font-size:13px; margin-bottom:10px; }
  .comp-head b { color:var(--title); }
  .comp-head .right { margin-left:auto; color:var(--muted); font-size:12px; }
  .comp-head .right b { color:var(--text); }
  .comp-sub { color:var(--muted); font-size:11px; margin-top:8px; }
  .comp-sub b { color:var(--text); }
  details.detail { margin-top:10px; }
  details.detail summary { cursor:pointer; color:var(--link); font-size:12px;
                           user-select:none; list-style:none; }
  details.detail summary::before { content:"▸ "; }
  details.detail[open] summary::before { content:"▾ "; }
  .chartbox { margin-top:10px; border:1px solid var(--border); border-radius:8px;
              padding:10px 12px; }
  .chart-head { display:flex; justify-content:space-between; font-size:11px;
                color:var(--muted); margin-bottom:6px; }
  .chart-head b { color:var(--text); }
  svg.lat { width:100%; height:120px; display:block; }
  .srow { display:flex; align-items:center; gap:8px; font-size:11px; margin-top:6px; }
  .srow .code { width:90px; color:var(--text); }
  .srow .track { flex:1; background:var(--nodata); border-radius:4px; height:12px;
                 overflow:hidden; }
  .srow .fill { height:100%; border-radius:4px; }
  .srow .cnt { width:100px; text-align:right; color:var(--muted); }
  .srow .code { white-space:nowrap; }
  .colo-badge { display:inline-block; padding:0 6px; border:1px solid; border-radius:4px;
                font-size:10px; font-weight:bold; line-height:18px; margin-right:4px; }
  /* 边缘节点行：比状态码行更宽松 */
  .srow.cololine { margin-top:14px; font-size:12px; align-items:center; }
  .srow.cololine .code { width:180px; display:inline-flex; align-items:center; white-space:nowrap; }
  .srow.cololine .track { height:14px; }
  .srow.cololine .cnt { width:150px; line-height:1.55; text-align:right; }
  .bars { display:flex; gap:2px; height:28px; align-items:stretch; }
  .bar { flex:1 1 0; min-width:2px; border-radius:2px; }
  .bar.up       { background:#2da44e; }
  .bar.degraded { background:#d4a72c; }
  .bar.down     { background:#cf222e; }
  .bar.nodata   { background:var(--nodata); }
  .bar-days { display:flex; justify-content:space-between; color:var(--muted);
              font-size:10px; margin-top:4px; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-top:10px; }
  th { text-align:left; color:var(--muted); font-weight:normal; padding:8px 10px;
       border-bottom:1px solid var(--border); }
  td { padding:10px; border-bottom:1px solid var(--border); }
  .url { color:var(--muted); font-size:11px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:4px; }
  .green { background:#3fb950; box-shadow:0 0 6px #3fb950; }
  .red   { background:#f85149; box-shadow:0 0 6px #f85149; }
  .gray  { background:#6e7681; }
  .red { color:#f85149; }
  .foot { margin-top:26px; color:var(--muted); font-size:11px; }
  a { color:var(--link); text-decoration:none; }
  h2 { font-size:15px; color:var(--title); margin:30px 0 4px; }
  /* 延迟曲线描边动画（pathLength=100 归一化） */
  @keyframes drawline { to { stroke-dashoffset: 0; } }
  svg.lat .lat-line { stroke-dasharray: 100; stroke-dashoffset: 100;
                      animation: drawline 1.1s .15s ease-out forwards; }
${FX_CSS}
</style></head><body><div class="wrap">
<button class="tbtn" id="themeBtn" title="切换深浅色">🌓</button>
<h1>Home Lab Status</h1>
<div class="sub">uptime-monitor · Cloudflare Workers + Cron + D1 · 探测间隔 5 分钟 · 页面 60s 自动刷新</div>
${banner}
<div class="nav">
  <b>System status</b>
  ${older}
  <span>${esc(data.range.start)} ~ ${esc(data.range.end)}（${data.range.days} 天，北京时间）</span>
  ${newer}
</div>
${sections}
<h2>最近 24 小时明细</h2>
<table>
<tr><th>目标</th><th>地址</th><th>状态</th><th>最近延迟</th><th>24h 可用率</th><th>24h 平均延迟</th></tr>
${rows}
</table>
<div class="foot">powered by Cloudflare Workers · generated ${esc(data.generated_at)} ·
json: <a href="/api/status">/api/status</a></div>
</div>
<script>
${THEME_JS}
${FX_JS}
</script>
</body></html>`;

  return new Response(page, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
