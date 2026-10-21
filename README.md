# uptime-monitor

跑在 **Cloudflare Workers 免费套餐**上的极简服务状态板 —— 零服务器、零依赖、零数据库运维。

Cron 定时探测 → D1 落库 → KV 快照 → 状态翻转邮件告警，服务端渲染页面带全套动效。

## 特性

**探测与数据**
- 每 5 分钟 Cron 探测一轮（超时 1–30 秒后台可配），D1 存 7 天明细
- **双探测视角**：Cloudflare 边缘（`cf`）与家宽节点（`home`）分库存储，总览统计跟随所选主视角，杜绝双源数据混算污染可用率
- **边缘节点分布**：从探测响应的 `cf-ray` 头提取 Cloudflare 数据中心 IATA 机场码（如 SEA/NRT/FRA），零额外请求，24h 按节点聚合延迟与可用率，徽章按大洲着色
- KV 写放大修复：快照仅在首次探活或状态翻转时写入，稳定运行每轮 0 次 KV 写（保住免费额度 1000 写/天）

**告警**
- 状态翻转触发邮件告警：QQ SMTP 直连（`cloudflare:sockets` 连 465 隐式 TLS，AUTH LOGIN 授权码），可换任意 SMTP 服务商
- Email Routing（`send_email`）作为备用通道

**前端（服务端渲染，零依赖）**
- 动效体系：MPA 跨页视图过渡、卡片瀑布入场、延迟曲线描边动画、90 天 uptime 条逐根生长、绿点呼吸 / 红点闪烁，全部尊重 `prefers-reduced-motion`
- 概览页 90 天可用率条、详情页双视角延迟曲线 + 状态码分布 + 最近探测表

**管理后台（`/diamond_dia`）**
- 两种登录方式并存：管理密码（HMAC cookie）或 Cloudflare Zero Trust 邮箱 OTP（可选，未配置自动隐藏入口）
- 监控项增删改、探测超时、探测来源三模式（仅 Worker / 仅家宽 / 两者同时）
- 可选 VPS 侧 x-ui 重启按钮（浏览器直连，HMAC 短时密钥）

## 架构

```
                ┌──────────────────────────────────────────────┐
                │           Cloudflare Workers (免费套餐)        │
 cron */5 * * * │                                              │
 ──────────────►│  探测 ──► D1 (7天明细) ──► /api/status        │
                │    │  └─► KV (最新快照, 翻转才写)             │
 家宽节点 ──────►│  /api/report (probe=home, key 鉴权)          │
  POST 上报      │    │                                        │
                │    └─ 状态翻转 ──► SMTP 邮件告警               │
                └──────────────────────────────────────────────┘
                        │
                 /diamond_dia  管理后台
                 （密码 或 Zero Trust 邮箱 OTP）
```

## 快速开始

完整步骤（含 D1/KV 创建、migration、Secrets、可选 Zero Trust 配置）见 **[update-deploy.md](update-deploy.md)**，按 AI 可读格式编写，可直接交给 AI 助手执行部署。

```powershell
# 1. 替换 wrangler.jsonc 中的全部 <PLACEHOLDER>（见 update-deploy.md §3.2）
# 2. 安装依赖并建表
npm install
npx wrangler d1 execute uptime-db --remote --file schema.sql
# 3. 配置 secrets（ADMIN_PASSWORD / SMTP_USER / SMTP_PASS）
# 4. 部署
npx wrangler deploy
```

部署后打开状态板首页即用内置示例目标；登录 `/diamond_dia` 添加你自己的监控项。

## 目录结构

```
├── update-deploy.md            # AI 可读部署文档（含 changelog / migration / 回滚）
├── wrangler.jsonc              # Worker 配置（占位符模板）
├── schema.sql                  # D1 建表脚本（含 probe / colo 列）
├── src/
│   ├── index.js                # Worker 主程序（后端逻辑 + 全部页面）
│   └── smtp.js                 # SMTP 告警通道（cloudflare:sockets 直连 465）
└── vps/
    └── xui-restart-server.py   # 可选：VPS 侧 x-ui 重启 HTTP 服务
```

## 安全说明

- 本仓库为**脱敏版**：`wrangler.jsonc` 中账户/资源 ID、密钥、邮箱、域名均为占位符，`src/index.js` 默认监控目标为公共示例站点
- 真实凭证一律通过 `npx wrangler secret put` 注入（ADMIN_PASSWORD / SMTP_USER / SMTP_PASS / RESTART_KEY），不入库不落盘
- `/api/*` 接口以 `API_KEY` 鉴权；管理 cookie 为 HMAC-SHA256 签名，HttpOnly + Secure + SameSite=Strict

## Changelog

见 [update-deploy.md](update-deploy.md) §2：v2.1.0（边缘节点统计、Zero Trust 登录）、v2.0.0（双探测视角、KV 写放大修复、动效体系）等。
