# uptime-monitor — 更新部署说明（AI 可读）

> 本文档面向执行部署的 AI 助手或工程师。按顺序执行，每步都有校验点；
> 任何一步失败请停止并向操作者汇报原始错误，不要自行猜测绕过。

- **版本**: v2.1.0
- **发布日期**: 2026-10-21
- **运行时**: Cloudflare Workers（Node.js 兼容模式）
- **自定义域**: 由 `wrangler.jsonc` 中 `routes.pattern` 决定（custom domain，部署后自动生效）
- **Cron**: `*/5 * * * *`（每 5 分钟探测一轮）

---

## 1. 包内容清单

```
uptime-monitor-v2.1.0.zip
├── update-deploy.md          ← 本文件
├── wrangler.jsonc            ← Worker 配置模板（**占位符已脱敏**，见 §3 资源准备）
├── package.json / package-lock.json
├── schema.sql                ← D1 建表脚本（全新库直接执行，已含 probe + colo 列）
├── src/
│   ├── index.js              ← Worker 主程序（全部后端逻辑 + 前端页面；默认监控目标已替换为公共示例站点）
│   └── smtp.js               ← QQ SMTP 告警通道（cloudflare:sockets 直连 465；可用任意 SMTP 服务商）
└── vps/
    └── xui-restart-server.py ← VPS 侧 x-ui 重启 HTTP 服务（可选，仅在重建 VPS 时部署）
```

排除项：`node_modules/`（部署前 `npm install` 重建）。

**安全说明**: 本包为**脱敏版**——`wrangler.jsonc` 中所有账户/资源 ID、密钥、邮箱、
域名、Zero Trust 团队域与 AUD 均为 `<PLACEHOLDER>` 占位符；`src/index.js` 中原项目
的默认监控目标已替换为公共示例站点（cloudflare/github/httpbin/example.com）。
部署前需完成 §3 的替换。

---

## 2. CHANGELOG

### v2.1.0（2026-10-21）

**数据层**
- **[schema] `checks` 表新增 `colo` 列**（`TEXT NOT NULL DEFAULT ''`）。
  记录每次 CF 探测所落的 Cloudflare 数据中心（IATA 机场码）。
  **已有历史数据的库部署时必须执行 migration，见 §4.2。**

**后端**
- **边缘节点采集（零额外请求）**：探测响应头 `cf-ray`（格式 `<hex>-<COLO>`）
  解析出 IATA 机场码随每次探测入库；不增加任何探测频率。
- **管理员登录新增 Cloudflare Zero Trust（Access）方式（与密码登录并存）**：
  - 边缘层：Access 应用**仅拦截专用入口 `/diamond_dia/access`**，邮箱 OTP 验证
    （One-time PIN）；密码登录页与全部管理接口**不被 Access 拦截**；
  - Worker 层：校验请求头 `Cf-Access-Jwt-Assertion` 的 RS256 签名（团队 JWKS，
    缓存 1 小时）+ `aud` + 邮箱白名单，通过即签发与密码登录一致的 admin cookie，
    后续会话与密码登录完全相同；
  - 登录页在配置了 `ACCESS_*` 时显示「通过 Cloudflare Zero Trust 登录」按钮；
    OTP 完成后的首次回跳若边缘会话未同步（缺 JWT 头），自动重试最多 3 次
    （1 秒/次，中转页提示"正在完成 Zero Trust 登录…"）；
  - **向后兼容**：三个 `ACCESS_*` vars 未配置（留空）时按钮不显示、回退纯密码登录，
    完全不影响不使用 Zero Trust 的部署。
- 新增 vars：`ACCESS_EMAILS`（白名单邮箱，逗号分隔）、
  `ACCESS_TEAM_DOMAIN`（团队域，如 `yourteam.cloudflareaccess.com`）、
  `ACCESS_AUD`（Access 应用的 AUD tag）。

**前端**
- 详情页新增「边缘节点分布（24h）」区块：按数据中心聚合探测次数 / 占比 /
  平均延迟 / 可用率；内置约 60 个 CF 节点的 IATA→城市映射；徽章按大洲着色
  （AS 蓝 / EU 紫 / NA 绿 / SA 黄 / AF 橙 / OC 青）；行布局宽松（城市名 180px 列宽、
  统计两行显示）。

### v2.0.0（2026-10-20，累积自 v1.x）

**数据层**
- **[schema] `checks` 表新增 `probe` 列**（`TEXT NOT NULL DEFAULT 'cf'`）。
  区分探测来源：`'cf'` = Cloudflare 边缘视角，`'home'` = 家宽节点。

**后端 API**
- **新增 `POST /api/report`**：家宽探测节点上报入口。
  鉴权 `?key=<API_KEY>`；body 为 `{"results":[{name,ok,status,latency,error}]}`；
  数据以 `probe='home'` 入库，**不触发告警、不写 KV**；单次最多 50 条。
- **`GET /api/status` 新增 `probeMode` 字段**：返回当前探测来源模式
  （`worker` / `home` / `both`）。
- **总览统计主视角跟随探测来源**：`probeMode=home` 时 24h 统计与 90 天逐日
  聚合取家宽数据，否则取 CF 数据；杜绝双路数据混算污染可用率。

**探测逻辑**
- **KV 写放大修复**：`state:<name>` 快照仅在「首次探活」或「状态翻转」时写入。
  稳定运行时每轮 0 次 KV 写，保护免费额度（1000 写/天）。邮件告警仍由状态翻转触发。
- **探测超时可配置**：管理员后台设置，存 KV `config:timeout_ms`，
  取值 1000–30000ms（后台输入 1–30 秒），未配置默认 8000ms；每轮探测开头读取一次。
- **探测来源模式**：存 KV `config:probes`，三选一：
  | 模式 | Worker cron | 家宽上报 | 总览主视角 | 告警 |
  |------|-------------|----------|-----------|------|
  | `worker` | 探测 | 拒收 (403) | CF | 正常 |
  | `home` | **暂停**（仅做 7 天数据清理） | 入库 | 家宽 | 无 |
  | `both`（默认） | 探测 | 入库 | CF | 正常 |

**前端（服务端渲染，零依赖）**
- **动效体系**（`FX_CSS` + `FX_JS` 常量，总览/详情/管理页共享）：
  - MPA 跨页视图过渡（`@view-transition`，Chrome 126+，其它浏览器自动降级）
  - 卡片瀑布入场、表格行渐入（`--i` 序号由 `FX_JS` 注入）
  - 按钮按压反馈（active 缩放 / hover 光晕；主题键按下旋转）
  - 延迟曲线描边动画（`pathLength="100"` 归一化 + `stroke-dashoffset`）
  - 90 天 uptime 条逐根生长 + hover 提亮
  - 状态码分布条从 0 填充（`--w` 变量）
  - 状态点：绿点呼吸光环，DOWN 红点急促闪烁
  - 全部尊重 `prefers-reduced-motion: reduce`
- **详情页双曲线**：① Cloudflare 边缘视角 ② 家宽视角，两条分隔展示；
  状态码分布按来源分组；「最近 20 次探测」表新增「来源」列（家宽金色 / CF 灰色）。
- 管理后台新增「探测超时」「探测来源」两张设置卡片。

---

## 3. 前置条件与占位符替换

### 3.1 创建 Cloudflare 资源（全新账户）
```powershell
npx wrangler login                       # 浏览器授权
npx wrangler whoami                      # 记下 Account ID
npx wrangler d1 create uptime-db         # 记下输出的 database_id
npx wrangler kv namespace create KV      # 记下输出的 id
```

### 3.2 替换 `wrangler.jsonc` 中的全部占位符

| 占位符 | 填入内容 |
|--------|----------|
| `<YOUR_ACCOUNT_ID>` | `wrangler whoami` 输出的 Account ID |
| `<YOUR_D1_DATABASE_ID>` | `d1 create` 输出的 database_id |
| `<YOUR_KV_NAMESPACE_ID>` | `kv namespace create` 输出的 id |
| `<YOUR_ALERT_EMAIL@example.com>` | 告警收件邮箱 |
| `<YOUR_FROM_EMAIL@example.com>` | 备用通道发件标识（可同收件邮箱） |
| `<YOUR_RANDOM_API_KEY>` | 自生成随机串（用于 `/api/*` 鉴权，建议 48 位） |
| `<YOUR_UPTIME_DOMAIN>` | 你的自定义域（须已托管在同账户，如 `uptime.your-domain.com`） |
| `<YOUR_ACCESS_EMAILS>` | （可选）Zero Trust 白名单邮箱，逗号分隔；不启用留空 `""` |
| `<YOUR_ACCESS_TEAM_DOMAIN>` | （可选）Zero Trust 团队域 `xxx.cloudflareaccess.com`；不启用留空 `""` |
| `<YOUR_ACCESS_AUD>` | （可选）Access 应用的 AUD tag（§3.5 生成）；不启用留空 `""` |

`SSH_HOST`/`SSH_PORT` 为 VPS 重启功能预留，无 VPS 保持 `example.com` 即可。
若账户未配置 Email Routing，删除 `send_email` 块（主告警通道走 SMTP，不受影响）。

> **三个 `ACCESS_*` 全部留空 = 关闭 Zero Trust 登录**，管理后台照旧使用
> `ADMIN_PASSWORD` 密码登录；这不是必填项。

### 3.3 设置 Secrets（每个都会交互式提示输入）
```powershell
npx wrangler secret put ADMIN_PASSWORD   # 管理后台登录密码
npx wrangler secret put SMTP_USER        # SMTP 账号（如 QQ 邮箱）
npx wrangler secret put SMTP_PASS        # SMTP 授权码（非登录密码）
npx wrangler secret put RESTART_KEY      # 任意随机串（仅 VPS 重启功能需要）
```

### 3.4 工具版本
```powershell
node --version   # >= 18
```

### 3.5 （可选）启用 Zero Trust 管理员登录

前置：账户已开通 Cloudflare Zero Trust（dashboard 首次进入选择 team 域名与
Free 套餐即可；One-time PIN 登录方式默认可用）。安装官方 CLI 并登录：
```powershell
npm i -g cf ; cf auth login              # 浏览器授权
```

① 确认组织（记下输出的 `auth_domain`，即 `ACCESS_TEAM_DOMAIN`）：
```powershell
cf zero-trust organization get
```

② 创建 Access 应用（`<YOUR_UPTIME_DOMAIN>` 换成你的域；**路径必须是
`/diamond_dia/access*`**——只拦截 Zero Trust 专用入口，密码登录不受影响）：
```powershell
cf zero-trust access applications create --body '{"name":"uptime-admin","type":"self_hosted","domain":"<YOUR_UPTIME_DOMAIN>/diamond_dia/access*","session_duration":"720h","app_launcher_visible":false}'
```
输出中的 **`aud` 字段**即 `ACCESS_AUD`；`id` 字段下一步要用。

③ 创建邮箱白名单策略（可放多个邮箱，逗号分隔逐个写 `email` 条目）：
```powershell
cf zero-trust access policies create --body '{"name":"admin-emails","decision":"allow","include":[{"email":{"email":"you@example.com"}}]}'
```
记下输出的 `id`（policy id）。

④ 把策略挂到应用上：
```powershell
cf zero-trust access applications update <APP_ID> --body '{"type":"self_hosted","name":"uptime-admin","domain":"<YOUR_UPTIME_DOMAIN>/diamond_dia/access*","app_launcher_visible":false,"policies":[{"id":"<POLICY_ID>"}]}'
```

⑤ 将 `ACCESS_TEAM_DOMAIN` / `ACCESS_AUD` / `ACCESS_EMAILS` 填入 `wrangler.jsonc`
后再执行 §4.3 部署。

**验证 Access**：浏览器打开 `https://<YOUR_UPTIME_DOMAIN>/diamond_dia`，登录页应
出现「通过 Cloudflare Zero Trust 登录」按钮（密码登录仍在，两种方式并存）→ 点击 →
Access 页输入白名单邮箱 → 收 6 位验证码 → 验证后自动进入管理后台（首次可能短暂
显示"正在完成 Zero Trust 登录…"中转页）；之后再点按钮为秒进（Access 会话默认 30 天）。
注意：QQ 邮箱收 Access 验证码可能进垃圾箱，Gmail/Outlook 更稳。

> Windows PowerShell 里执行以上 `--body` 命令时，JSON 内的双引号需写成 `\"`
> （或让 AI 助手处理转义）。

---

## 4. 部署步骤

### 4.1 安装依赖
```powershell
cd <解压目录>
npm install
```

### 4.2 D1 建表 / migration
```powershell
# 全新空库：直接执行建表脚本（已含 probe + colo 列）
npx wrangler d1 execute uptime-db --remote --file schema.sql

# 从 v2.0.0 升级（已有 probe 列）：只需补 colo 列
npx wrangler d1 execute uptime-db --remote --command "ALTER TABLE checks ADD COLUMN colo TEXT NOT NULL DEFAULT ''"

# 从 v1.x 升级：先查再逐列补
npx wrangler d1 execute uptime-db --remote --command "PRAGMA table_info(checks)"
# 缺 probe 列：
npx wrangler d1 execute uptime-db --remote --command "ALTER TABLE checks ADD COLUMN probe TEXT NOT NULL DEFAULT 'cf'"
# 缺 colo 列：
npx wrangler d1 execute uptime-db --remote --command "ALTER TABLE checks ADD COLUMN colo TEXT NOT NULL DEFAULT ''"
```

### 4.3 部署
```powershell
npx wrangler deploy
```
预期输出包含：`<YOUR_UPTIME_DOMAIN> (custom domain)` 与
`schedule: */5 * * * *`。记录输出中的 Current Version ID。

### 4.4 部署后添加监控项
首次部署后 KV 中没有目标列表，页面会用内置的公共示例站点
（Cloudflare / GitHub / HttpBin / GitHub API / Example）。
登录管理后台 `<YOUR_UPTIME_DOMAIN>` 路径下的 `/diamond_dia`（Access 邮箱 OTP
或 `ADMIN_PASSWORD` 密码，取决于 §3.5 是否启用）添加你自己的监控项、
配置探测超时与探测来源。默认探测来源为 `both`；无家宽节点时建议切换为
`worker`（`/api/report` 上报接口保留，随时可接）。

### 4.5 （可选）VPS 侧组件
`vps/xui-restart-server.py` 仅在 VPS 需要重建时部署（systemd 常驻，环境变量
`RESTART_KEY` 与 Worker 侧一致）。已在运行的 VPS 服务无需任何操作。

---

## 5. 部署后验证清单

```powershell
# 1. API 可用且包含新字段（预期 "probeMode": "both"）
curl.exe -s "https://<YOUR_UPTIME_DOMAIN>/api/status" | findstr "probeMode"

# 2. 动效已上线（预期输出 True）
$h = (Invoke-WebRequest "https://<YOUR_UPTIME_DOMAIN>" -UseBasicParsing).Content
$h.Contains("@view-transition"); $h.Contains("dotpulse"); $h.Contains("lat-line")

# 3. 家宽上报端点鉴权（预期 401）
curl.exe -s -o NUL -w "%{http_code}" -X POST "https://<YOUR_UPTIME_DOMAIN>/api/report"

# 4. 等待一个 cron 周期（≤5 分钟）后确认 D1 持续写入，且 colo 列开始积累机场码
npx wrangler d1 execute uptime-db --remote --command "SELECT COUNT(*), MAX(ts) FROM checks WHERE probe='cf'"
npx wrangler d1 execute uptime-db --remote --command "SELECT DISTINCT colo FROM checks WHERE ts > strftime('%s','now') - 3600 AND colo != ''"
```

页面人工检查项（浏览器打开 `https://<YOUR_UPTIME_DOMAIN>`）：
- [ ] 卡片瀑布入场动画播放（≤1s）
- [ ] 90 天条逐根生长、绿点呼吸
- [ ] 点击任一监控项进入详情页：跨页过渡平滑、延迟曲线描边动画播放
- [ ] 详情页出现「边缘节点分布（24h）」区块（刚部署时显示"节点数据积累中"属正常，
      经 CF 代理的目标积累一轮探测后即有数据）
- [ ] Console 无报错
- [ ] （若启用 Zero Trust）打开 `/diamond_dia` 跳转 Access 登录页，OTP 验证后直进后台

---

## 6. 回滚

```powershell
# 方式一：回滚到上一版本（保留当前配置）
npx wrangler rollback

# 方式二：重新部署任意历史包（解压旧版本 zip 后在本目录执行）
npx wrangler deploy
```
`probe` / `colo` 列均无需回退（旧代码不感知新列，`DEFAULT` 值不影响旧版读写）。
若需临时关闭 Zero Trust 登录：将 `wrangler.jsonc` 中三个 `ACCESS_*` 置空 `""`
后重新 `npx wrangler deploy` 即回退为纯密码登录；同时可在 Zero Trust dashboard
删除 Access 应用恢复边缘直连。

---

## 7. 已知边界

- 仅 `home` 模式下**没有告警**（Worker 侧探测暂停，家宽上报不触发告警）——设计如此。
- KV 快照仅在状态翻转时写入 ⇒ 状态页 `latest` 来自 KV，两次写入之间数据不变属正常。
- `src/ssh.js` 为未引用孤儿文件，可安全删除。
- `colo` 只对**经过 Cloudflare 代理（橙云）**的目标有值；直连目标（灰云 DNS）的
  探测响应无 `cf-ray` 头，`colo` 为空、不参与边缘节点统计——设计如此。
- Zero Trust 仅保护自定义域路由；若启用了 `workers.dev` 预览地址，该地址不受
  Access 拦截，但 Worker 端仍要求密码 cookie 或有效 Access JWT，不会放行。
