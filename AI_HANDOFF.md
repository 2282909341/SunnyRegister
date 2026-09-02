# SunnyRegister AI 接手文档（唯一权威版）

> 更新日期：2026-09-03
> 当前 HEAD：`fc86e8d`（已推送 `origin/main`）
> 面向：后续接手本项目的 AI/开发者
> 原则：不记录卡密、密码、Token、代理凭证或数据库密码。
> 说明：本文件是**唯一**交接文档。历史上遗留的 `_HANDOFF*.md` / `_momo_probe_report.md` 均为 ic.meigo 时代的过期草稿，已归档到 `_delivery/_archive_handoffs/`，勿再当作现行事实。

## 1. 项目目标与用户真实工作流

SunnyRegister 是一套本地运行的账号注册与交付工作台：邮箱验证、ChatGPT 注册/登录、密码与 2FA 设置、Session 保存、接码、代理、反代导入、提链与支付探测。

当前注册身份（工作台“自动注册”第 1 步可切换）：

- **system**：本地已导入邮箱池（微软 / Apple iCloud），注册数量=勾选的邮箱数。
- **domain**：自建域名邮箱（`domain_api`），按数量下单/取码。
- **remail**：Remail 第三方邮箱供应商，按数量下单并通过 API 收取验证码。
- **google / microsoft**：预留身份，当前 UI 置灰不可用。
- **ic.meigo**：曾新增后按用户要求**整体移除**（提交 `9ece5ae`），当前代码与数据库均无此渠道。

用户核心偏好：**操作尽量少、系统自动识别、失败不误伤资源、页面显示与真实账号状态一致、注册速度不能明显变慢。**

## 2. 仓库与分支

- 工作目录：`E:\gpt协议注册提链支付\SunnyRegister`
- 开发分支：`main`，直接 push 不做 PR
- 用户远程（origin）：`https://github.com/2282909341/SunnyRegister.git`（fork）
- 作者上游（upstream）：`https://github.com/pxygit/SunnyRegister.git`（原项目，无 ic.meigo 代码）
- 上游状态：`merge-base == upstream/main == 37ec239`，即上游自分叉后**未再更新**；`main` 领先上游 46+ 个提交，无同步负担。
- 提交规则见根目录 `AGENTS.md`。修改前必须 `git pull --ff-only`，修改后审查 diff → 测试/构建 → 提交 → 推送 `origin/main`。
- 工作树长期存在大量历史 `_*.sql` / `_*.txt` / `_probe_*` / `_delivery` 未跟踪文件，**禁止 `git add .`**（只暂存本次明确修改的文件）。

## 3. 技术架构

| 层 | 目录 | 职责 |
|---|---|---|
| 前端 | `frontend/` | React + TypeScript + Vite，工作台、邮箱配置、账号管理和任务日志 |
| 后端 | `backend/` | Go HTTP API、数据模型、任务创建、静态资源嵌入 |
| Worker | `python-worker/` | Python 认证状态机、协议/浏览器流程、邮箱取码、密码和 2FA、并发与随机间隔 |
| 数据库 | PostgreSQL | 本地 `127.0.0.1:5433`；凭证只从 `.env` 的 `DATABASE_URL` 读取 |

运行端口：

- 后端：`http://127.0.0.1:8088`，健康检查 `/api/ready`
- Worker：`http://127.0.0.1:8765`，健康检查 `/health`

## 4. 当前 git 状态与最近提交链

HEAD=`fc86e8d`，与 `origin/main` 同步。最近（ic.meigo 移除后仍有效）提交：

| 提交 | 内容 |
|---|---|
| `fc86e8d` | 代理会话粘性**默认关闭**，回退轮换出口，修复坏出口 502 卡住 |
| `f889f4e` | 账号级设备画像（persona）+ 代理会话粘性（`-session-<hash>`） |
| `9ece5ae` | 移除 ic.meigo 全渠道 + 间隔改为 3-8 秒轻量抖动 |
| `7f82221` | 账号指纹池（12 种 impersonate）+ 批量随机间隔 |
| `de227d0` | 账户列表紧凑化显示 |
| `d98005c` | OTP 输入框未找到自动重试 + 429/400 限流如实上报 |
| `4809558` | （已随 ic.meigo 移除而失效）默认 icmeigo 身份 |

## 5. 注册链路关键实现（防批量关联）

### 5.1 TLS 指纹池（`fingerprint_pool.py`）

`pick_impersonate(seed)` 用 `sha256(seed)` 从 12 个 curl_cffi 指纹确定性挑选：
`chrome124/131/136/142/145、firefox133/135/144/147、safari17_0/safari18_0、edge101`。
每个账号 TLS/JA3/HTTP2 指纹不同，全链路（`protocol_auth` / `agent_identity` / `access_token_probe`）已接入 seed。

### 5.2 账号设备画像（`account_persona.py`）

`AccountPersona` + `pick_persona(seed, country)`：按邮箱派生 impersonate / UA / 屏幕分辨率 / locale / 时区 / 硬件并发 / 内存，并按**代理出口国家**对齐 locale（JP→ja-JP/Tokyo、VN→vi-VN/Ho_Chi_Minh、US→en-US 等）。`protocol_auth`、`sentinel`（Sentinel 反爬 token 生成）、`openai_auth`（设备指纹）、`access_token_probe` 全部接入，确保同一账号的协议头/UA/屏幕/locale 全程一致。

### 5.3 代理会话粘性（`proxy.py`，**默认关闭**）

- `sticky_proxy_url(proxy_url, key)` 给轮换住宅代理用户名追加 `-session-<sha256(key)[:8]>`，让同一账号复用同一出口 IP。
- **默认关闭**：`SUNNY_PROXY_STICKY` 默认 `"0"`。原因：轮换住宅会把账号钉在某个坏/过载出口上，导致注册报 `curl: (7) CONNECT tunnel failed, response 502` 卡死；轮换则每次连接换出口、坏出口一次就滚过去。
- 想开启：`.env` 加 `SUNNY_PROXY_STICKY=1`（`start-windows.ps1` 会自动导出），但前提是代理池质量够好。

### 5.4 账号间间隔（`worker.py`）

`_register_pacing_range` / `_pacing_delay`：账号间随机冷却，默认 **3-8 秒**。可用 payload `register_pacing_min_sec/max_sec` 或 env `SUNNY_REGISTER_PACING_MIN_SEC/MAX_SEC` 覆盖，双 0 关闭。

### 5.5 认证恢复（`auth_resilience.py`）

`classify_auth_failure` 把可恢复错误（`stale_auth_context`，含 `wrong code` / `otp input was not found` 等）标记 retryable，用全新认证上下文自动重试一次；429/400 限流按真实 HTTP 状态上报（不再映射成 0）。

## 6. 封号调查结论（2026-09-02 波浪式扫号）

- 40 个 `banned` 全部集中在 2026-09-02，呈波浪式批量（06:39 一分钟 6 个、21:15-21:19 五个、21:40-21:41 两个，存活 9-60 分钟）。
- `last_error` 统一 `account_deactivated`，多在 FORCE 密码+2FA 步骤被检出（注册后被 OpenAI 风控扫号波停用，流水线复核时撞死号）。
- 根因（已修）：① 全库只有 `chrome136`+`firefox144` 两种 TLS 指纹；② 轮换住宅每连接换 IP（机械脚本特征）；③ 账号间无间隔。
- 残余风险（未完全解决）：101 个 JP + 101 个 VN 账号**共用 2 组代理凭证串**=同一代理商同一 IP 池/ASN。粘性本可固定出口，但实测坏出口 502 导致卡死，故已默认关闭。若后续仍成波封号，升级路径=加第二家住宅代理商 + 少量静态独享 IP。

## 7. 已实现可靠性修复汇总

- 可恢复认证问题用全新认证上下文自动重试一次。
- `wrong_email_otp_code` / `otp input was not found` 归类为可恢复旧认证上下文。
- 旧验证码按时间过滤（`_code_email_is_fresh`），避免 resume 读旧码导致 `HTTP 401 Wrong code`。
- Camoufox/Playwright 已跳转 ChatGPT 时，`interrupted by another navigation` 不再误判失败。
- 任务成功/失败以密码、2FA、Session 实际落库为准，不以页面跳转为唯一成功信号。
- 失败邮箱保留、允许直接重试，不自动释放或销毁。
- CA 证书中文路径 curl 77 根治（`ca_bundle.py` 全局加载 + 各 session 补 `verify=ca_bundle_path()`）。

## 8. 重要文件定位

| 功能 | 文件 |
|---|---|
| 任务创建/邮箱/账户/代理/健康检查 | `backend/sunny_register.go`、`backend/sunny_health.go` |
| 支付探测/试用/checkout | `backend/sunny_payment_probe.go`、`backend/sunny_trial.go`、`backend/sunny_checkout_probe.go` |
| 认证状态机与协议 | `python-worker/sunny_core/protocol_auth.py`、`openai_auth.py` |
| 设备画像 / 指纹池 | `python-worker/sunny_core/account_persona.py`、`fingerprint_pool.py` |
| 认证错误分类 | `python-worker/sunny_core/auth_resilience.py` |
| 代理（粘性/预检/TLS） | `python-worker/sunny_core/proxy.py`、`proxy_scheduler.py` |
| 邮箱读取器 | `python-worker/sunny_core/mailbox.py` |
| Worker 主流程与并发/间隔 | `python-worker/sunny_core/worker.py` |
| Worker 数据库写回 | `python-worker/sunny_core/db.py` |
| 前端工作台 | `frontend/src/pages/SunnyRegister.tsx` |

## 9. 测试与构建

### Go

```powershell
cd backend
go test ./...
go build -trimpath -ldflags="-s -w" -o ..\bin\SunnyRegister.exe .
```

`backend/remail_test.go` 使用 Go 1.24 特性，当前 `go.mod` 为 1.23；本机全量测试时临时改名排除，测试后**必须恢复**。

### Python

```powershell
cd python-worker
.\.venv\Scripts\python.exe -m pytest tests -q
```

`python-worker/sunny_core/worker.py`（含 FastAPI 入口 `python-worker/worker.py`）与 `openai_auth.py` 的 Git 版本首字节为 UTF-8 BOM（EF BB BF）；用编辑工具改动后必须恢复 BOM，否则与 HEAD 整体对比会误判改动。

### 前端

```powershell
cd frontend
npm run build
```

产物输出到 `backend/static`（gitignore，不入库），Go 后端构建时嵌入。改前端后先 `npm run build` 再重构建后端。

## 10. 数据库访问方法（勿打印凭证）

```powershell
$url = (Get-Content '.env' | Where-Object { $_ -match '^DATABASE_URL=' } | Select-Object -First 1) -replace '^DATABASE_URL=',''
$noSsl = ($url -split '\?',2)[0]
$m = [regex]::Match($noSsl, 'postgres(?:ql)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)')
$env:PGPASSWORD = $m.Groups[2].Value
$h=$m.Groups[3].Value; $p=$m.Groups[4].Value; $u=$m.Groups[1].Value; $d=$m.Groups[5].Value
psql -h $h -p $p -U $u -d $d -c "SELECT ..."
```

端口 5433，库名 `sunnyregister`。SQL 里**避免写中文字面量**（psql UTF8 会报 invalid byte sequence）。主要表：`tasks`（无 `task_id` 列，主键为 `id`；含 `status/progress_current/progress_total/success_count/error_count/payload_json/result_json`）、`task_events`（`task_id` 外键指 `tasks.id`）、`sunny_accounts`、`sunny_mailboxes`、`sunny_proxies`、`sunny_mailbox_leases`。

## 11. 本地部署和验证

1. 从 `.env` 导入环境变量，不要打印其值。
2. 后端运行 `bin/SunnyRegister.exe`，端口 8088。
3. Worker 运行 `python-worker/.venv/Scripts/python.exe -m uvicorn worker:app --host 127.0.0.1 --port 8765`。
4. 重启方式：`scripts\stop-windows.ps1` → `scripts\start-windows.ps1`（改 Python/Go 代码后必须重启才生效）。
5. 不要只看进程名，必须核对端口占用 PID、两个健康接口以及 Worker 数据库连接状态。
6. 真实注册验证必须核对任务表、任务事件、邮箱状态和 Session 落库；健康接口 200 不等于注册一定成功。

## 12. 故障排查顺序

1. 查 `/api/ready` 和 `/health`，确认 Worker `running` 列表。
2. 查最新 `tasks` 的 `status/progress_current/progress_total/success_count/error_count`。
3. 查该任务最新 `task_events`，对邮箱、代理和 Token 脱敏后再记录结论。
4. 核对任务 `payload_json` 的 `mailbox_ids/count/concurrency/identity/proxy_countries` 与代理快照，不输出敏感字段。
5. 任务页看似“卡住”时，先判断数据库是 `running` 还是已终止；不能只依赖页面缓存。
6. 代理类报错（如 `curl: (7) CONNECT tunnel failed, response 502`）→ 先确认粘性开关：默认轮换；`proxy_sticky: true` 出现率高且伴随 502，说明粘性钉到坏出口。

## 13. 关键环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `DATABASE_URL` | 无（必填） | PostgreSQL 连接串，来自 `.env` |
| `SUNNY_PROXY_STICKY` | `0` | 1=开启代理会话粘性（防关联），0=轮换（防 502 卡死） |
| `SUNNY_REGISTER_PACING_MIN_SEC` / `MAX_SEC` | `3.0` / `8.0` | 账号间随机冷却，双 0 关闭 |
| `SUNNY_HEALTHCHECK_ENABLED` / `TIME` / `CONCURRENCY` | `true` / `06:00` / `2` | 定时健康检查 |

## 14. 接手者必做清单

1. 读 `AGENTS.md`、本文档、最近 5 条 Git 提交。
2. `git status --short --branch`，只暂存本次明确修改的文件，**禁止 `git add .`**。
3. `git fetch origin upstream` → `git pull --ff-only origin main`。
4. 先读现场数据，再改代码；禁止自动释放失败邮箱。
5. 修改后审查完整 diff，运行对应 Go/Python/前端测试，注意 `remail_test.go` 排除与 BOM 恢复。
6. 构建新后端并重启服务，校验端口 PID 与两个健康接口。
7. 提交用 `feat: XXX实现了XXX功能`，直接推送 `origin/main`。

## 15. 开发理解

注册链路的本质是资源轮转 + **批量关联规避**：每个账号尽量独立 TLS 指纹、独立出口 IP、账号间随机间隔，成功可确认、失败可重试、流速可接受。最重要的不是单次 100% 成功，而是：

- 成功可确认；
- 失败可重试；
- 外部页面/网络波动不被写成虚假成功；
- 批量账号不因同指纹/同节奏被一次性聚类封禁。

后续修复继续围绕这几点；同时注意“防封”与“可用性”的平衡——例如粘性固定出口防关联，但坏出口会卡死，因此做成默认关闭、可开关。
