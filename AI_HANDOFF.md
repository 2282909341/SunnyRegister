# SunnyRegister AI 接手文档（唯一权威版）

> 更新日期：2026-09-03
> 当前 HEAD：以 `git rev-parse HEAD` 为准（`main` 与 `origin/main` 应保持同步）
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
- 上游基线：`upstream/main == 37ec239`。操作前仍需重新 `git fetch upstream`，不要把本文数值当成永久不变的事实。
- 提交规则见根目录 `AGENTS.md`。修改前必须 `git pull --ff-only`，修改后审查 diff → 测试/构建 → 提交 → 推送 `origin/main`。
- 工作树长期存在大量历史 `_*.sql` / `_*.txt` / `_probe_*` / `_delivery` 未跟踪文件，**禁止 `git add .`**（只暂存本次明确修改的文件）。

## 3. 技术架构

| 层 | 目录 | 职责 |
|---|---|---|
| 前端 | `frontend/` | React + TypeScript + Vite，工作台、邮箱配置、账号管理和任务日志 |
| 后端 | `backend/` | Go HTTP API、数据模型、任务创建、静态资源嵌入 |
| Worker | `python-worker/` | Python 认证状态机、协议/浏览器流程、邮箱取码、密码和 2FA、并发调度 |
| 数据库 | PostgreSQL | 本地 `127.0.0.1:5433`；凭证只从 `.env` 的 `DATABASE_URL` 读取 |

运行端口：

- 后端：`http://127.0.0.1:8088`，健康检查 `/api/ready`
- Worker：`http://127.0.0.1:8765`，健康检查 `/health`

## 4. 当前 git 状态与最近提交链

当前 HEAD 以 Git 命令查询为准。下表仅保留当前仍有效的关键历史：

| 提交 | 内容 |
|---|---|
| 当前提交 | 协议注册恢复作者上游实现，仅保留 CA 证书路径处理与默认本地代理 `7890` |
| `8bf3a6e` | 前端：移除 Hero 光球常驻动画 + `will-change` 收敛 + 大阴影收窄（优化工作台滚动掉帧） |
| `096f0e7` | 前端：移除吸顶栏与卡片 `backdrop-filter` 背景模糊（优化滚动掉帧） |
| `f04823e` | 前端：`useCachedState` 去双写 + 任务持久化 250ms 防抖 + 表格紧凑化 |
| `74b0ba0` | AI 交接文档唯一权威化整合 + 历史草稿归档 |
| `9ece5ae` | 移除 ic.meigo 全渠道（该移除仍有效） |
| `de227d0` | 账户列表紧凑化显示 |
| `d98005c` | 429/400 限流如实上报；其中协议注册额外 OTP 自动重试已随本次回归移除 |

## 5. 注册链路当前实现（作者上游基线）

用户明确要求协议注册除两项本地兼容修复外回归 `upstream/main=37ec239`：

1. **保留 CA 证书路径处理**：`protocol_auth.py`、`agent_identity.py`、`access_token_probe.py` 仍使用 `verify=ca_bundle_path()`，避免 Windows 中文路径下 `curl (77)`。
2. **保留默认本地代理端口 `7890`**：`backend/sunny_register.go` 的默认代理为 `http://127.0.0.1:7890`。

已移除的定制项：账号指纹池、账号设备画像、国家代理注册选择、代理会话粘性、账号间 3-8 秒随机间隔、额外的新认证上下文重试、额外的密码/2FA 完整性强制判定、wuasai 取码适配。

当前协议注册的 `curl_cffi` impersonate 回归原版固定 `chrome136`；Sentinel、浏览器回退、Worker 并发和验证码错误处理均以上游实现为准。

## 6. 封号调查结论（2026-09-02 波浪式扫号）

- 40 个 `banned` 全部集中在 2026-09-02，呈波浪式批量（06:39 一分钟 6 个、21:15-21:19 五个、21:40-21:41 两个，存活 9-60 分钟）。
- `last_error` 统一 `account_deactivated`，多在 FORCE 密码+2FA 步骤被检出（注册后被 OpenAI 风控扫号波停用，流水线复核时撞死号）。
- 这些是当时现象与推断，不是已证明的单一根因。指纹池、设备画像、粘性代理和随机间隔已按用户要求移除，不得继续写成“当前已修复”。

## 7. 已实现修复汇总（可靠性 + 前端性能/紧凑化）

- CA 证书中文路径 curl 77 根治（`ca_bundle.py` 全局加载 + 各 session 补 `verify=ca_bundle_path()`）。
- 默认本地代理端口保持 `7890`。
- 其他协议注册行为与作者上游一致；后续不要根据历史提交误把已回退的定制再加回来。

### 前端性能与紧凑化（2026-09-03 本轮）

- `useCachedState` 去除重复 `useEffect` 双写 `localStorage`（每次状态更新少一次阻塞主线程的同步写盘）。
- `publishSessionTasks` 改为 250ms 防抖持久化：内存快照仍同步更新（UI 即时），高频 SSE/轮询不再每 tick 全量 `JSON.stringify` 写盘。
- 账户/邮箱/接码/代理/会话表统一紧凑化：行高 42→34px、字号 13→12px、内边距 8→6px。
- 移除吸顶导航栏 `backdrop-blur-2xl` 与所有卡片的 `backdrop-filter: blur(22px)`（滚动掉帧主因之一）。
- 移除 Hero 光球 `float-orb 8s infinite` 常驻动画；`will-change` 从大卡片收敛到 `.sr-modal/.sr-toast`；`--surface-glow` 阴影 80px→32px。
- 涉及文件：`frontend/src/pages/SunnyRegister.tsx`、`frontend/src/App.tsx`、`frontend/src/index.css`。
- 若滚动仍掉帧，下一步候选（未做）：表格卡片 `content-visibility: auto`（配合 `contain-intrinsic-size`）、账户/邮箱大表行虚拟化。

## 8. 重要文件定位

| 功能 | 文件 |
|---|---|
| 任务创建/邮箱/账户/代理/健康检查 | `backend/sunny_register.go`、`backend/sunny_health.go` |
| 支付探测/试用/checkout | `backend/sunny_payment_probe.go`、`backend/sunny_trial.go`、`backend/sunny_checkout_probe.go` |
| 认证状态机与协议 | `python-worker/sunny_core/protocol_auth.py`、`openai_auth.py` |
| 认证错误分类 | `python-worker/sunny_core/auth_resilience.py` |
| 代理（作者原版预检/TLS） | `python-worker/sunny_core/proxy.py`、`proxy_scheduler.py` |
| 邮箱读取器 | `python-worker/sunny_core/mailbox.py` |
| Worker 主流程与并发 | `python-worker/sunny_core/worker.py` |
| Worker 数据库写回 | `python-worker/sunny_core/db.py` |
| 前端工作台 | `frontend/src/pages/SunnyRegister.tsx` |
| 前端全局样式/主题令牌 | `frontend/src/index.css` |
| 前端壳与吸顶导航 | `frontend/src/App.tsx` |

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

`python-worker/sunny_core/worker.py`（含 FastAPI 入口 `python-worker/worker.py`）与 `openai_auth.py` 的 Git 版本首字节为 UTF-8 BOM（EF BB BF）；前端 `frontend/src/index.css` 与 `frontend/src/App.tsx` 同样带 UTF-8 BOM。用编辑工具改动后必须恢复 BOM（PowerShell 读字节，若缺少 EF BB BF 则前缀补回），否则与 HEAD 整体对比会误判改动。

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
4. 核对任务 `payload_json` 的 `mailbox_ids/count/concurrency/identity` 与代理快照，不输出敏感字段。
5. 任务页看似“卡住”时，先判断数据库是 `running` 还是已终止；不能只依赖页面缓存。
6. 代理类报错（如 `curl: (7) CONNECT tunnel failed, response 502`）→ 按作者原版代理预检和代理池状态排查；当前无粘性代理开关。

## 13. 关键环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `DATABASE_URL` | 无（必填） | PostgreSQL 连接串，来自 `.env` |
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

当前原则是“作者上游行为优先”：除 CA 路径和 `7890` 外，协议注册不再维护自定义指纹、设备画像、粘性代理、国家选择或随机间隔。继续开发时优先保证：

- 成功可确认；
- 失败可重试；
- 外部页面/网络波动不被写成虚假成功；
- 不误伤邮箱和账号数据。

后续若要再增加上述任一定制，必须先得到用户新的明确要求，并与 `upstream/main` 逐项对比。
