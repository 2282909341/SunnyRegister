# SunnyRegister AI 接手文档

> 更新日期：2026-09-02（ic.meigo 渠道已移除）
> 面向：后续接手本项目的 AI/开发者
> 原则：不记录卡密、密码、Token、代理凭证或数据库密码。

## 1. 项目目标与用户真实工作流

SunnyRegister 是一套本地运行的账号注册与交付工作台，包含邮箱验证、ChatGPT 注册/登录、密码与 2FA 设置、Session 保存、接码、代理和反代导入。

当前注册身份（工作台“自动注册”第 1 步可切换）：

- **system**：使用本地已导入的邮箱池（微软 / Apple iCloud），注册数量=勾选的邮箱数。
- **domain**：自建域名邮箱（`domain_api`），按数量下单/取码。
- **remail**：Remail 第三方邮箱供应商，按数量下单并通过 API 收取验证码。
- **google / microsoft**：预留身份，当前 UI 置灰不可用。

用户的核心偏好是：**操作尽量少、系统自动识别、失败不误伤资源、页面显示与真实账号状态一致。**

## 2. 仓库与分支

- 工作目录：`E:\gpt协议注册提链支付\SunnyRegister`
- 开发分支：`main`
- 用户远程：`https://github.com/2282909341/SunnyRegister.git`
- 作者上游：`https://github.com/pxygit/SunnyRegister.git`（原始项目，不含 ic.meigo）
- 提交规则见根目录 `AGENTS.md`。修改前必须 `git pull --ff-only`，修改后必须审查、测试、提交并推送 `origin/main`。
- 工作树长期存在大量历史 `_*.sql` / `_*.txt` / `_delivery` 未跟踪文件，**禁止 `git add .`**。

## 3. 技术架构

| 层 | 目录 | 职责 |
|---|---|---|
| 前端 | `frontend/` | React + TypeScript + Vite，工作台、邮箱配置、账号管理和任务日志 |
| 后端 | `backend/` | Go HTTP API、数据模型、任务创建、静态资源嵌入 |
| Worker | `python-worker/` | Python 认证状态机、协议/浏览器流程、邮箱取码、密码和 2FA、并发与随机间隔 |
| 数据库 | PostgreSQL | 本地默认使用 `127.0.0.1:5433`；凭证只从 `.env` 读取 |

运行端口：

- 后端：`http://127.0.0.1:8088`，健康检查 `/api/ready`
- Worker：`http://127.0.0.1:8765`，健康检查 `/health`

## 4. 注册链路关键实现

### 防批量关联（7f82221 起）

- `fingerprint_pool.py`：按邮箱/代理种子 `sha256` 从 12 个 curl_cffi 指纹（chrome124/131/136/142/145、firefox133/135/144/147、safari17/18、edge101）确定性挑选，**每个账号 TLS/JA3/HTTP2 指纹不同**；`pick_impersonate(seed)` / `impersonate_pool()`。
- `protocol_auth.py::_new_session` / `agent_identity.py::_session` / `access_token_probe.py` 均接入 seed；删除自定义 User-Agent 覆盖（指纹自带真实 UA）。
- `worker.py::_register_pacing_range` / `_pacing_delay`：账号间随机冷却，默认 **3-8 秒**（轻抖动，不显著拖慢批量）；payload `register_pacing_min_sec/max_sec` 或 env `SUNNY_REGISTER_PACING_MIN_SEC/MAX_SEC` 可调，双 0 关闭。

### 认证恢复

- `auth_resilience.py` 分类 `stale_auth_context`（含 "otp input was not found"）等可恢复错误并自动换全新认证上下文重试一次；429/400 类限流按真实 HTTP 状态上报。

## 5. 当前已实现的可靠性修复

- 首次流程发生可恢复认证问题时，使用全新认证上下文自动重试一次。
- `wrong_email_otp_code` / `otp input was not found` 归类为可恢复的旧认证上下文。
- Camoufox/Playwright 已跳转到 ChatGPT 时，`interrupted by another navigation` 不再误判为失败。
- 任务成功/失败必须以密码、2FA 和 Session 实际落库为准，不以页面跳转作为唯一成功信号。
- 失败邮箱保留、允许直接重试，不自动释放或销毁。

## 6. 重要文件定位

| 功能 | 文件 |
|---|---|
| 任务创建/邮箱/账户/代理/健康检查 | `backend/sunny_register.go`、`backend/sunny_health.go` |
| 认证状态机与协议 | `python-worker/sunny_core/protocol_auth.py`、`openai_auth.py` |
| 认证错误分类 | `python-worker/sunny_core/auth_resilience.py` |
| 邮箱读取器（xbovo/url_api/remail/domain/hotmail） | `python-worker/sunny_core/mailbox.py` |
| Worker 主流程与并发/间隔 | `python-worker/sunny_core/worker.py` |
| Worker 数据库写回 | `python-worker/sunny_core/db.py` |
| TLS 指纹池 | `python-worker/sunny_core/fingerprint_pool.py` |
| 前端工作台/邮箱配置 | `frontend/src/pages/SunnyRegister.tsx` |

## 7. 测试与构建

### Go

```powershell
cd backend
go test ./...
go build -o ..\bin\SunnyRegister.verify.exe .
```

`backend/remail_test.go` 使用 `testing.(*B).Context`，需要 Go 1.24；当前 `go.mod` 为 Go 1.23。本机全量测试时需临时排除该文件，测试后必须原样恢复。

### Python

```powershell
cd python-worker
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
```

`python-worker/sunny_core/worker.py` 的 Git 版本首字节为 UTF-8 BOM（EF BB BF）；用编辑工具改动后必须恢复 BOM，否则与 HEAD 对比会整体视为改动。

### 前端

```powershell
cd frontend
npm run build
```

前端产物输出到 `backend/static`，Go 后端构建时嵌入。修改前端后必须先构建前端，再重新构建和替换后端可执行文件。

## 8. 本地部署和验证

1. 从 `.env` 导入环境变量，不要打印其值。
2. 后端运行 `bin/SunnyRegister.exe`，端口 8088。
3. Worker 使用 `python-worker/.venv/Scripts/python.exe -m uvicorn worker:app --host 127.0.0.1 --port 8765`。
4. 不要只看进程名，必须核对端口占用 PID、两个健康接口以及 Worker 数据库连接状态。
5. 真实注册验证必须再核对任务表、任务事件、邮箱状态和 Session 落库；健康接口 200 不等于外部注册一定成功。

## 9. 故障排查顺序

1. 查 `/api/ready` 和 `/health`，确认 Worker `running` 列表。
2. 查最新 `tasks` 的 `status/progress_current/progress_total/success_count/error_count`。
3. 查该任务最新 `task_events`，对邮箱、代理和 Token 做脱敏后再记录结论。
4. 核对任务 `payload_json` 里的 `mailbox_ids`、`count`、`concurrency`、`identity` 与代理快照，不要输出敏感字段。
5. 任务页看似“卡住”时，先判断数据库是 `running` 还是已终止；不能只依赖页面缓存。

## 10. 接手者必做清单

1. 读取 `AGENTS.md`、本文档以及最近 5 条 Git 提交。
2. 检查 `git status --short --branch`，仅暂存本次明确修改的文件。
3. `git fetch origin upstream` 并 `git pull --ff-only origin main`。
4. 先读现场数据，再改代码；禁止自动释放失败邮箱。
5. 修改后审查完整 diff，运行对应 Go/Python/前端测试。
6. 构建新后端并重启服务，校验实际端口 PID 和新前端包内容。
7. 提交信息使用 `feat: XXX实现了XXX功能`，直接推送 `origin/main`。

## 11. 开发理解

注册链路的本质是资源轮转与**批量关联规避**：每个账号尽量使用独立 TLS 指纹、独立代理出口、账号间随机间隔，成功可确认、失败可重试、流速可接受。最重要的不是追求单次“100% 成功”，而是保证：

- 成功可确认；
- 失败可重试；
- 外部页面或网络波动不会被写成虚假成功；
- 批量账号不因同指纹/同节奏被一次性聚类封禁。

后续修复应继续围绕这几点，而不是叠加更多需要用户手工点击的选项。