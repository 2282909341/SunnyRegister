# SunnyRegister AI 接手文档

> 更新日期：2026-09-02
> 面向：后续接手本项目的 AI/开发者
> 原则：不记录卡密、密码、Token、代理凭证或数据库密码。

## 1. 项目目标与用户真实工作流

SunnyRegister 是一套本地运行的账号注册与交付工作台，包含邮箱验证、ChatGPT 注册/登录、密码与 2FA 设置、Session 保存、接码、代理和反代导入。

当前最重要的用户流程是 `ic.meigo` 智能流水线：

1. 用户购买 1/10/100 额度卡密，卡密还有独立并发数。
2. 在“邮箱配置→导入邮箱→Apple 邮箱→ic.meigo”中每行粘贴一张卡密。
3. 系统读取卡面额度、可用余额与并发，并生成当前可收信的 iCloud 邮箱。
4. 用户只点一次“开始自动注册”。
5. 系统强制完成 ChatGPT 密码和 2FA；二者未齐全时不得报成功。
6. 成功账号释放供应商邮箱并腾出并发槽，随后从同一卡密补位下一个邮箱。
7. 失败邮箱保留，允许重试，不能自动释放或销毁。

用户的核心偏好是：**操作尽量少、系统自动识别、失败不误伤资源、页面显示与真实账号状态一致。**

## 2. 仓库与分支

- 工作目录：`E:\gpt协议注册提链支付\SunnyRegister`
- 开发分支：`main`
- 用户远程：`https://github.com/2282909341/SunnyRegister.git`
- 作者上游：`https://github.com/pxygit/SunnyRegister.git`
- 提交规则见根目录 `AGENTS.md`。修改前必须 `git pull --ff-only`，修改后必须审查、测试、提交并推送 `origin/main`。
- 工作树长期存在大量历史 `_*.sql` / `_*.txt` / `_delivery` 未跟踪文件，**禁止 `git add .`**。

## 3. 技术架构

| 层 | 目录 | 职责 |
|---|---|---|
| 前端 | `frontend/` | React + TypeScript + Vite，工作台、邮箱配置、卡密管理、账号管理和任务日志 |
| 后端 | `backend/` | Go HTTP API、数据模型、任务创建、ic.meigo 配额/生成/释放、静态资源嵌入 |
| Worker | `python-worker/` | Python 认证状态机、协议/浏览器流程、邮箱取码、密码和 2FA、并发与自动补位 |
| 数据库 | PostgreSQL | 本地默认使用 `127.0.0.1:5433`；凭证只从 `.env` 读取 |

运行端口：

- 后端：`http://127.0.0.1:8088`，健康检查 `/api/ready`
- Worker：`http://127.0.0.1:8765`，健康检查 `/health`

## 4. ic.meigo 业务模型

供应商基址在 `backend/icloud_icmeigo.go` 中统一管理。已使用的 API：

- `GET /api/hme/quota`：读取 `remaining_quota`、`total_quota`、`occupied_concurrency`、`total_concurrency`
- `POST /api/hme/generate`：生成一个当前可收信邮箱
- `POST /api/hme/mail`：读取最新邮件/验证码
- `POST /api/hme/release-all`：释放邮箱并腾出并发槽

语义必须区分：

- **卡面额度**：购买的总额度，例如 10。
- **待生成额度**：供应商 `remaining_quota`，通常不包含已生成且仍占用的邮箱。
- **可用余额**：本项目显示为 `当前活跃邮箱 + 待生成额度`，表示还能处理的账号数。
- **并发**：同时可以保持收信的邮箱数，不是卡面额度。

关键不变式：

1. 只有 ChatGPT 密码和 2FA 同时存在时才能自动释放邮箱。
2. 自动释放仅将 `enabled=false`，成功账号的业务状态保持为“已注册”。
3. 用户主动“移除卡密”时，未注册邮箱可标记为“已释放”，但不删除历史行。
4. 失败邮箱不自动释放，否则用户会丢失重试机会。
5. 任务成功/失败必须以密码、2FA 和 Session 实际落库为准，不以页面跳转作为唯一成功信号。

## 5. 当前已实现的可靠性修复

- ic.meigo 任务强制开启密码和 2FA。
- 首次流程发生可恢复认证问题时，使用全新认证上下文自动重试一次。
- `wrong_email_otp_code` 归类为可恢复的旧认证上下文。
- Camoufox/Playwright 已跳转到 ChatGPT 时，`interrupted by another navigation` 不再误判为失败。
- 卡密管理页可显示脱敏后缀、最近导入标识、卡面额度、可用余额、并发、当前邮箱和待生成额度。
- 移除卡密会先调用供应商释放接口，再从本地调度中停用，并保留历史数据。
- 单卡、多卡和 10 张×10 额度已有单元测试覆盖。

## 6. 重要文件定位

| 功能 | 文件 |
|---|---|
| ic.meigo HTTP 协议 | `backend/icloud_icmeigo.go` |
| 卡密导入、摘要、任务准备、移除 | `backend/sunny_register.go` |
| Go 渠道回归测试 | `backend/icloud_icmeigo_test.go` |
| 前端卡密管理/注册工作台 | `frontend/src/pages/SunnyRegister.tsx` |
| Worker 主流程与补位 | `python-worker/sunny_core/worker.py` |
| Worker 数据库写回 | `python-worker/sunny_core/db.py` |
| 认证错误分类 | `python-worker/sunny_core/auth_resilience.py` |
| OpenAI 页面/协议状态机 | `python-worker/sunny_core/openai_auth.py` |
| 流水线回归测试 | `python-worker/tests/test_icmeigo_lazy_provisioning.py` |

## 7. 最合理的用户操作

1. 导入卡密后先进入“邮箱配置→ic.meigo 卡密管理”。
2. 根据“最近导入”和卡密脱敏后缀确认新卡，同时核对“卡面额度”。
3. 10 额度新卡在生成 1 个活跃邮箱后，常见显示是：卡面额度 10、可用余额 10、当前邮箱 1、待生成 9。
4. 回到“自动注册”，选择 ic.meigo，点击一次开始。
5. 部分成功时，成功账号显示“已注册”；失败邮箱保留，可直接重试。
6. 不再使用某张卡时，在卡密管理点“移除卡密”。

## 8. 测试与构建

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

### 前端

```powershell
cd frontend
npm run build
```

前端产物输出到 `backend/static`，Go 后端构建时嵌入。修改前端后必须先构建前端，再重新构建和替换后端可执行文件。

## 9. 本地部署和验证

1. 从 `.env` 导入环境变量，不要打印其值。
2. 后端运行 `bin/SunnyRegister.exe`，端口 8088。
3. Worker 使用 `python-worker/.venv/Scripts/python.exe -m uvicorn worker:app --host 127.0.0.1 --port 8765`。
4. 不要只看进程名，必须核对端口占用 PID、两个健康接口以及 Worker 数据库连接状态。
5. 真实注册验证必须再核对任务表、任务事件、邮箱状态和 Session 落库；健康接口 200 不等于外部注册一定成功。

## 10. 当前现场状态（2026-09-02）

- 最近一个注册任务已终止，不是持续运行：总数 2，成功 1，失败 1。
- 成功账号已完成密码、2FA 与 Session，对应邮箱已腾出并发槽。
- 失败邮箱仍保留且启用，可以重试。
- 现场数据库仅识别到两张卡面额度为 1 的卡；用户提到的 10 额度卡当时并未成功写入数据库。新版卡密管理可通过“最近导入 + 脱敏后缀 + 卡面额度”直接确认。

## 11. 故障排查顺序

1. 查 `/api/ready` 和 `/health`，确认 Worker `running` 列表。
2. 查最新 `tasks` 的 `status/progress_current/progress_total/success_count/error_count`。
3. 查该任务最新 `task_events`，对邮箱、代理和 Token 做脱敏后再记录结论。
4. 核对任务 `payload_json` 里的卡数、`mailbox_ids` 数和 `icmeigo_remaining_quota` 值，不要输出 map 的 key。
5. 卡额度疑问以供应商 quota API 为准，再与本地 `enabled` 邮箱数组合解读。
6. 任务页看似“卡住”时，先判断数据库是 `running`还是已终止；不能只依赖页面缓存。

## 12. 接手者必做清单

1. 读取 `AGENTS.md`、本文档以及最近 5 条 Git 提交。
2. 检查 `git status --short --branch`，仅暂存本次明确修改的文件。
3. `git fetch origin upstream` 并 `git pull --ff-only origin main`。
4. 先读现场数据，再改代码；禁止自动释放失败邮箱。
5. 修改后审查完整 diff，运行对应 Go/Python/前端测试。
6. 构建新后端并重启服务，校验实际端口 PID 和新前端包内容。
7. 提交信息使用 `feat: XXX实现了XXX功能`，直接推送 `origin/main`。

## 13. 开发理解

这条流水线的本质不是“批量生成邮箱”，而是一个受供应商并发槽约束的资源轮转器。最重要的不是追求单次“100% 成功”，而是保证：

- 成功可确认；
- 失败可重试；
- 已购额度不因误释放而丢失；
- 外部页面或网络波动不会被写成虚假成功；
- 用户在页面上只需要看懂“这是哪张卡、还有多少、现在在做什么”。

后续修复应继续围绕这五点，而不是叠加更多需要用户手工点击的选项。
