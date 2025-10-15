# openai

本仓库提供一个企业堡垒机(Bastion)系统的总体设计与基础实现，当前包含：

- [docs/bastion-system-design.md](docs/bastion-system-design.md)：系统目标、架构与功能规划。
- `app/`：基于轻量级 FastAPI 兼容路由器与 `sqlite3` 的堡垒机管理后端原型，覆盖用户/角色、主机授权、会话审计与录像目录等核心能力。
- [docs/development-progress.md](docs/development-progress.md)：分阶段开发目标与当前完成情况。

## 快速开始

1. 本仓库当前实现聚焦于管理核心业务逻辑与数据持久化，使用自研的 FastAPI 兼容层运行于本地进程，无需额外依赖安装。

2. 设置数据库位置（可选）：

   ```bash
   export BASTION_DATABASE_URL="sqlite:///./bastion.db"
   ```

   未设置时默认写入仓库根目录下的 `bastion.db` 文件。

3. 运行集成测试以验证核心流程：

   ```bash
   python -m pytest
   ```

   测试用例会通过 HTTP 风格的请求模拟器执行用户创建、主机注册、授权绑定、会话录像等端到端场景。

4. 启动管理 API 服务（可选）：

   ```bash
   python -m app.server
   ```

   默认监听 `0.0.0.0:8000`，可结合 `curl` 或 Postman 调用 REST 接口，配合第 3 步的自动化测试校验功能完整性。

## 当前能力速览

- 用户、角色、主机、授权的 CRUD 接口。
- 用户支持详情查询、角色/邮箱更新与启用状态切换，便于快速冻结或恢复账号。
- 授权目录管理：支持按用户或主机查询授权关系，并可撤销授权，权限类型限定为 `read`、`read-write`、`admin`。
- 授权支持配置 `requires_approval`，可触发双人审批流程。
- 主机支持在线调整协议组合、端口以及 TLS/NLA 标记，并在启用 RDP 时校验必须开启 NLA。
- 主机资产支持维护标签、环境、所属业务信息，并可按协议/环境/标签/关键词筛选资产清单。
- 主机分组能力：可以创建主机分组并批量绑定主机，支持按主机过滤分组列表以及在组内查看主机详情。
- 主机凭据库：通过 `/credentials` 管理账号密码/SSH Key，记录轮换频率、最近轮换时间与启用状态，避免明文散落。
- 协议网关编排：`/protocol-gateways` 提供网关登记、查询、更新、删除与健康上报接口，并支持通过 `/hosts/{id}/gateways/{protocol}` 为主机协议指派网关，主机详情会展示已绑定网关。
- 会话生命周期记录：开始/结束时间、使用协议、关联录像路径与附加元数据。
- 会话、录像检索：支持按用户、主机、协议、时间窗口过滤会话列表，并可按用户/主机/协议筛选录像记录。
- 录像目录管理：自动登记录像文件的存储路径、大小、时长、校验值，可按会话过滤并提供单条查询。
- 会话发起校验：在启动会话时校验用户启用状态、授权关系、主机支持协议情况，并强制 RDP 会话启用 NLA。
- 会话网关强制：会话启动前会验证主机与协议是否存在激活的网关绑定，并在会话元数据及连接指引中记录网关信息（SSH/SFTP 命令自动带上 ProxyJump 参量）。
- 授权来源 IP 控制：授权可配置 `source_cidrs` CIDR 白名单，会话启动请求必须携带 `source_ip` 并命中白名单才允许建立连接。
- 命令策略防护：通过 `/command-policies` 维护命令允许/禁止模式，授权绑定策略后会要求会话发起时提供 `requested_commands` 并在建立连接前完成校验。
- 会话登录指引：通过 `/sessions/{id}/connections` 生成基于主机协议与凭据的登录命令、注意事项，并允许记录连接结果与失败原因，辅助运维快速定位连接问题。
- 授权调度：支持维护“访问时间窗”策略，可为授权绑定允许的星期与时间范围，会话发起时将按照策略校验是否在授权时段内。
- 会话详情查询：可获取单条会话及关联录像列表，支撑审计回溯与取证。
- 操作审计：支持在关键管理接口中携带 `performed_by` 标识操作者，所有资产、账号与授权更改均写入审计事件表，并可通过 `/audit-events` 组合筛选。
- 双人审批：`/access-requests` 提供申请、审批、拒绝、撤销接口，管理员/审计员可限定审批有效期，会话发起时将校验审批状态。
- 分页能力：用户、主机、授权、会话、录像与审计事件列表均支持 `limit` / `offset` 参数，便于在资产规模扩张时进行批量浏览与前端分页展示。
- 主机分组接口：`/host-groups` 提供创建、查询、更新与删除能力，`/host-groups/{id}/hosts` 支持绑定/解绑主机，所有操作均支持 `performed_by` 审计入库。

## 功能验证与部署

- **自动化回归**：执行 `python -m pytest` 可覆盖所有已实现的管理、授权、审计、审批、命令策略、网关等流程，确保功能行为稳定。
- **本地部署**：通过 `python -m app.server` 可直接启动内置 HTTP 服务，无需额外依赖。详细部署指引（含数据库路径、端口修改与样例调用）见 [docs/deployment-guide.md](docs/deployment-guide.md)。
- **功能巡检脚本**：运行 `python scripts/verify_installation.py` 将自动初始化演示数据库、启动 HTTP 服务并串联用户、主机、授权、会话、连接指引等核心流程，输出的 JSON 结果可作为验收凭证与日常健康检查脚本。

## 示例：通过 API 登录目标主机

目前项目仍以前后端分离架构为目标，Web 控制台尚在规划阶段。以下步骤展示了如何使用已经完成的管理 API 进行运维登录：

1. **准备环境**：启动服务 `python -m app.server`（如需指定数据库文件，可通过 `BASTION_DATABASE_URL` 环境变量设定）。
2. **创建管理员与运维用户**：分别向 `/users` 提交管理员（包含 `admin` / `operator` 角色）和运维员账号，记录返回的 `id`。
3. **登记协议网关与主机**：
   - 调用 `/protocol-gateways` 注册 SSH/RDP 等协议网关。
   - 调用 `/hosts` 创建目标主机，并通过 `/hosts/{host_id}/gateways/{protocol}` 绑定对应网关。
4. **录入主机凭据与授权**：
   - 在 `/credentials` 保存目标主机的登录凭据（密码或 SSH Key），建议由管理员维护并设置 `performed_by` 便于审计。
   - 通过 `/authorizations` 为运维员授予访问权限，可选配置来源 IP 白名单 `source_cidrs`、命令策略 `command_policy_id` 以及审批开关 `requires_approval`。
5. **发起会话**：运维员调用 `/sessions`，携带 `user_id`、`host_id`、`protocol`、`source_ip` 以及可选的 `requested_commands` 即可申请访问。系统会自动校验授权、审批、命令策略与访问时间窗等限制。
6. **获取登录指引**：在会话保持开启状态时，调用 `/sessions/{session_id}/connections` 并传入运维员 ID 与凭据 ID，即可获得带有 ProxyJump、TLS 等参数的标准登录命令。完成实际登录后，可通过 `/session-connections/{attempt_id}` 更新为 `succeeded` 或 `failed` 并记录原因。

上述流程亦可通过 `scripts/verify_installation.py` 自动化执行一次演示运行，脚本最终会输出会话与连接指引示例，帮助快速确认部署是否可用。

## 操作审计说明

- 创建/更新用户、主机与授权关系时，可在请求体中传入 `performed_by`（管理用户 ID），服务端将校验操作者存在后将事件写入审计日志。
- 访问时间窗（Access Window）管理接口 `/access-windows` 支持创建、更新、删除与列表查询，可结合授权接口 `access_window_id` 字段绑定使用。
- 撤销授权时，通过查询参数 `?performed_by=<admin_id>` 指定操作者。
- 会话启动与结束自动使用发起人账号写入 `session.started` 与 `session.ended` 事件，包含协议、录像产出等上下文信息。
- 当授权绑定命令策略时，会话启动需在请求体中提供 `requested_commands`，服务会校验命令是否命中禁止模式或未匹配允许模式，并在审计事件与会话元数据中保留指纹。
- `/audit-events` 支持按 `actor_id`、`action`、`target_type`、`target_id` 以及时间窗口过滤，返回按时间倒序排列的事件列表。

## 运行测试

```bash
python -m pytest
```
