# 部署与运行指南

本文档说明如何在本地或测试环境部署仓库内的堡垒机管理原型服务，并给出快速验证全部已实现能力的步骤。

## 1. 环境准备

- Python 3.11 及以上版本。
- 无需额外依赖，仓库已提供轻量 FastAPI 兼容层与 SQLite 存储。
- 可选：为了隔离运行环境，建议使用 `python -m venv .venv` 创建虚拟环境并激活。

## 2. 配置数据库

服务默认在仓库根目录创建 `bastion.db` 文件，若希望自定义路径或使用外部数据库，可设置环境变量：

```bash
export BASTION_DATABASE_URL="sqlite:////path/to/bastion.db"
```

支持标准 SQLite 连接串，后续也可以替换为企业级数据库（如 PostgreSQL）。

## 3. 启动管理服务

使用仓库提供的内置 HTTP 服务器启动 REST 接口：

```bash
python -m app.server
```

默认监听 `0.0.0.0:8000`，控制台会输出启动日志。若需修改监听地址或端口，可在源码中调用 `app.server.run(host="127.0.0.1", port=9000)` 或构建上层进程管理脚本。

## 4. 健康校验

服务启动后可通过 `curl` 进行最小化验证：

```bash
# 查询用户列表（初次为空）
curl http://127.0.0.1:8000/users

# 创建用户
curl -X POST http://127.0.0.1:8000/users \
  -H 'Content-Type: application/json' \
  -d '{"username": "ops", "full_name": "Ops Engineer", "email": "ops@example.com", "roles": ["operator"]}'

# 创建主机并绑定授权
curl -X POST http://127.0.0.1:8000/hosts \
  -H 'Content-Type: application/json' \
  -d '{"name": "db01", "hostname": "db01.internal", "port": 22, "operating_system": "linux", "protocols": ["ssh"], "tls_enabled": true, "rdp_nla": true}'

curl -X POST http://127.0.0.1:8000/authorizations \
  -H 'Content-Type: application/json' \
  -d '{"user_id": 1, "host_id": 1, "privileges": "read"}'
```

返回 `201` / `204` 状态码表示操作成功，后续即可继续创建会话、录入网关、凭据、策略等信息。

## 5. 全量功能验证

项目附带的 `pytest` 集成测试覆盖了所有已完成功能（用户/主机管理、授权治理、访问时间窗、审批、命令策略、凭据库、协议网关、连接指引等）。在部署前后执行以下命令可确保功能正常：

```bash
python -m pytest
```

所有用例通过后，代表当前交付的功能行为与设计文档一致。

## 6. 运行与维护建议

- 服务默认以前台模式运行，可结合 `systemd`、`supervisord` 或容器平台编排生命周期管理。
- 生产部署建议：
  - 使用外部数据库以获得持久化能力与备份策略。
  - 将 HTTP 服务置于反向代理（Nginx/Traefik）之后，启用 TLS 与访问控制。
  - 配置日志轮转与监控，结合未来规划中的网关与前端控制台组件实现完整堡垒机体系。

完成上述步骤后，即可在本地或测试环境体验堡垒机管理原型的全部能力，并保证与当前文档中的功能列表保持一致。
