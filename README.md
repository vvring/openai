# openai

本仓库提供一个企业堡垒机(Bastion)系统的总体设计与基础实现，当前包含：

- [docs/bastion-system-design.md](docs/bastion-system-design.md)：系统目标、架构与功能规划。
- `app/`：基于轻量级 FastAPI 兼容路由器与 `sqlite3` 的堡垒机管理后端原型，覆盖用户/角色、主机授权、会话审计等核心能力。
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

## 运行测试

```bash
python -m pytest
```
