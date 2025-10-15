# openai

本仓库提供一个企业堡垒机(Bastion)系统的总体设计与基础实现，当前包含：

- [docs/bastion-system-design.md](docs/bastion-system-design.md)：系统目标、架构与功能规划。
- `app/`：基于 FastAPI + SQLAlchemy 的堡垒机管理后端原型，覆盖用户/角色、主机授权、会话审计等核心能力。

## 快速开始

1. 安装依赖：

   ```bash
   pip install -r requirements.txt
   ```

2. 启动管理服务：

   ```bash
   uvicorn app.main:app --reload
   ```

   默认使用 `sqlite:///./bastion.db` 数据库，可通过环境变量 `BASTION_DATABASE_URL` 指定其他数据库。

3. 通过 [http://localhost:8000/docs](http://localhost:8000/docs) 访问交互式接口文档，执行用户管理、主机授权、会话记录等操作。

## 运行测试

```bash
pytest
```
