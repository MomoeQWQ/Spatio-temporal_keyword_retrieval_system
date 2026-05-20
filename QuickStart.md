# 具有隐私保护的可验证空间关键词检索系统

本项目是一个面向毕业设计提交的可运行原型系统，支持“关键词 + 空间范围”的隐私保护检索、多个 CSP 协同执行、客户端结果恢复与验证，并包含统一 token 编译执行、RAPQ+ 候选检索和分层验证等扩展机制。

## 目录结构

| 路径 | 内容 |
| --- | --- |
| `run_cli.py` | CLI 客户端入口 |
| `run_csp.py` | 单个 CSP 服务端入口 |
| `run_all.py` | 一键启动 3 个 CSP 并执行一次 CLI 查询 |
| `run_owner_setup.py` | 数据拥有者索引构建入口 |
| `run_gui_client.py` | GUI 客户端入口 |
| `run_gui_server.py` | GUI 服务端入口 |
| `run_web.py` | Web 原型入口 |
| `core/` | 底层原理与检索核心，包括 GBF、DMPF、索引构建、查询共享、验证、RAPQ+ 和 LLM 扩展搜索模块 |
| `apps/` | 工程实现，包括 CLI、GUI、Web、CSP 服务端、用户管理和权限控制 |
| `evaluation/scripts/` | 性能评估、功能测试和查询扩展评估脚本 |
| `evaluation/outputs/` | 实验输出指标、CSV、JSON 和生成图 |
| `conFig.ini` | 系统参数配置 |
| `us-colleges-and-universities.csv` | 默认测试数据集 |

## 快速运行

构建或刷新认证索引：

```bash
python run_owner_setup.py
```

一键运行在线多 CSP 查询：

```bash
python run_all.py "ORLANDO UNIVERSITY; R: 28.2,-81.6,28.8,-81.1"
```

单独启动 CSP：

```bash
python run_csp.py --port 8001 --aui apps/cli/aui.pkl --user-db apps/cli/users_db.json
```

CLI 查询：

```bash
python run_cli.py --query "ORLANDO UNIVERSITY; R: 28.2,-81.6,28.8,-81.1" --expansion-mode fallback --retrieval-mode rapq_plus
```

启动 GUI：

```bash
python run_gui_server.py
python run_gui_client.py
```

启动 Web 原型：

```bash
python run_web.py
```

浏览器访问：`http://127.0.0.1:5099`

## LLM 扩展搜索

CLI、GUI 和 Web 均已接入扩展搜索。默认可使用本地 fallback 词典；如需 Gemini 扩展，安装 `google-generativeai` 并设置环境变量：

```bash
set GEMINI_API_KEY=你的密钥
python run_cli.py --query "COLLEGE" --expansion-mode gemini
```

若 Gemini 不可用，系统会自动回退到本地扩展词典，不影响基础查询。

## 实验与测试

性能评估脚本集中在 `evaluation/scripts/`：

```bash
python evaluation/scripts/performance_study.py
python evaluation/scripts/rapq_benchmark.py
python evaluation/scripts/evaluate_query_expansion.py
python evaluation/scripts/simulate_group_queries.py
```

实验输出统一保存在 `evaluation/outputs/`，其中 `evaluation/outputs/figures/` 存放生成图。
