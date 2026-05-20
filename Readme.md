# 具有隐私保护的可验证空间关键词检索系统

本仓库实现了一个面向空间关键词数据的隐私保护检索原型系统。系统支持“关键词 + 空间范围”的联合查询，能够在多个云服务提供商（Cloud Service Provider, CSP）协同执行的场景下完成密态检索、客户端结果恢复与结果验证。项目同时提供命令行、图形界面和 Web 原型，便于进行功能演示、实验复现和答辩展示。

本项目是毕业设计工程原型，重点在于系统实现、查询执行优化、候选检索加速和验证流程组织；其中 Garbled Bloom Filter、DMPF、HMAC 等底层密码学工具作为基础组件使用。

## 功能特性

- **空间关键词联合查询**：支持关键词条件与空间范围条件组合查询，查询格式示例为 `ORLANDO UNIVERSITY; R: 28.2,-81.6,28.8,-81.1`。
- **密态索引构建**：使用 Bloom Filter / Garbled Bloom Filter 对关键词 token 与空间 cell token 进行编码，并生成认证索引与密钥材料。
- **多 CSP 协同执行**：客户端将查询计划拆分为多个份额，由多个 CSP 分别执行局部密态计算，避免单个 CSP 直接获得完整查询选择逻辑。
- **结果恢复与验证**：客户端合并各 CSP 返回的结果份额，并通过验证机制检查返回结果是否与查询执行过程一致。
- **统一 token 编译执行**：对原始关键词、扩展词和空间 cell 进行统一 token 化与去重，减少扩展查询场景下的重复执行。
- **RAPQ+ 候选检索**：利用关键词倒排表、空间 cell 倒排表和稀有度排序生成候选集合，在候选覆盖充分时缩小在线执行范围。
- **分层验证机制**：快速阶段提供候选子集绑定和随机哨兵抽检，完整阶段保留 FX+HMAC 验证路径。
- **用户与权限管理**：支持用户登录、用户组、空间查询权限、最大关键词数量等基础权限控制。
- **多种运行入口**：提供 CLI、GUI、Web 三类演示方式，并保留实验评估脚本和生成图表。

## 环境要求

推荐环境：

- 操作系统：Windows 10/11，Linux/macOS 理论上可运行但主要在 Windows 环境下测试
- Python：`3.10` 或更高版本
- pip：建议使用 Python 对应版本的 `pip`
- 可选：MinGW / MSYS2，用于编译 C++ XOR 加速模块；未编译时系统会自动使用 Python fallback

## 安装依赖

建议先创建虚拟环境：

```bash
python -m venv .venv
.venv\Scripts\activate
```

安装依赖：

```bash
pip install -r requirements.txt
```

核心依赖包括：

| 依赖 | 用途 |
| --- | --- |
| `pandas` | 数据集读取与结果表处理 |
| `numpy` | 实验统计与图表数据处理 |
| `matplotlib` | 性能评估图生成 |
| `Flask` | Web 原型服务 |
| `google-generativeai` | 可选，Gemini LLM 扩展搜索 |

如果不使用 Gemini 扩展搜索，可以忽略 `google-generativeai` 相关配置。默认 fallback 扩展词典不需要外部 API。

## 目录结构

```text
Project_Crypto/
├─ run_owner_setup.py          # 数据拥有者：构建认证索引与密钥
├─ run_csp.py                  # 单个 CSP 服务端入口
├─ run_cli.py                  # CLI 客户端入口
├─ run_all.py                  # 一键启动多 CSP 并执行一次查询
├─ run_gui_server.py           # GUI 服务端入口
├─ run_gui_client.py           # GUI 客户端入口
├─ run_web.py                  # Web 原型入口
├─ conFig.ini                  # 系统参数配置
├─ requirements.txt            # Python 依赖列表
├─ QuickStart.md               # 快速运行说明
├─ us-colleges-and-universities.csv
│
├─ core/                       # 底层原理脚本与检索核心
│  ├─ GBF.py                   # Garbled Bloom Filter 相关实现
│  ├─ DMPF.py                  # 查询共享 / 多点选择份额生成
│  ├─ SetupProcess.py          # 认证索引构建、掩码、标签生成
│  ├─ verification.py          # 结果验证与快速标签校验
│  ├─ QueryUtils.py            # 查询规范化与 token 处理
│  ├─ config_loader.py         # 配置读取
│  ├─ prepare_dataset.py       # 数据集读取与清洗
│  ├─ convert_dataset.py       # 明文记录到索引对象的转换
│  ├─ ai_clients/              # 可选 LLM 客户端
│  └─ secure_search/           # 查询计划、RAPQ+、排序、扩展搜索等核心逻辑
│
├─ apps/                       # 工程实现脚本
│  ├─ cli/                     # CLI、CSP 服务端、用户管理
│  ├─ gui/                     # Tkinter GUI 客户端与服务端
│  └─ web/                     # Flask Web 原型
│
└─ evaluation/                 # 实验评估与生成结果
   ├─ scripts/                 # 性能测试、RAPQ+ 测试、扩展查询测试
   └─ outputs/                 # CSV/JSON 指标与图表输出
```

## 快速开始

### 1. 构建认证索引

```bash
python run_owner_setup.py
```

该命令会读取 `us-colleges-and-universities.csv` 和 `conFig.ini`，在 `apps/cli/` 下生成：

- `aui.pkl`：认证索引
- `K.pkl`：客户端密钥材料

### 2. 一键运行 CLI 查询

```bash
python run_all.py "ORLANDO UNIVERSITY; R: 28.2,-81.6,28.8,-81.1"
```

该命令会自动启动 3 个 CSP 服务端，然后调用 CLI 客户端完成一次查询。

### 3. 单独启动 CSP 与客户端

启动一个 CSP：

```bash
python run_csp.py --port 8001 --aui apps/cli/aui.pkl --user-db apps/cli/users_db.json
```

另开终端运行客户端：

```bash
python run_cli.py --query "ORLANDO" --csp http://127.0.0.1:8001 http://127.0.0.1:8002 http://127.0.0.1:8003
```

通常建议使用 `run_all.py` 进行快速演示；手动启动 CSP 更适合调试服务端接口。

## CLI 查询模式

基础查询：

```bash
python run_cli.py --query "ORLANDO" --expansion-mode none --retrieval-mode legacy
```

fallback 扩展查询：

```bash
python run_cli.py --query "UNIVERSITY" --expansion-mode fallback --max-expansion-terms 3
```

RAPQ+ 快速候选检索：

```bash
python run_cli.py --query "ORLANDO" --expansion-mode none --retrieval-mode rapq_plus --top-k 10
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--query` | 查询字符串，支持关键词与 `R:` 空间范围 |
| `--expansion-mode` | 扩展模式：`none`、`fallback`、`gemini` |
| `--retrieval-mode` | 检索模式：`legacy`、`rapq`、`rapq_plus` |
| `--top-k` | 输出前 K 条排序结果 |
| `--max-expansion-terms` | 每个关键词最多扩展词数量 |
| `--rapq-sentinels` | RAPQ+ 随机哨兵抽检数量 |

## LLM 扩展搜索

系统已将 LLM 扩展搜索接入 CLI、GUI 和 Web。默认可使用本地 fallback 词典，无需联网或 API Key。

如需使用 Gemini：

```bash
set GEMINI_API_KEY=你的_API_KEY
python run_cli.py --query "COLLEGE" --expansion-mode gemini
```

当 Gemini 依赖缺失、API Key 未配置或请求失败时，系统会自动回退到 fallback 扩展，不影响基础检索流程。

## GUI 演示

先启动服务端 GUI：

```bash
python run_gui_server.py
```

再启动客户端 GUI：

```bash
python run_gui_client.py
```

GUI 客户端支持配置索引路径、密钥路径、CSP 地址、用户登录信息、扩展模式和 Top-K 输出，并以表格形式展示查询结果。

## Web 原型

启动 Web：

```bash
python run_web.py
```

访问地址：

```text
http://127.0.0.1:5099
```

Web 原型支持：

- 用户登录与查询
- 管理员登录
- 用户组与权限配置
- CSP 端口启动与停止
- AUI、密钥、数据集和配置路径管理
- 查询结果展示

默认用户信息位于 `apps/cli/users_db.json`。

## 实验复现

性能评估脚本位于 `evaluation/scripts/`。

基础性能测试：

```bash
python evaluation/scripts/performance_study.py
```

RAPQ+ 性能与命中一致性测试：

```bash
python evaluation/scripts/rapq_benchmark.py
```

扩展查询评估：

```bash
python evaluation/scripts/evaluate_query_expansion.py
```

用户组权限通信模拟：

```bash
python evaluation/scripts/simulate_group_queries.py
```

实验输出位于：

```text
evaluation/outputs/
```

主要输出包括：

- `metrics.json`
- `rapq_metrics.csv`
- `rapq_metrics.json`
- `figures/` 下的性能图与系统演示截图

## 数据与配置

默认数据集：

```text
us-colleges-and-universities.csv
```

配置文件：

```text
conFig.ini
```

`conFig.ini` 中包含安全参数、Bloom Filter 参数、空间网格大小、多 CSP 数量等配置。修改数据集或配置后，建议重新运行：

```bash
python run_owner_setup.py
```

## 可选 C++ 加速

项目保留了可选 C++ XOR 加速模块源码：

```text
core/secure_search/_native_accel.cpp
```

如果未编译该模块，系统会自动使用 Python fallback，不影响功能正确性。若需要构建扩展，可根据本机编译环境运行：

```bash
python core/setup_native_accel.py build_ext --inplace
```

## 注意事项

- RAPQ+ 是候选驱动的快速检索路径，并不等价于完整验证路径。
- 快速阶段的候选子集绑定和哨兵抽检用于提供轻量一致性检查，最终严格验证仍应以完整验证路径为准。
- LLM 扩展搜索运行在客户端侧；使用 Gemini 时需要自行配置 API Key。
- Web 服务使用 Flask 开发服务器，仅用于本地演示，不建议直接用于生产部署。

## 项目状态

本仓库为毕业设计提交版本，已移除论文文档、参考文献 PDF、AI 写作 Skill、中间文档和已弃用实验代码，仅保留系统运行、核心算法、工程入口和实验评估所需内容。
