# Web Demo

本目录提供可本地浏览器访问的 Web 端实现，包含：
- 客户端登录与查询（支持扩展模式与排序结果）。
- 管理员后台（用户组/权限管理、用户管理、CSP端口启停、AUI/数据库等路径配置）。

## 启动
在项目根目录执行：
```bash
python web_demo/app.py
```
默认访问地址：
- `http://127.0.0.1:5099/` 客户端入口
- `http://127.0.0.1:5099/admin` 管理员后台入口

## 初始账号
- 管理员：`admin / admin123`
- 普通用户：`alice / alice123`

## 管理能力
- 用户组与权限：`can_search`、`allow_spatial`、`max_keywords`、`can_manage_users`、`can_manage_groups`
- 用户管理：创建/更新用户、分配组、启用/禁用
- 运行控制：一键开启/关闭 CSP 端口
- 系统配置：AUI 路径、Keys 路径、数据集路径、配置文件路径、用户库路径、CSP 端口

配置文件保存位置：
- `web_demo/web_config.json`
