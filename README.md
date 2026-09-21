# GPT BUSINESS Manager

面向 Gmail 子号、GPT 账号注册和 BUSINESS 多席位工作区的独立管理系统。项目提供账号导入、代理分配、无头浏览器注册、邮箱验证、密码与 Authenticator 2FA、短信接码、批量邀请、成员退出和可恢复任务。

> 本项目不是 Google 或 OpenAI 官方产品。请仅管理你有权使用的邮箱、账号和工作区，并遵守服务提供方的使用条款。

## 主要功能

| 模块 | 功能 |
| --- | --- |
| 管理后台 | 管理员密码、TOTP 二次验证、HttpOnly 会话、明暗主题 |
| 普通账号 | 导入 Gmail 子号、查看注册状态、批量注册、失败重试和日志 |
| Gmail 收件 | Gmail 母号共享授权、+alias 子号关联、验证码精确匹配 |
| GPT 注册 | 密码注册、邮箱验证、资料完善、2FA 设置和登录会话保存 |
| BUSINESS 母号 | 导入母号、登录、刷新工作区、识别普通/高级席位和成员 |
| 席位管理 | 按剩余席位批量选择子号、并发准备、批量邀请和批量退出 |
| 代理管理 | 单个或批量导入、连通性检测、注册租约和代理隔离 |
| 短信接码 | SMSBower、GrizzlySMS 统一接口、余额查询和激活记录 |
| 任务恢复 | 持久任务、步骤日志、租约、防重复执行和服务重启恢复 |
| 数据安全 | AES-256-GCM 凭证加密、Argon2id 管理员密码、默认关闭 API 文档 |

系统包含两个主要账号页面：

- **普通账号**：管理 Gmail 子号及其 GPT 注册、安全设置和后续状态。
- **BUSINESS 母号**：管理多席位工作区、邀请额度、成员和批量操作。

## 技术结构

- 后端：Python 3.13、FastAPI、SQLModel、Alembic。
- 前端：React 19、TypeScript、Ant Design、Vite。
- 浏览器自动化：Chrome/Chromium，Linux 默认无头运行。
- 数据库：默认 SQLite，也支持 PostgreSQL URL。
- 部署：本机脚本、Docker Compose、HTTPS 反向代理。

前端只访问同源 /api。浏览器任务在后台线程执行，外部操作使用持久任务、步骤和租约记录，进程重启后可从已经确认的状态继续。

## 环境要求

本机部署需要：

- Python 3.13
- Node.js 20.19+ 或 22.12+
- Chrome、Chromium 或 Google Chrome Stable
- 推荐安装 uv，未安装时脚本会使用 venv 和 pip

Docker 部署会在镜像中安装 Chromium，不需要宿主机额外安装浏览器。

## 本机快速部署

~~~bash
git clone https://github.com/sunboyzoey/gpt-business-manager.git
cd gpt-business-manager
./scripts/setup.sh
./scripts/server.sh start
~~~

访问：

~~~text
http://127.0.0.1:8011/
~~~

首次打开时设置管理员密码，随后建议在“设置”中启用管理员 TOTP。

常用命令：

~~~bash
./scripts/server.sh status
./scripts/server.sh restart
./scripts/server.sh stop
~~~

setup.sh 会创建 .venv、安装锁定的 Python/Node.js 依赖并构建前端。修改前端后需要重新构建：

~~~bash
cd frontend
npm ci --no-audit --no-fund
npm run build
cd ..
./scripts/server.sh restart
~~~

## Docker Compose 部署

~~~bash
git clone https://github.com/sunboyzoey/gpt-business-manager.git
cd gpt-business-manager
cp .env.example .env
docker compose up -d --build
~~~

默认只映射到宿主机 127.0.0.1:8011。查看运行状态：

~~~bash
docker compose ps
docker compose logs -f app
curl http://127.0.0.1:8011/healthz
~~~

如果 Docker 网络使首次初始化请求不再表现为回环请求，可直接在容器内部初始化管理员密码：

~~~bash
docker compose exec app python -c 'import getpass,json,urllib.request; p=getpass.getpass("管理员密码："); r=urllib.request.Request("http://127.0.0.1:8011/api/auth/setup",data=json.dumps({"password":p}).encode(),headers={"Content-Type":"application/json"},method="POST"); urllib.request.urlopen(r,timeout=10).read(); print("初始化完成")'
~~~

数据保存在 Docker 卷 gbm_data。升级前必须同时备份数据库与凭证加密密钥。

## Linux 服务器部署

先使用发行版软件源、pyenv 或 uv 安装 Python 3.13。以 Debian/Ubuntu 安装其余系统依赖为例：

~~~bash
sudo apt-get update
sudo apt-get install -y chromium nodejs npm
git clone https://github.com/sunboyzoey/gpt-business-manager.git
cd gpt-business-manager
export DRISSION_BROWSER_PATH=/usr/bin/chromium
./scripts/setup.sh
./scripts/server.sh start
~~~

不同发行版请安装对应的 Chrome/Chromium 软件包。项目会自动查找 google-chrome、google-chrome-stable、chromium 和 chromium-browser。也可以在 .env 中设置：

~~~dotenv
DRISSION_BROWSER_PATH=/usr/bin/chromium
~~~

默认无头模式不依赖 DISPLAY 或 Xvfb。使用有头浏览器调试时才需要桌面环境。

## 公网 HTTPS 部署

应用默认只监听 127.0.0.1。生产环境建议保持本机监听，并通过 Nginx、Caddy 或其他反向代理提供 HTTPS。

.env 至少设置：

~~~dotenv
GBM_HOST=127.0.0.1
GBM_PORT=8011
GBM_COOKIE_SECURE=true
GBM_ENABLE_API_DOCS=false
~~~

建议执行两次以下命令，生成两个独立随机密钥：

~~~bash
openssl rand -hex 32
~~~

分别写入 .env：

~~~dotenv
GBM_APP_CREDENTIAL_ENCRYPTION_KEY=<第一个随机值>
GBM_APP_JWT_SECRET=<第二个随机值>
~~~

Nginx 示例：

~~~nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:8011;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
~~~

首次管理员初始化只能从服务器回环地址执行。远程服务器可先建立 SSH 隧道：

~~~bash
ssh -L 8011:127.0.0.1:8011 user@server
~~~

然后在本机访问 http://127.0.0.1:8011/ 完成初始化，再开放 HTTPS 域名。

## 数据目录与备份

默认运行数据位于 data/：

| 文件 | 用途 |
| --- | --- |
| data/workspace.db | SQLite 数据库 |
| data/chatgpt_security.key | 账号凭证加密密钥 |
| data/server.log | 服务日志 |
| data/server.pid | 本机服务进程记录 |

可通过以下变量修改：

~~~dotenv
GBM_RUNTIME_DIR=/srv/gpt-business-manager/data
GBM_DATABASE_URL=sqlite:////srv/gpt-business-manager/data/workspace.db
~~~

PostgreSQL 示例：

~~~dotenv
GBM_DATABASE_URL=postgresql+psycopg://gbm:change-me@127.0.0.1:5432/gbm
~~~

账号密码、TOTP 密钥、恢复码和服务商密钥使用 AES-256-GCM 加密。只备份数据库而不备份加密密钥将无法恢复凭证。不要把数据库、密钥、日志、Cookie、浏览器资料或 .env 提交到 Git。

## 推荐使用顺序

1. 初始化管理员密码并启用管理员 TOTP。
2. 在“代理管理”中导入并检测注册代理。
3. 在“短信接码”中配置服务商并验证余额查询。
4. 在“普通账号”中导入 Gmail 子号迁移包。
5. 批量注册未注册子号，观察步骤日志和失败原因。
6. 在“BUSINESS 母号”中导入母号并执行登录与工作区刷新。
7. 根据真实普通/高级剩余席位批量准备并邀请子号。

### Gmail 子号导入

项目不提供独立 Gmail 管理页面。迁移包为每个 Gmail 母号保存一份共享收件授权，并关联该母号生成的 +alias 子号。导入时先验证共享 IMAP 收件能力，再建立母子关系；重复导入会更新原记录，不会生成重复账号。

### BUSINESS 母号导入

支持以下文本格式：

~~~text
邮箱----GPT密码
邮箱----GPT密码----2FA密钥
邮箱----邮箱密码----refresh_token----client_id
~~~

也可以从兼容系统导出的 JSON 迁移包导入。导入只建立管理记录，不会伪造登录状态、套餐类型、席位余额或成员信息。首次登录和工作区刷新会读取真实状态。

## 配置原则

- 普通配置通过管理后台保存。
- API Key、邮箱密码和服务商密钥只写入加密存储，不会通过配置查询接口回显。
- .env 仅保存部署级设置，不应提交到 Git。
- API 文档默认关闭；只在本地开发时设置 GBM_ENABLE_API_DOCS=true。
- 默认监听回环地址；公网使用必须配置 HTTPS、安全 Cookie 和管理员 TOTP。

完整变量示例见 [.env.example](.env.example)，安全发布要求见 [SECURITY.md](SECURITY.md)，系统状态机和模块边界见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 测试

安装依赖后运行：

~~~bash
.venv/bin/python -m pytest -q tests
cd frontend
node --test tests/*.test.mjs
npm audit
~~~

界面流程测试：

~~~bash
.venv/bin/python scripts/smoke_ui.py
.venv/bin/python frontend/tests/proxy_ui_smoke.py
~~~

测试使用临时数据库和合成账号，不会向 Gmail 或 ChatGPT 提交真实注册和邀请操作。

## 开发

后端开发模式：

~~~bash
GBM_RELOAD=1 .venv/bin/python main.py
~~~

前端开发模式：

~~~bash
cd frontend
npm run dev
~~~

前端开发服务器默认监听 127.0.0.1:5174，并将 /api 代理到 127.0.0.1:8011。

## 安全与发布

- 管理员密码使用 Argon2id。
- 管理员会话使用签名、版本化、HttpOnly、SameSite Cookie。
- 账号敏感字段使用独立密钥和 AES-256-GCM 信封加密。
- API 响应默认设置 no-store、CSP、禁止 iframe 和 MIME 嗅探等安全响应头。
- GitHub Actions 会执行后端测试、前端构建、依赖审计和 Gitleaks 扫描。
- 发布时应使用干净克隆或 git archive，不要直接压缩包含运行数据的工作目录。

发现安全问题时请按照 [SECURITY.md](SECURITY.md) 私下报告，不要在公开 Issue 中提交账号、Cookie、Token、密码、2FA 密钥或数据库。

## License

[MIT License](LICENSE)
