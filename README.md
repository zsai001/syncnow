# SyncNow Self-Hosted Relay (`syncnow-relay`)

开源、零明文端到端加密（E2EE）的 [**SyncNow**](https://xtags.top/syncnow) 自建中继与同账号信令服务端。  
同时支持 **Cloudflare Workers 一键网页部署（免 GitHub App · 免费套餐可用）**、**Docker / Docker Compose（含自动 HTTPS）** 与 **Linux VPS 一行安装**，安装完成后直接在浏览器打开 **`/setup`** 完成可视化初始化。

[![SyncNow Product](https://img.shields.io/badge/SyncNow-%E5%AE%98%E7%BD%91%E4%B8%8E%E5%AE%A2%E6%88%B7%E7%AB%AF%E4%B8%8B%E8%BD%BD-2563EB?style=for-the-badge&logo=apple&logoColor=white)](https://xtags.top/syncnow)
[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy%20to%20Cloudflare%20Workers-%E4%B8%80%E9%94%AE%E9%83%A8%E7%BD%B2%EF%BC%88%E5%85%8D%20GitHub%20App%EF%BC%89-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://xtags.top/deploy/syncnow)
[![Docker Ready](https://img.shields.io/badge/Docker-Compose%20%2B%20Auto%20HTTPS-2496ED?style=for-the-badge&logo=docker&logoColor=white)](#方式二docker--docker-compose-部署)
[![Linux VPS](https://img.shields.io/badge/Linux%20VPS-1--Line%20systemd-10B981?style=for-the-badge&logo=linux&logoColor=white)](#方式三linux-vps-一行-systemd-直装无需-git-clone)
[![Support on X](https://img.shields.io/badge/Support-@zsai010%20on%20X-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/zsai010)

> **Open-Source, Zero-Knowledge Self-Hosted Relay for [SyncNow](https://xtags.top/syncnow).**  
> Download SyncNow at **[xtags.top/syncnow](https://xtags.top/syncnow)**. Supports **One-Click Web Deploy to Cloudflare Workers + Durable Objects (Free Plan, zero Cloudflare GitHub App)**, **Docker / Compose (+ Caddy Auto-HTTPS)**, and **Linux VPS systemd** — all with a built-in **Web Setup UI (`/setup`)**.
>
> **Notice:** This repository does not accept external Pull Requests (PRs are automatically closed). Feel free to fork and self-host! For support, bug reports, or feedback, mention **[@zsai010](https://x.com/zsai010)** on X.

---

## 核心特性 / Features

- **开箱自带网页初始化向导与管理控制台（Web Setup UI）**：无论是 Cloudflare Workers、Docker 还是 Linux VPS，安装全程零交互不卡死；部署完打开浏览器访问 `https://你的域名/`（或 `/setup`）即可 30 秒绑定机主 `xtags.top` 账号、在线调整 **Tmp 大文件体积上限与保留期限**、查看宿主机磁盘余量、一键清空临时缓存，并签发移动端受限设备令牌（`snr_dev_...`）。
- **流式分块 `tmp` 大文件临时中转（8MiB/片 E2EE）**：利用 Cloudflare R2 Multipart 边缘直传（零出口流量费，默认 8GB 水位严守 10GB 免费层；未开 R2 时自动回退 DO SQLite 流式分块）或 Docker/VPS 本地磁盘，支持断点续传、HTTP Range、签收后自动延迟清理与 LRU 防爆仓。
- **零明文端到端加密（E2EE）**：剪贴板内容（`/ws`、`/v1/sync`、`/v1/push`）、小附件（`/v1/blobs/`）与大文件分片（`/v1/tmp/*`）均在客户端使用 `ChaCha20-Poly1305` 加密后上传，中继服务端永不可见明文。
- **统一 `xtags.top` 账号鉴权 & 同账号组密钥自动收敛**：默认校验 `xtags.top` Bearer Token，并通过 `/v1/signal/group-vault` 使用设备 `SyncNowAccountCert` + `X25519` 零知识自动对齐异地同账号设备的 `SNK-` 组密钥。
- **同账号信令互通与跨 NAT WebSocket 隧道兜底（`/v1/tunnel/ws`）**：直连可达时自动建立 P2P 控制；家宽/热点对称 NAT 无法直连时自动无缝回退至零明文二进制 WebSocket 隧道，解锁异地免配对直连与跨屏键鼠协同。
- **机主独占锁**：网页 Setup 一键绑定你的 `xtags.top` 账号，仅允许你自己（或白名单账号）使用，其他账号自动 `403` 拦截。
- **离线/纯内网静态令牌模式**：也支持完全不连 `xtags.top` 的静态 Bearer Token 私有部署。

---

## 三种部署方式 / Deployment Options

| 方式 | 一行命令 / 入口 | 成本 | 持久层 | HTTPS / WSS |
| :--- | :--- | :--- | :--- | :--- |
| **1. Cloudflare Workers**（推荐） | `curl -fsSL .../deploy/cf-deploy.sh \| bash` | **免费套餐即可运行** | SQLite Durable Objects（可选 R2） | 自动自带 HTTPS/WSS |
| **2. Docker / Compose** | `docker compose up -d --build` | 自有服务器 | Docker Volume (`/data`) | 内置可选 Caddy 自动 HTTPS |
| **3. Linux VPS (`systemd`)** | `curl -fsSL .../deploy/vps-install.sh \| sudo bash` | 自有 VPS | `/var/lib/syncnow-relay` | 附 Caddy / Nginx 反代模板 |

---

## 方式一：Cloudflare Workers 直接部署（推荐 · 免费套餐 · 无需 Cloudflare GitHub App）

### 1.1 浏览器一键部署（免命令行 · 免 Cloudflare GitHub App · 5 秒上线）

直接点击下方按钮进入部署页，创建一个临时 Cloudflare API Token（预设最小权限），粘贴后一键直接发布免费套餐 SQLite Durable Objects Worker 到你自己的 Cloudflare 账号，部署完立刻跳转 **`https://<你的子域>.workers.dev/setup`** 页面初始化：

[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy%20to%20Cloudflare%20Workers-%E4%B8%80%E9%94%AE%E9%83%A8%E7%BD%B2%EF%BC%88%E5%85%8D%20GitHub%20App%EF%BC%89-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://xtags.top/deploy/syncnow)

### 1.2 本地命令行一行直传（不想粘贴 API Token 的极客首选）

在 macOS / Linux / WSL 终端直接运行（只需 Node.js 18+，无需 `git clone`，也不会在你的 GitHub 建垃圾仓库）：

```bash
curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/cf-deploy.sh | bash
```

- 首次运行会自动打开浏览器完成一次 Cloudflare 官方 OAuth 登录（**不需要安装 Cloudflare GitHub App**）；
- 几秒内自动创建免费套餐 SQLite Durable Objects 并打印你的 **`https://syncnow-relay.<子域>.workers.dev/setup`**；
- 直接点开该网址，在页面上用 **xtags.top 6 位授权码** 认领机主身份即可完成配置！

*(如需自定义 Worker 名称：`curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/cf-deploy.sh | WORKER_NAME=my-syncnow bash`)*

### 1.3 无本地终端？通过 Fork + GitHub Actions 直接部署（同样无需 Cloudflare GitHub App）

1. 点击右上角 **Fork** 将本仓库复刻到你自己的 GitHub 账号；
2. 进入你的仓库 **Settings → Secrets and variables → Actions**，添加 `CLOUDFLARE_API_TOKEN`（Cloudflare 创建 **Edit Cloudflare Workers** 模板令牌即可）与 `CLOUDFLARE_ACCOUNT_ID`；
3. 打开 **Actions → Deploy to Cloudflare Workers (Manual) → Run workflow**，20 秒自动部署完毕；
4. 访问你的 `https://syncnow-relay.<子域>.workers.dev/setup` 完成页面初始化。

<details>
<summary>备选：Cloudflare 官方模板按钮（注意：需提前在 GitHub 安装并授权最新版 Cloudflare GitHub App）</summary>

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zsai001/syncnow)

> 如果点击后 Cloudflare 提示 `You must reinstall the Cloudflare GitHub App to use templates`，建议直接使用上方 **1.1 浏览器一键部署**、**1.2 一行命令直传** 或 **1.3 Fork Actions 部署**，完全绕过 GitHub App 限制。

</details>

### 可选：绑定 Cloudflare R2 存放 25MB+ 大文件

默认情况下加密文件块会自动分片存入 Durable Object SQLite（零额外费用）；如果你经常跨公网同步超大附件，可启用 R2：

```bash
npx wrangler r2 bucket create syncnow-blobs
# 取消 wrangler.toml 中 [[r2_buckets]] 的注释后重新 npm run deploy
```

---

## 方式二：Docker / Docker Compose 部署

### 2.1 快速启动（部署后直接浏览器 `/setup` 配置）

```bash
git clone https://github.com/zsai001/syncnow.git syncnow-relay
cd syncnow-relay
docker compose up -d --build
```

启动后直接打开 **`http://<你的服务器IP>:8787/setup`** 完成网页初始化即可！*(如需提前用 `.env` 预设参数，可参考 `cp deploy/docker.env.example .env`。)*

### 2.2 一键自带自动 HTTPS / WSS（内置 Caddy）

将域名 A 记录解析到服务器 IP，设置 `RELAY_DOMAIN=relay.yourdomain.com` 到 `.env`，然后运行：

```bash
docker compose --profile tls up -d --build
```

Caddy 会自动申请 Let's Encrypt 证书并转发 WebSocket（`/ws`、`/v1/signal/ws`），完成后打开 `https://relay.yourdomain.com/setup`。

### 2.3 单条 `docker run` 启动

```bash
docker build -t syncnow-relay:latest .
docker run -d --name syncnow-relay --restart unless-stopped \
  -p 8787:8787 \
  -v syncnow_relay_data:/data \
  syncnow-relay:latest
```

---

## 方式三：Linux VPS 一行 `systemd` 直装（无需 `git clone`）

支持 Ubuntu / Debian / Rocky / CentOS（`amd64` & `arm64`，需已安装 Go 1.22+）：

```bash
curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/vps-install.sh | sudo bash
```

安装全程非交互零阻塞，完成后终端会直接输出 **`http://<服务器IP>:8787/setup`**，打开浏览器即可完成机主绑定。

常用运维命令：

```bash
# 查看实时日志
journalctl -u syncnow-relay -f

# 重启服务
sudo systemctl restart syncnow-relay
```

### 配置 HTTPS / WSS 反向代理

- **Caddy（最简单，自动续签证书）**：参考 [deploy/Caddyfile.example](deploy/Caddyfile.example)（VPS 本机运行时将 `RELAY_UPSTREAM` 设为 `127.0.0.1:8787`）。
- **Nginx**：参考 [deploy/nginx.conf.example](deploy/nginx.conf.example)（已包含 `Upgrade` / `Connection` WebSocket 转发与 50MB 附件上传配置）。

---

## SyncNow 客户端接入步骤

> 还没有安装客户端？前往 SyncNow 产品官网获取最新版本：**[https://xtags.top/syncnow](https://xtags.top/syncnow)**

1. 在 SyncNow 中进入 **「xtags.top 统一账号与自建中继」**，通过浏览器一键授权或 6 位授权码登录 `xtags.top`。
2. 在下方 **「自建中继托管」** 填入你的服务地址（例如 `https://syncnow-relay.yourname.workers.dev` 或 `https://relay.yourdomain.com`）。
3. 打开 **「启用自建中继与同账号信令互通」**，点击 **「测试连通性」** → **「保存并应用」**。
4. 无需填写额外密码——客户端会自动复用 `xtags.top` 登录态完成鉴权、剪贴板/文件加密中转以及同账号设备免配对信令匹配。

---

## 支持与反馈 / Support

- **产品官网与客户端下载**：[https://xtags.top/syncnow](https://xtags.top/syncnow)
- **问题反馈 / 技术支持**：请在 X (Twitter) 上直接 `@` **[@zsai010](https://x.com/zsai010)**（[https://x.com/zsai010](https://x.com/zsai010)）

---

## HTTP & WebSocket API 一览

| 路径 | 方法 / 协议 | 鉴权 | 作用 |
| :--- | :--- | :--- | :--- |
| `/` | `GET` | 初始化后必填（401 默认拒绝） | 首次未初始化跳转 `/setup`；初始化后未授权直接返回 `401 Unauthorized` |
| `/setup` | `GET` | 初始化后需验证机主/管理员 | 内置 Web Setup 初始化向导；初始化后仅显示鉴权解锁入口，零信息泄露 |
| `/v1/setup/*` | `GET` / `POST` | 初始化后仅机主/管理员 | 读取状态（未授权返回 `401`）、验证 xtags 6 位码、热更新配置 |
| `/health` | `GET` | 必填 | 健康检查与能力探测（未授权返回 `401`） |
| `/ws?group=<hash>&device=<id>` | `WebSocket` | 必填 | 剪贴板 E2EE 实时广播 |
| `/v1/push` | `POST` | 必填 | 剪贴板 E2EE 推送（HTTP 兜底） |
| `/v1/sync?group=<hash>&since=<seq>` | `GET` | 必填 | 增量拉取剪贴板密文 |
| `/v1/blobs/<blobID>?group=<hash>` | `PUT` / `GET` | 必填 | 加密文件/图片块上传与下载 |
| `/v1/signal/ws?device=<id>` | `WebSocket` | 必填 | 同账号实时在线状态与直连信令互通 |
| `/v1/signal/peers` | `GET` | 必填 | 查询当前同账号在线设备及可达端点 |
| `/v1/updates/check` | `GET` | 公开 | 客户端自动更新 / 强制更新检查 |
| `/v1/admin/updates` | `POST` / `PUT` | 机主 / Admin Token | 发布版本更新策略 |

---

## License

MIT License — see [LICENSE](LICENSE).
