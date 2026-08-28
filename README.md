<div align="center">

# 🌐 OpenSight 3.2 （个人学习项目）（Unfinished）
### 智能 VPN 节点质量评估与应用级路由管理系统
**安全优先 · 零系统代理污染 · 进程级精准分流 · 多端口自动优选 · 本地免安装便携版**

[![Windows](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg?logo=windows)]()
[![Rust](https://img.shields.io/badge/Frontend-Tauri%20v2%20%7C%20React%2018-orange.svg?logo=rust)]()
[![Python](https://img.shields.io/badge/Core-FastAPI%20%7C%20Python%203.11+-brightgreen.svg?logo=python)]()
[![Security](https://img.shields.io/badge/Security-DPAPI%20%7C%20Fail--Closed%20KillSwitch-red.svg)](SECURITY.md)
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

[🌟 软件核心亮点](#-软件核心亮点) • [📥 节点导入方式](#-节点导入与多端口机制) • [🔀 应用分流机制](#-应用分流与白名单机制) • [🛡️ 系统安全与零断网保障](#-安全架构与零断网保障) • [🚀 快速上手教程](#-快速上手指南) • [❓ 常见问题 (FAQ)](#-常见问题与用户解答-faq)

</div>

---

## 📖 项目简介 (Introduction)

**OpenSight 3.2** 是一款专为 Windows 打造的下一代 VPN 节点评估、多模式连接与应用分流管理工具。

很多用户在使用传统代理工具时常遇到痛点：**卸载或崩溃后导致电脑断网打不开网页**、**节点测速时频繁连断 VPN 导致 IP 乱跳**、**多端口节点需要手动切换测试**、**配置文本存在恶意脚本后门**等。

OpenSight 从底层架构解决这些问题：
1. **不侵入 Windows 注册表系统代理**：设计为不修改系统全局代理项，在正常退出与受支持的异常终止路径下，避免系统代理残留对日常上网造成污染；
2. **零隧道并发测速**：无需建立 VPN 隧道即可精准测出节点延迟、抖动和质量评分，测速全程不影响本地网络访问；
3. **多端口全自动优选**：一个节点支持的多个备选端口（如 443、80、8443 等）全量并发测速，并在界面自动合并呈现最优端口；
4. **灵活的应用白名单分流**：鼠标一键点选，指定浏览器或特定软件走代理，微信/游戏/国内网站一律走本地家庭宽带，互不干扰；
5. **Windows DPAPI 用户级凭据保护**：VPN 账号密码采用 Windows 原生 DPAPI (`CryptProtectData`) 用户级安全加密存储，以当前登录用户身份上下文加密，不存明文文本。

---

## 🌟 软件核心亮点

### 1. 🔍 零隧道安全并发测速 (Zero-Tunnel Safe Probe)
* **不拨号、不跳 IP**：基于轻量级 TCP 协议握手探测，**测速期间电脑公网 IP 保持不变**，微信、网页、游戏完全无感。
* **多端口独立测速与自动优选**：ProtonVPN 等服务商的单个 TCP 节点常常支持多个端口（如 443 / 80 / 8443）。系统会在后台并发测完所有端口，在界面上**合并为一个清晰卡片**，并自动帮你标出评分最高、延迟最低的最优端口。
* **综合评分模型**：结合 TCP 首包延迟、抖动（Jitter）与稳定性进行多维度评分，快速选出当前最佳节点。
* **极低资源消耗**：测速百个节点仅耗时 **3~5 秒**，单节点流量消耗不到 **1 KB**，不额外占用网络配额。

### 2. 🔀 智能应用分流 (App-level Split Tunneling)
* **白名单精准隔离**：开启分流后，只有在列表中指定的应用程序（如 Chrome、Edge、Telegram）会走 VPN 隧道；未指定的软件（微信、国内游戏、网银）自动走本地宽带直连，防止国内应用因频繁变动 IP 被异常风控或封号。
* **常用软件一键添加**：无需手动寻找或输入冗长的文件路径（如 `C:\Program Files\...`），界面直接提供常用浏览器与通信工具的一键快捷添加按钮，同时支持下拉菜单自动识别已安装程序。
* **Split-DNS 隔离防污染**：走代理的应用使用 VPN 隧道内部加密解析，直连应用直达本地运营商网关，有效防护 DNS 污染与隐蔽泄漏。

### 3. 🛡️ 零信任安全与网络状态保护
* **不碰系统代理 (No System Proxy Hijack)**：不改写 Windows 系统的全局 127.0.0.1 代理设置，从根源降低软件退出后浏览器打不开网页的风险。
* **零信任 OVPN 配置解析**：内置 AST 词法安全分析，自动过滤并阻断 `.ovpn` 中可能包含的危险脚本指令（如 `up`, `down`, `script-security` 等），防范任意代码执行（RCE）风险。
* **Windows DPAPI 用户级凭据保护**：VPN 用户名和密码经由 Windows 系统底层 `CryptProtectData` 绑定当前登录用户账户上下文加密存储，不以明文 `.txt` 或普通 JSON 存储。
* **原子级 KillSwitch 防火墙**：异常断线时自动拦截非白名单出站流量，防止未加密的敏感数据泄漏。

---

## 📥 节点导入与多端口机制

OpenSight 支持 **3 种便捷导入方式**，点击主界面左上角 **【+ 导入配置】** 即可使用：

| 导入形式 | 适用场景 | 操作方法 |
| :--- | :--- | :--- |
| **`.zip` 压缩包一键导入** | ProtonVPN 官方打包全量节点 | **无需手动解压**，直接把下载的 `.zip` 压缩包拖入导入弹窗，软件自动提取并批量导入所有配置 |
| **单/多个 `.ovpn` 文件** | 自定义或第三方 OpenVPN 节点 | 鼠标批量多选 `.ovpn` 配置文件直接拖拽或点击浏览选择导入 |
| **文本代码直接粘贴** | 网页/聊天工具中复制的配置代码 | 切换到“手动粘贴”标签页，粘贴配置文本并输入备注名称即可一键解析 |

### 💡 多端口是如何处理与展示的？
* **后台测速**：例如某个节点支持 `443`、`80`、`8443` 三个端口，系统在测速时会对这 3 个端口**独立并发测试**；
* **界面展示**：为了保持界面清爽，**不会拆分成 3 个重复卡片**，而是合并为一个节点卡片，并在右上角显示当前表现最好的优选端口（如 `TCP/443 · 68ms`）；
* **发起连接**：点击【连接】时，系统自动通过测速得分最高的端口建立隧道，保证连接质量。

---

## 🔀 应用分流与白名单机制

在主界面左侧导航栏打开 **【应用分流】**：

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. 常用应用一键添加：                                         │
│    [+ Google Chrome]  [+ Microsoft Edge]  [+ Telegram] ...  │
├─────────────────────────────────────────────────────────────┤
│ 2. 下拉菜单点选已安装程序：                                   │
│    [ 搜索已安装应用... ▼ ]   [ 走 VPN 隧道 ▼ ]   [ + 添加 ]    │
├─────────────────────────────────────────────────────────────┤
│ 3. 运行逻辑（严格白名单）：                                   │
│    • 列表内指定的软件 (Chrome, Edge)   ──► 走 VPN 隧道       │
│    • 其余所有软件 (微信, 游戏, 系统更新) ──► 本地家庭宽带直连    │
└─────────────────────────────────────────────────────────────┘
```

> **📌 提示**：对于大型游戏平台（如 Steam）或多层进程软件，如果在白名单模式下只想让游戏对局加速，可打开任务管理器查看游戏核心发包进程名（如 `cs2.exe`）并添加即可；或者直接在连接时选择 **“全局代理模式”**。

---

## 🛡️ 安全架构与网络状态保护

```
┌─────────────────────────────────────────────────────────────┐
│                    Tauri v2 前端 (React 18)                  │
│  - 纯本地 IPC 通信   - 现代暗黑极简 UI   - 严格 CSP 保护       │
└──────────────────────────────┬──────────────────────────────┘
                               │ 本地安全通信 (127.0.0.1 Bearer Token)
┌──────────────────────────────▼──────────────────────────────┐
│                  FastAPI 核心服务 (Python 3.11+)             │
│  - Windows JobObject 绑定  - 退出时内核自动回收全部子进程与网卡 │
├──────────────────────────────┬──────────────────────────────┤
│  凭据保险箱 (DPAPI 用户级保护) │  配置安全过滤 (AST 词法白名单) │
├──────────────────────────────┼──────────────────────────────┤
│  KillSwitch 防火墙事务管理    │  Split-DNS 防泄漏与分流引擎   │
├──────────────────────────────┼──────────────────────────────┤
│  零隧道并发测速 (不改系统路由)│  Wintun 虚拟网卡驱动管理     │
└──────────────────────────────┴──────────────────────────────┘
```

### 网络状态恢复机制
1. **不修改系统全局代理**：不写入 `127.0.0.1:7890` 之类的注册表代理项，避免软件退出后浏览器打不开网页的常见网络故障；
2. **虚拟网卡生命周期绑定**：连接时才启用虚拟网卡，断开连接或退出时自动注销；
3. **路由临时生效**：所有的 VPN 路由绑定在虚拟网卡接口上，设计用于在正常退出及受支持的异常终止路径下自动注销虚拟网卡并恢复临时路由。

---

## 🚀 快速上手指南

### 步骤 1：下载与启动
1. 前往本仓库 [Releases 页面](../../releases) 下载最新版的 `OpenSight-v3.2.0-win-x64-portable-full.zip`；
2. 解压到任意文件夹（建议路径不包含特殊符号）；
3. 双击 `OpenSight.exe` 启动（首次启动弹出 UAC 管理员权限提示时选择【是】）。

### 步骤 2：导入节点
* 点击左上角 **【+ 导入配置】**，将你的 `.ovpn` 配置文件或从 ProtonVPN 官网下载的配置 `.zip` 压缩包直接拖入窗口，点击【开始解析导入】。

### 步骤 3：配置凭据（可选）
* 如果你的节点需要账号密码验证，点击右上角 **【凭据管理】** 填入专用 OpenVPN 用户名与密码，点击保存（由 Windows DPAPI 用户级加密保护）。

### 步骤 4：一键测速
* 点击顶部的 **【开始智能测速】**，数秒内所有节点将完成并发探测，并按综合得分自动排序。

### 步骤 5：发起连接
* 在心仪的节点卡片上点击 **【连接】**，选择 **全局代理** 或 **应用分流** 即可畅享安全网络。

---

## 🧹 卸载与系统清理 (Uninstallation & Cleanup)

OpenSight 为纯绿色免安装软件，提供内置的**图形界面全自动卸载流程**：

### 1. 普通用户的标准卸载方式 (Primary GUI Workflow)
普通用户**无需手动运行任何 PowerShell 脚本或手动删除文件**：
1. 打开 OpenSight 界面右上角 **【设置】**；
2. 选择 **【卸载 OpenSight】**；
3. 选择卸载模式并点击确认：
   * **正常卸载 (Normal Uninstall)**：安全退出并清除 OpenSight 程序运行组件与所属网络/系统状态，保留您的用户配置与节点数据；
   * **彻底抹除 (Full Purge)**：完整移除 OpenSight 所有的程序文件、用户数据、节点配置、DPAPI 加密凭据、运行日志、缓存数据、元数据清单，以及 OpenSight 专属的临时路由、`OpenSight-*` 防火墙规则、`OpenSight-TUN` 虚拟网卡、OpenSight 拥有的 OpenVPN 与 sing-box 组件；
4. 系统将全自动完成所有资源释放与外部终态验证，确认完毕后软件自动关闭退出。

### 2. 归属权安全边界与网络状态保护 (Ownership-Aware Cleanup)
OpenSight 严格实施基于**安装归属权清单**的精准清理：
* **仅清理自身资源**：仅移除 OpenSight 创建的专属路由表项（如 `172.19.0.0/30`、`OpenSight-TUN` 绑定路由）、`OpenSight-*` 防火墙规则与专属虚拟网卡，**严禁且绝不使用 `route -f` 全局重置路由表**；
* **保护第三方与用户资产**：OpenSight 不会移除任何与本项目无关的用户自有 VPN 网卡、第三方路由、用户自定义防火墙规则，或用户单独安装的外部 OpenVPN 客户端；
* **OpenVPN 专属归属判断**：仅在安装清单明确记录为 OpenSight 专属安装的 OpenVPN 组件时才会调用卸载；如检测为外部或用户已有安装，将自动予以保留（`SKIPPED_EXTERNAL_COMPONENT`）。

### 3. 卸载诊断日志说明 (Uninstall Diagnostic Log)
卸载完成后，Windows 临时目录中会专门保留一份诊断日志：`%TEMP%\OpenSight-Uninstall.log`。
* **保留目的**：供用户在遇到系统清理异常时审查卸载结果与排查故障；
* **属性说明**：该文件属于外部诊断记录，不属于已安装应用程序的一部分，也不影响系统正常运行。排查完毕后用户可随时安全手动删除；
* **安全隐私**：卸载诊断日志在设计上严格排除了用户密码、VPN 凭据、私钥、身份令牌等任何敏感机密信息。

> **💡 开发者与技术支持排查 (Advanced Diagnostic Mechanism)**：
> 高级开发者或技术支持人员如需在不改动系统状态的前提下独立核验残留状态，可在终端运行：
> ```powershell
> powershell -ExecutionPolicy Bypass -File scripts\uninstall_opensight_windows.ps1 -VerifyOnly -PurgeData
> ```

---

## 🛠️ 开发者与构建指南 (Developer & Build Guide)

### 环境要求
- Windows 10/11 x64
- [Python 3.11+](https://www.python.org/)
- [Bun](https://bun.sh/) (推荐固定版本 1.1.27 用于前端构建与锁定依赖) 或 Node.js 18+
- [Rust 工具链](https://rustup.rs/) (用于 Tauri 宿主程序构建)

> **📦 依赖文件说明**：
> - `requirements.lock`：**生产与 CI 依赖锁文件**（包含全部直接与传递依赖精确版本与安全修复，用于可复现构建与打包）。
> - `requirements.txt`：**抽象依赖规范说明**（记录顶层核心依赖范围，供日常开发参考）。
> - `requirements-dev.txt`：**开发测试工具链**（Flake8、Pytest、pip-audit、PyInstaller 等）。
> - `bun.lock`：**前端依赖锁文件**（锁定 React/Tauri 前端精确依赖版本）。

### 1. 开发者日常环境配置 (Developer Setup)
```powershell
# 1. 配置 Python 虚拟环境并使用锁文件安装依赖
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.lock
pip install -r requirements-dev.txt
pip install --no-deps -e .

# 2. 安装前端依赖 (通过 Bun 锁文件严格锁定)
bun install --frozen-lockfile

# 3. 运行单元测试
pytest -q
```

### 2. 生产与正式发布构建 (Production / Release Build)
为保证构建可复现性与供应链安全，CI 与 Release 构建严格执行无依赖重解析锁定构建：
```powershell
# 1. 严格按照锁文件安装依赖 (禁止次级解析)
pip install -r requirements-dev.txt
pip install --upgrade --no-deps -r requirements.lock
pip install --no-deps -e .
bun install --frozen-lockfile

# 2. 安全与代码质量门禁
flake8 src tests --config=.flake8
pip-audit
pytest --cov=opensight tests/

# 3. 拉取官方固化二进制与生成 SBOM / 安全清单
python scripts/fetch_components.py --dest dist/OpenSight
python scripts/build_portable.py
python scripts/smoke_test.py dist/OpenSight/OpenSight.exe
python scripts/package_release.py --commit <GIT_COMMIT_SHA>

# 4. 验证发布包清单与来源白名单
python scripts/verify_manifest.py dist/staging
python scripts/verify_provenance.py dist/staging
```

---

## ❓ 常见问题与用户解答 (FAQ)

<details>
<summary><b>Q1: 测速时会不会影响我正在玩的游戏、看视频或改变我的公网 IP？</b></summary>

**A**: 不会。测速采用的是非侵入式轻量级 TCP 握手探测，**全程不建立 VPN 隧道，不接管系统默认网关**。你的公网 IP 和网络路由保持不变，完全无感。
</details>

<details>
<summary><b>Q2: 为什么导入 ProtonVPN 节点会有很多端口？软件会怎么测？</b></summary>

**A**: ProtonVPN 的配置文件通常会指定多个备选端口（如 443、80、8443、1194 等）。OpenSight 会在后台对这些端口进行**全部并发独立测速**，但在界面上**合并为一个清晰卡片**，并自动帮您选定延迟最低、最稳定的端口进行连接。
</details>

<details>
<summary><b>Q3: 我需要手动输入软件很长的安装路径（如 C:\Program Files\...）来进行分流吗？</b></summary>

**A**: 不需要！分流面板提供了常用软件（Chrome, Edge, Firefox, Telegram, Discord, Spotify 等）的**一键快捷添加按钮**，同时自带已安装软件下拉菜单直接点选，非常简单。
</details>

<details>
<summary><b>Q4: 为什么有些代理软件退出后电脑就上不了网，OpenSight 会这样吗？</b></summary>

**A**: 不会。传统软件容易断网是因为它们修改了 Windows 系统的“全局 HTTP/SOCKS 代理设置（127.0.0.1）”，崩溃后系统代理没有被还原导致所有浏览器断网。OpenSight **从原理上不修改 Windows 注册表系统代理**，采用独立的虚拟网卡工作，设计用于在正常退出及受支持的异常终止路径下自动注销虚拟网卡并恢复临时路由，有效防止网络状态残留。
</details>

<details>
<summary><b>Q5: 测速会消耗很多手机热点或宽带套餐流量吗？</b></summary>

**A**: 不会。单节点探测仅收发几个极小的数据包（大小不到 1KB），即使同时测速上百个节点，总共消耗的流量也**不足 100KB**（不到一张网页图片的千分之一）。
</details>

<details>
<summary><b>Q6: 为什么启动时 Windows 会弹出 UAC 管理员权限确认框？</b></summary>

**A**: 因为启动虚拟网卡（Wintun）和配置底层防火墙防泄漏规则是 Windows 系统的内核级网络操作，必须具备管理员权限。项目代码开源透明，且提供严谨的安全策略。
</details>

<details>
<summary><b>Q7: 怎么完全卸载并清除所有数据？</b></summary>

**A**: OpenSight 提供内置的**图形界面全自动卸载流程**：
1. 打开 OpenSight 界面右上角 **【设置】**；
2. 选择 **【卸载 OpenSight】**；
3. 选择 **【彻底抹除】**（Full Purge，移除所有 OpenSight 运行文件、用户数据、DPAPI 凭据、日志与专属网络/防火墙规则）或 **【正常卸载】**（保留个人节点配置）；
4. 确认后系统全自动执行清理与终态验证，随后自动退出。

卸载诊断日志 `%TEMP%\OpenSight-Uninstall.log` 会单独保留在 Windows 临时目录供排障审阅，排查后可随时手动删除。外部/用户已有的 OpenVPN 或网络适配器会自动予以安全保留。
</details>

---

## 📄 安全策略与开源许可证 (Security & License)

- [安全策略与威胁模型 (SECURITY.md)](SECURITY.md)
- 本项目基于 [MIT License](LICENSE) 开源发布。
