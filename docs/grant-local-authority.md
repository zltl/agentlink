# 本地签发隔离：边界前提、方案与需用户决定的事项

本文是设计与沙盒策略代码（`agentlink_core::grant_authority`）的说明，**不是**已部署架构。默认节点与 `grant allow` / `paste-ui` 仍按现有同 UID issuer 工作。不修改生产用户、sudo 或权限，不安装特权 daemon。

## 必须先说清的冲突

用户要求：完整 grant（**包括 shell**）必须由**目标机本地命令或按钮**批准，且不能被 agentlink 自授权。

与此同时，今天的 `exec` / `full` 是：**远程代码以节点同一 OS 用户运行任意程序**。在 Linux 上，同 UID 的完整 exec 固有能力包括（不穷举）：

- 读 `grant-issuer.json` 的 `secret_hex`，直接签发；
- 写 `issued-grants/`、`grant-requests/`、`revoked-grants.json`；
- `env -u` / `setsid` 拆掉 CLI 防误用标志（已实测，回归必须保留）；
- 同 UID `ptrace`、读 `/proc/<pid>/mem`（受 `kernel.yama.ptrace_scope` 影响，但不能把默认 yama 当成保证）；
- 使用会话 D-Bus：AT-SPI、xdg-desktop-portal、通知与已登录会话上的 UI（若还持有 desktop/input 更直接；即便只有 shell，也可改用户服务）；
- 改 `~/.bashrc` / systemd user `autostart` / `~/.config/autostart`，在下次本地批准者启动时注入。

因此：

- **只 deny issuer 文件路径（Landlock 单独限制）不能称为已解决。** 它挡不住 ptrace、D-Bus 驱 UI、dotfiles 注入，也挡不住已在内存中的密钥。
- **不能同时承诺「同 UID 完整 exec」与「exec 不可代签」。** 二者冲突。若 grant 还包含 root/sudo，更不可能承诺不可代签。
- 未获准或已过期/已撤销的控制端仍然不能 exec，也就没有这些固有能力。要把「未获准」和「已获完整 exec」分开写，不能混成“exec 无法代签”。

Windows / Android **不能**用 Linux Landlock、logind 或 polkit 冒充为全平台已解决；见下文分平台可行性。

## 最小可证明边界（推荐方向）

复用成熟 OS 机制，不手写一套新密码学。核心是把「签发权威」和「远程 exec 身份」拆开，批准通道必须能证明**此刻是本地同意**，而不是“与节点同 UID 的某个进程调用了 CLI”。

三件套，缺一不可：

1. **受保护的 issuer 与权威授权库**  
   私钥和 `issued-grants` / `revoked-grants` / `used-nonces` 只属于独立 authority 身份（独立系统用户，或平台等价的服务帐户），对节点/exec 的 UID **不可读不可写**。节点进程也不长期把 `secret_hex` 放在可被同用户 dump 的地址空间里。

2. **受约束的远程 exec 身份**  
   远程 shell/exec **不能**再等于登录用户的固有全权。可选：单独 `agentlink-exec` 用户、或对 exec 子进程施加严格沙箱，且明确列出仍做不到的事（ptrace 节点/助手、写登录用户的 autostart、会话 D-Bus 点批准按钮）。若用户坚持 exec 继续以登录用户无沙箱运行，则**不能**承诺防自授权。

3. **真正本地 seat（或等价）认证的批准通道**  
   `grant allow` / `paste-ui` / 托盘按钮与助手通信（unix socket + `SO_PEERCRED`，或平台等价）。助手只在下列情况下签发：
   - 调用者是 authority 期望的本地批准者，且处于 **logind 活动图形 seat**；或
   - 调用者是目标机上的交互登录（SSH/Cursor），并按用户选择的策略通过 **polkit**（或等价）做在场确认；或
   - 明确拒绝来自 node 服务 cgroup / `AGENTLINK_REMOTE_EXEC` 谱系的调用（这是拒绝路径，不是唯一边界）。

会话 D-Bus 被 exec 操控的风险：若远程身份仍能向 seat 注入输入或 AT-SPI，它可以“替用户点批准”。因此受约束 exec **默认不应再附带 desktop/input**，或必须失去会话总线与输入合成能力。这是能力收窄，不是可选项里的隐藏细节。

## 沙盒原型（仅仓库）

`agentlink_core::grant_authority` 实现调用者分类与签发决定，并有单元测试。它**没有**在生产 `grant allow` 路径上启用，也没有安装单元或创建用户。用于锁定规则，避免以后把 Landlock-only 或 env 标志误写成“已隔离”。

## 启用该架构时会收窄的能力

若将来采用（需用户明确决定后，在生产上另做一次受控变更）：

- 已有 `exec`/`full` grant **不再**等于“与坐在键盘前的用户同等的任意代码 + 可自签 grant”。远程 exec 不能读 issuer、不能写权威库、不能作为批准通道。
- 远程 exec 可能无法再改登录用户的 dotfiles、用户 systemd、会话 D-Bus，或无法再 ptrace 节点。部分“把机器当自己用”的自动化会失败。
- `full` 若仍包含无限制 shell，与防自授权冲突；需要把 “full 的 shell” 重新定义为受约束 runner，或停止签发无限制 shell。
- 含 sudo/root 的远程能力与“不可代签”不能同时承诺；必须取消这类 grant 或接受无保证。

**不会**自动撤销已有生产 grant；迁移时要决定是否重签、是否缩 scope。

## 需要用户决定的事项（具体选项，不是“授权后再说”）

**决定 A — 远程 shell 的含义（必选，否则硬门槛无法落地）**

- **A1（可证明边界）**：新的 exec/shell 以独立用户或等价沙箱运行；不能 ptrace 登录会话、不能写 login 用户 autostart、不能操作 seat 总线去点批准。issuer 迁到独立用户。本地 `grant allow` / `paste-ui` / 托盘仍以登录用户在 seat 或经 polkit 批准。
- **A2（维持现状的固有全权）**：exec 继续以登录用户无限制运行。则文档与 UI 必须持续写明：**已获 exec/full 的控制端可以代签**；“必须本地批准、无自授权”对这类控制端不成立。不要部署独立 issuer 来假装解决。

**决定 B — 目标机 SSH/Cursor 的 `grant allow`**

- **B1**：只要是目标机上的交互登录（tty/SSH），CLI 披露指纹后可签（接近今天 t421 的用法）。须能与 node/exec cgroup 区分。
- **B2**：SSH 也必须经过 seat 上的 polkit（或等价）在场确认。更严，但无图形会话的纯 SSH 管理机会签不了，除非另开一个 tty 策略。

**决定 C — 若选 A1，一次最小特权安装（仅当用户要求落地，且不在本轮执行）**

在 Linux 生产机上一次完成（示例，需 root；**现在不要跑**）：

1. 系统用户 `agentlink-issuer`（无登录壳、无家目录登录）。
2. 将节点数据目录中的 `grant-issuer.json`、`issued-grants/`、`revoked-grants.json`、`used-nonces.json` 改为该用户所有、目录 `0700`、文件 `0600`；节点进程去掉对这些文件的读权限。
3. 安装 **systemd system** 单元 `agentlink-grant-authority.socket`（仅本地 unix socket，如 `/run/agentlink-grant-authority/sock`），以 `agentlink-issuer` 运行助手；用 polkit action `org.agentlink.grant.issue`（活动 seat 确认；SSH 按决定 B）。
4. 将节点 `exec`/`pty` 改为以 `agentlink-exec` 用户运行（第二个系统用户），或对子进程使用 Landlock **并且** `yama`/`PR_SET_DUMPABLE`/无会话总线/无 user systemd 写权限——Landlock 只是其中一层，不能单独作为验收标准。
5. CLI 的 `grant allow` / `paste-ui` 改为只跟该 socket 说话，不再在节点 UID 下本地签名。

这是最小具体安装集：两个系统用户 + 一个可选的 exec 用户、一个 systemd socket 单元、一个 polkit action、一次目录属主迁移。不需要自研密码协议。不做就保持现网行为（A2）。

Windows / Android 的等价物见下节，不能套用上述命令。

## 分平台可行性

### Linux（本仓库当前桌面节点）

可行，机制成熟：系统用户、unix socket、`SO_PEERCRED`、logind `session/seat`、polkit、systemd、Landlock（仅作 exec 约束的一层）。上文 C 即最小落地集。

### Windows

不能用 Landlock/logind/polkit。可行方向：

- issuer 放在单独 Windows 服务帐户下，ACL 拒绝普通用户读取；
- 批准走 NT 服务 + named pipe，用客户端 token 识别；本地确认走 **UAC Consent UI** 或已登录会话的 Windows 安全提示，而不是环境变量；
- 远程 exec 若以同一用户的完整交互令牌运行，同样拥有固有全权（读服务可访问的对象、驱动 UI 自动化）。要对齐 Linux 的 A1，exec 需要受限 token / 独立帐户 / AppContainer，并失去 UI 自动化与该服务的写权。

现状：Windows 节点若与 Linux 一样同用户存 issuer，则同样不能声称防自授权。须单独实现，不能靠 Linux 助手“顺便覆盖”。

### Android

应用沙箱已经是不同 UID。issuer 应留在节点应用的私有目录（其他应用读不到）。主要风险不是同 UID exec，而是：

- 已授权的 exec/shell（若暴露）仍在应用 UID 内；
- Accessibility / 媒体投影 / 通知点击可能被用来模拟“本地批准”。

批准通道应是应用内必须可见的 Activity（用户手势），而不是一个可被 shell 直接调用的无 UI 接口。Linux 的系统用户方案在此不适用。无 USB/在线设备时只记录可行性，不强推安装。

## 与现网灰度的关系

在决定 A 未选 A1 并完成迁移之前，生产继续使用旧二进制，**不做全机灰度**。本轮只修门户 Cancel/Close、paste-ui 全链，以及把上述边界写进仓库。`env -u` / `setsid` 负例必须保留，不为了“全绿”删除。
