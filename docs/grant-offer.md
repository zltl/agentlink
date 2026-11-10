# 控制端身份码与目标机本地签发（grant offer）

本文是 agentlink 本地授权的源设计：控制端（远程）复制身份/配对码，目标机（本地）粘贴核对后由本机用户签发 grant。公开身份不是凭证，身份码不是 grant token，relay 不能授权。

术语固定如下，界面和 CLI 文案必须同样清楚：

- **控制端 / 远程**：发起控制的一方（controller）。
- **目标机 / 本地**：被控制、签发 grant 的节点所在机器（node host）。

已有仍有效的 grant 无需再次粘贴或签发。没有可信控制端密码学身份不能发新 grant。手工复制不是唯一合法入口：在目标机上对完整 64 位控制端公钥调用已有的 `grant issue --grantee <hex>`（或 `grant paste` 的公钥形式）与粘贴身份码等价；名称或 relay 声称的短 ID 不能代替公钥。

## 业界对照（官方公开资料）

下表区分五件事：**寻址 ID**、**密码学身份/指纹**、**临时验证码或共享秘密**、**目标本地同意**、**无人值守授权**。叙述均来自下列页面，不凭产品印象补细节。

### RustDesk

来源：

- [RustDesk Client](https://rustdesk.com/docs/en/client/)：安装后左上角是本机 **ID** 和 **One Time Password**，右侧输入框用于“if you know their ID”连接到另一台电脑。`--get-id` / `--set-id` / `--password` 分别读取或设置 ID、设置永久密码。
- [Advanced Settings](https://rustdesk.com/docs/en/self-host/client-configuration/advanced-settings/)：`approve-mode` 为 `password`、`click` 或 `password-click`（默认 `password-click`），即密码或目标机手动点击接受。`verification-method` 允许一次性临时密码和/或永久密码。`id-whitelist` 写明：*“The ID is reported by the connecting client, so it is not an authentication mechanism. This whitelist reduces exposure, it does not replace the password or 2FA.”*

对照：RustDesk ID 是寻址；认证靠密码或点击。官方自己说明 ID 白名单不能替代认证。无人值守依赖目标机上设置的永久密码（及服务），不是把控制端公钥贴到目标机。

### AnyDesk

来源：

- [AnyDesk Address - ID and Alias](https://support.anydesk.com/docs/anydesk-id-and-alias)：每个客户端有一个用于建立连接的唯一地址，是数字 **AnyDesk ID**（随机生成的 9 或 10 位）或 Alias。
- [Set up Unattended Access](https://support.anydesk.com/docs/unattended-access)：默认关闭无人值守时，必须有人在目标侧用 Connection Accept 窗口接受或拒绝。启用方式是在**远程设备（目标）**上设置密码；官方警告 *“anyone with your password and AnyDesk ID could gain full access to your device depending on the configured permissions.”* 保存登录时，目标机在密码验证成功后签发 **token**（密码本身不存储，token 绑定签发它的客户端，改密码即作废）。

对照：ID/Alias 是寻址；共享秘密是目标机密码；本地同意是 Accept 窗口；无人值守是目标机设定的密码及随后的设备绑定 token。ID 加密码即可访问，密码不是控制端公钥身份。

### TeamViewer

来源：

- [For personal use](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-classic/licensing/personal-use/for-personal-use/)：TeamViewer ID 是安装时分配的 9 或 10 位数字，官方比喻为 *“a phone number for your device. You dial the TeamViewer ID, then use the password to authenticate the connection.”*
- [Connect via ID and password](https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-remote/remote-control/connect-via-id-and-password/)：控制端输入目标设备 ID，再输入该设备的密码。
- [Remote control via Easy Access](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-classic/remote-control/connection-methods/remote-control-via-easy-access/)：无人值守的一种方式是在**目标设备上**把设备分配给 TeamViewer 账户并启用 Easy Access；之后用该账户登录即可连接，无需再输 ID/密码。设置必须在目标设备完成。

对照：ID 是寻址（“电话号码”），密码是秘密，Easy Access 是账户绑定的无人值守，仍不是“控制端复制公钥、目标机本地核对指纹后签发”。

### OpenSSH 公钥与 fingerprint

来源：

- [ssh(1)](https://man.openbsd.org/ssh.1)：用户用 `ssh-keygen` 生成密钥对，把**公钥**放到目标机 `~/.ssh/authorized_keys`；之后登录凭私钥证明，不再使用账户密码。
- [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)：`-l` 显示指纹，`-E fingerprint_hash` 可选 `md5` 或 `sha256`（默认 `sha256`）。
- [ssh-copy-id(1)](https://github.com/openssh/openssh-portable/blob/master/contrib/ssh-copy-id.1)（OpenSSH portable）：把本地可用的公钥安装到远程机以授权登录。

对照：寻址是用户名与主机；身份是公钥；核对用指纹；授权是目标机（或管理员）把公钥写入 authorized_keys。公钥本身不能登录。这与用户要求的“控制端复制身份、目标机本地 grant”最接近，也是本设计的基准。agentlink 在此之上增加：身份码携带**签名过的请求**（策略、TTL、nonce、可选的目标公钥与 relay 证书指纹），目标机展示**实际能力**后再本地签发有期限的 grant；后续会话仍须控制端用私钥做已有的 E2E 证明。

## 选定设计

1. **控制端**运行 `agentlink grant offer`，用控制端私钥签发一张自包含身份码（`agentlink-offer:v1:` + URL-safe base64 JSON，带版本）。码内含控制端公钥、请求的 policy/ttl、时间窗、nonce，以及可选的目标节点公钥、relay 证书指纹。身份码**不是** grant，也不得当作 access token 复用。
2. **目标机本地**运行 `agentlink grant paste`（CLI）或随后在托盘/`grant prompt` 中处理待批：解析、校验签名与版本，显示控制端 `SHA256:` 指纹（与 OpenSSH `ssh-keygen -l -E sha256` 同类）、完整公钥、以及 `NodePolicy::capability_summary()`（`desktop` 必须写出 exec 与文件读写，不得只写 “desktop”）。由本机用户 `grant allow` / `grant prompt` 签发。网络送来的待批数据仍然只是请求。
3. 改码、换控制端密钥、重放同一 nonce、绑定了不同目标公钥、绑定了不同 relay 指纹、过期，一律拒绝。签名密钥不下发控制端以外，也不经过 relay 签发。
4. 不实现短码在线查找（避免枚举/碰撞/中间人替换）。若将来加短码，必须同时提供完整指纹的独立核对，并限流。二维码只是同一自包含字符串的可选编码，本版不另造加密协议。
5. 完整 64 位公钥仍可直接用于已有 `grant issue --grantee` 或 `grant paste <hex> --policy … --ttl …`。后者没有身份码上的即时签名，目标机应提示：仅公钥不能证明此刻持有私钥，控制端之后仍须用私钥完成 E2E。
6. 已有有效 grant 保持可用，本流程不改写、不撤销它们。
7. `agentlink-invite:` 入会邀请、`approve allow/deny`（危险操作确认）都不是 grant。

## CLI

```
# 控制端（远程）
agentlink grant offer --policy desktop --ttl 4h [--node <目标64位公钥>] 

# 目标机（本地）
agentlink grant paste 'agentlink-offer:v1:…' --data-dir <节点数据目录>
agentlink grant pending --data-dir …
agentlink grant allow <request-id> --data-dir …
# 目标机可以缩小权限或缩短 ttl，不能加大：
agentlink grant allow <request-id> --policy exec --ttl 10m --data-dir …
# 或图形入口（zenity/kdialog 粘贴框 + 核对指纹后批准）
agentlink grant paste-ui --data-dir …
# 或
agentlink grant paste '…' --prompt --data-dir …
```

目标机托盘在节点本机还提供「粘贴控制端身份码…」与带 SHA256 指纹的 Allow/Deny。UI 必须展示指纹，并写明：签名只证明私钥，不证明屏幕名称或人员真实性。

其它约束：

- `grant paste` / `allow` / `prompt` / `paste-ui` / `issue` 等签发入口遇到 `AGENTLINK_REMOTE_EXEC`（节点 exec/pty/shell 会注入）时拒绝。这只是 CLI 防误用，**不是**防自授权边界：已获得 exec/full 的控制端与目标机同 UID，可清除该变量、读取 `grant-issuer.json` 私钥或改写 grant 权威目录。未获准的控制端仍然不能 exec。已授权的独立 SSH/Cursor（不是 agentlink exec）可在目标机本地代执行 grant。详见 `docs/grant-authorization-boundary.md`。
- `grant paste-ui`：目标机图形粘贴身份码 → 展示指纹与声明 → 用可访问的权限按钮（每项写出实际能力；OK 为默认最小且不大于请求的权限；每个预设一枚可点按钮，避免 zenity radiolist 无法用 AT-SPI 选中）缩小 scope、缩短 ttl → **最终确认框再次展示真正要签发的 scope 与 ttl** 后再签发，或拒绝/取消。取消与拒绝都不签发。仅粘贴不会授权。
- 身份码解析有长度上限（8KiB）。used-nonces 原子落盘，删除待批文件或重启后同一 nonce 仍拒绝。
- 时间边界：身份码在 `exp_unix` 当时仍有效，`exp_unix+1` 过期。跨目标公钥、跨 relay 指纹拒绝。
- 公开身份码绝不可被当成 SignedGrant / bearer 授权。

错误信息使用可理解的中文，并分清控制端与目标机。
