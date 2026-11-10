# Grant 签发边界（诚实说明）

本文纠正把 `AGENTLINK_REMOTE_EXEC` 包装成“exec 无法代签 / 防自授权”的说法。环境变量不是强安全机制，也不应再叠加另一个可清除标志。

## 两层对象必须分开

1. **未获准的控制端**：没有对该节点的有效 exec/full grant。节点不会为其启动 exec/pty/shell，因此碰不到本机 `grant-issuer.json` 和 grant 权威目录。身份码是公开身份，不是 bearer；relay 不能授权。这一层仍然成立。
2. **已获得 exec/full 的控制端**：远程代码与节点进程、issuer 文件同属一个 OS 用户。完整 exec 在这里等于该用户的固有能力，包括签发 grant。不能声称“exec 无法代签”。

## 现有 CLI 守卫只是防误用

节点在 exec/pty/shell 子进程中注入 `AGENTLINK_REMOTE_EXEC=1`。CLI 的 `grant issue/paste/allow/prompt/paste-ui/revoke` 等变更入口在该变量仍存在时拒绝运行，避免操作者误以为可从 exec 里点批准。

这不是边界：

- `env -u AGENTLINK_REMOTE_EXEC` 即可走完全部签发入口。
- `setsid` 或脱离父进程同样可以。
- 同 UID 可直接读取 `grant-issuer.json`（`secret_hex`，模式 0600，属主与节点相同）。
- 同 UID 可直接在 `grant-requests/`、`issued-grants/`、`revoked-grants.json` 等权威目录写入。

## 隔离节点上的实测（非生产）

时间均为 Asia/Shanghai (UTC+8)。候选二进制 `agentlink-c83a5ca`，隔离节点用户 `ltl` uid 1000，issuer 模式 600、属主 ltl。生产节点与生产 issuer 未改。

| 编号 | 操作 | 期望（诚实） | 实际 |
| --- | --- | --- | --- |
| S1 | 无有效 grant 的控制端 B `exec true` | 失败（未获准 / 过期） | `S1_rc=1`，grant 已过期，未执行 |
| S2 | 已授权 A `exec grant allow`（环境变量保留） | CLI 拒绝 | 拒绝，文案现已改为“防误用，不是防自授权” |
| S3 | A `exec env -u AGENTLINK_REMOTE_EXEC grant issue --policy exec --ttl 5m` | 会签发 | `S3_rc=0`，用 iso issuer 签发，jti `bb4d1c24-…`（随后在 iso `revoked-grants.json` 撤销；误写入默认 config-dir 的 iso 节点 grant 文件已删除） |
| S4 | A `exec` 读 issuer | 可读 | `test -r` 成功；JSON keys 为 `public_hex, secret_hex`；`has_secret_hex=true`（未打印私钥） |
| S5 | A `exec` 向 `grant-requests/` 写 canary 并删除 | 可写 | `WROTE_CANARY` / `REMOVED_CANARY` |
| S6 | A `exec setsid env -u … grant allow` | 越过守卫 | 进入 allow 逻辑，错误为 `no grant request does-not-exist`（不是远程 exec 拒绝） |
| S7 | A `exec grant paste/issue`（环境变量保留） | CLI 拒绝 | 均拒绝 |

结论：未获准控制端仍被挡在 exec 之外；已获 exec 的控制端可以代签。先前“禁止 grant allow / 无法代签”的表述是误导。

## 若要坚持“grant（含 shell）必须本地批准、无 agentlink 自授权”

不能再靠环境变量。需要真正的 OS 隔离，使**远程 exec 身份**读不到签发私钥、写不了权威目录。可选方案（都不在本变更中实施；不改系统全局安全策略，不擅自加 root daemon）：

1. **首选、范围最小：对 exec/pty/shell 子进程施加 Landlock（或等价 LSM）**，拒绝打开 `grant-issuer.json`、`issued-grants/`、`grant-requests/`、`revoked-grants.json`、`used-nonces.json`、`owner-keys.json`。由节点在 spawn 时应用，不需要新用户或 root 服务。限制：只约束这条 agentlink exec 谱系；同用户的本地 shell / 独立 SSH 仍可按设计做本地批准。若主机 `ptrace_scope` 允许同用户附着节点进程，仍有读内存风险，需一并评估。
2. **更强：独立 issuer 用户或席位绑定签发助手**。私钥只属于该用户或只对图形席位上的本地助手可访问；远程 exec 的 UID 不可读。助手通过 unix socket + `SO_PEERCRED` + 登录席位校验接受本地批准。这比 Landlock 更清晰，但要新增组件，需单独授权后再做。

不要再增加可清除标志，也不要把上述方案未落地时的状态标成“已防自授权”。

## 与灰度的关系

在 issuer 对 exec UID 仍可读可写的情况下，**不能**把“无 agentlink 自授权”当作已通过的安全门槛，也因此不能以该声明为依据做生产灰度。其它互不依赖的修复（超时与 Cancel 清理、paste-ui 缩小权限链、诚实文档、负例重测）可以在隔离节点上继续验证。
