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

时间均为 Asia/Shanghai (UTC+8)。候选二进制 `agentlink-c83a5ca`，隔离节点用户 `operator` uid 1000，issuer 模式 600、属主 operator。生产节点与生产 issuer 未改。

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

那是 **A1**，需要真正的 OS 隔离。2026-11-11 08:17（Asia/Shanghai, UTC+8）用户已明确选择 **A2**：保留当前 OS 用户完整 shell，接受获准后可读取密钥并签发其他授权。本轮**不**实施独立 issuer 用户、受限 shell 或新特权服务，也不修改生产 sudo/权限。

Landlock **单独**限制 issuer 文件路径**不足以**称为已解决：同 UID 进程仍可能 ptrace / 读 `/proc`、经会话 D-Bus 驱动本地 UI、改 shell rc / autostart。A1 方案仍留在 `docs/grant-local-authority.md` 供日后改选，当前不部署。

不要再增加可清除标志，也不要把 `AGENTLINK_REMOTE_EXEC` 守卫宣传成防自授权。选择完整 shell **不是**取消首次本地 grant：未获准控制端仍不能 exec。撤销原 grant 不能撤销已经据此另建的授权或已做的系统改动。`env -u` / `setsid` 在已有 exec/full 之后能够代签，是被接受的能力，回归按此记录，而不是当成应失败的用例。

## 与灰度的关系

“无 agentlink 自授权”在 A2 下**不是**可宣称已通过的门槛，也不能用它来拒绝或代替其它门槛。可发布的前提是：首次未授权/过期/撤销/伪造等拒绝仍然成立；文档与 UI 诚实写出获准后的固有全权与撤销的极限；其它互不依赖的修复（门户 Cancel/Close、paste-ui、CJK、窗口 letterbox 诚实标记）在最终候选上实测通过。不得承诺不可能的回收或隔离能力，不得输出密钥。
