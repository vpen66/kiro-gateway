# Kiro 用量接口抓包与复现

本文档记录了如何在 macOS 本机上，用 `Wireshark` / `tshark` 手动抓取并复现 Kiro 账户面板的用量接口，请求参数、返回内容，以及它们在 UI 上的映射关系。

本文基于本次已验证结果整理，目标是让你下次可以完全独立复现。

## 1. 目标

要确认的内容有 4 个：

1. Kiro 账户面板到底请求了哪个后端接口。
2. 请求方法、域名、路径、query 参数分别是什么。
3. 返回 JSON 里哪些字段对应邮箱、套餐、额度、重置时间。
4. Kiro 是否存在定时轮询，以及轮询间隔是多少。

## 2. 本次确认到的结论

- 接口：`GET https://q.us-east-1.amazonaws.com/getUsageLimits`
- 常见 query 参数：
  - `origin=AI_EDITOR`
  - `profileArn=<你的 profile arn>`
  - `resourceType=AGENTIC_REQUEST`
  - 打开账户弹窗时还会多一个 `isEmailRequired=true`
- 关键返回字段：
  - `subscriptionInfo.subscriptionTitle`
  - `usageBreakdownList[*].currentUsageWithPrecision`
  - `usageBreakdownList[*].usageLimitWithPrecision`
  - `usageBreakdownList[*].nextDateReset`
  - `userInfo.email`
  - `userInfo.userId`
- Kiro 自身有轮询：
  - `intervalMs = 300000`

## 3. 前置准备

建议准备以下环境：

- macOS
- 已安装 Kiro
- 已安装 Wireshark
- 最好同时有 `tshark`
- 知道 Kiro 当前是否走本机代理

如果你是通过本机代理软件出网，比如 Clash、Surge、V2RayN、Shadowrocket 之类，且本机代理监听在 `127.0.0.1:7890`，那么最容易抓的是本地回环接口 `lo0`。

如果 Kiro 不走本机代理，而是直接联网，就抓物理网卡，比如 `en0`。

## 4. 推荐目录

建议先准备一个临时目录，专门放本次抓包文件：

```bash
mkdir -p ~/kiro-usage-capture/captures
cd ~/kiro-usage-capture
```

建议至少准备这两个文件：

- `captures/kiro-usage.pcapng`
- `captures/kiro-sslkeys.log`

## 5. 让 TLS 可以被 Wireshark 解密

如果只抓到 TLS 加密流量，而没有会话密钥，那么你只能看到 Kiro 连到了哪个域名，通常看不到 `/getUsageLimits` 这种明文路径。

Kiro 是 Electron 应用，可以通过 `SSLKEYLOGFILE` 导出 TLS 会话密钥。

先关闭 Kiro，然后用下面的方式启动：

```bash
export SSLKEYLOGFILE="$HOME/kiro-usage-capture/captures/kiro-sslkeys.log"
rm -f "$SSLKEYLOGFILE"
SSLKEYLOGFILE="$SSLKEYLOGFILE" /Applications/Kiro.app/Contents/MacOS/Electron
```

说明：

- `/Applications/Kiro.app/Contents/MacOS/Electron` 是当前这台机器上 Kiro 的可执行文件。
- 启动后如果 `captures/kiro-sslkeys.log` 开始增长，说明 TLS key log 已生效。

## 6. 开始抓包

### 6.1 走本机代理时

如果 Kiro 流量先发到 `127.0.0.1:7890`，优先抓 `lo0`：

```bash
sudo tshark -i lo0 -f "tcp port 7890" -w captures/kiro-usage.pcapng
```

### 6.2 直连外网时

如果 Kiro 直接访问公网，把接口名替换成你的实际网卡：

```bash
sudo tshark -i en0 -f "tcp port 443" -w captures/kiro-usage.pcapng
```

## 7. 触发目标请求

开始抓包后，回到 Kiro，按下面动作触发请求：

1. 打开 Kiro。
2. 等主界面完全加载。
3. 点击左下角头像。
4. 打开账户/套餐/额度弹窗。

这一动作通常会触发一次带 `isEmailRequired=true` 的 `GetUsageLimits` 请求。

如果你只是停留在主界面，不点账户弹窗，Kiro 后台也可能会周期性请求一次不带 `isEmailRequired` 的版本。

## 8. 停止抓包

抓到一次后就可以停止 `tshark`，通常 `Ctrl+C` 即可。

如果你用的是 Wireshark GUI，点击红色停止按钮即可。

## 9. 在 Wireshark 中解密和定位请求

### 9.1 配置 TLS key log

打开 Wireshark：

1. `Wireshark` -> `Settings` / `Preferences`
2. `Protocols`
3. `TLS`
4. 找到 `Pre-Master-Secret log filename`
5. 选择你的 `captures/kiro-sslkeys.log`

### 9.2 常用过滤器

如果你是走本机代理，先用：

```text
ip.addr == 127.0.0.1 && tcp.port == 7890
```

如果你要找目标域名，用：

```text
tls.handshake.extensions_server_name == "q.us-east-1.amazonaws.com"
```

如果 TLS 已成功解密，可以直接查找：

```text
getUsageLimits
```

或者在包详情里找：

- `:path: /getUsageLimits?...`
- `:method: GET`
- `:authority: q.us-east-1.amazonaws.com`

如果 Wireshark 没把 HTTP/2 头完整展开，也可以用 `Find Packet` 搜索 `/getUsageLimits`。

## 10. 用 Kiro 自身日志交叉验证

即使 pcap 里只拿到了目标域名，没有完全看到明文 query，Kiro 自身日志通常会把 `GetUsageLimitsCommand` 的输入输出打出来。

搜索方式：

```bash
rg -n "GetUsageLimitsCommand" "$HOME/Library/Application Support/Kiro/logs"
```

重点文件通常在：

```text
~/Library/Application Support/Kiro/logs/<时间戳>/window1/exthost/kiro.kiroAgent/q-client.log
```

你会看到两类记录：

- 后台刷新：
  - `origin=AI_EDITOR`
  - `profileArn=...`
  - `resourceType=AGENTIC_REQUEST`
- 账户弹窗：
  - 上面 3 个参数不变
  - 额外多一个 `isEmailRequired=true`

## 11. 用本地源码确认请求构造逻辑

Kiro 本地扩展代码里能看到这条请求是怎么拼出来的。

### 11.1 找请求序列化函数

```bash
sed -n '587560,587580p' /Applications/Kiro.app/Contents/Resources/app/extensions/kiro.kiro-agent/dist/extension.js
```

这里可以看到：

- 路径是 `/getUsageLimits`
- 方法是 `GET`
- 参数来自：
  - `profileArn`
  - `origin`
  - `resourceType`
  - `isEmailRequired`

### 11.2 找调用方

```bash
sed -n '690913,690940p' /Applications/Kiro.app/Contents/Resources/app/extensions/kiro.kiro-agent/dist/extension.js
```

这里可以看到：

- `origin: "AI_EDITOR"`
- `resourceType: "AGENTIC_REQUEST"`
- `profileArn` 通过 `resolveProfileArn({ required: true })` 获取
- `isEmailRequired` 根据场景传入

## 12. 用日志确认轮询间隔

轮询信息可以直接在 Kiro 扩展日志里找到：

```bash
rg -n "usageLimits.getUsageLimits|intervalMs" "$HOME/Library/Application Support/Kiro/logs"
```

当前已确认日志内容类似：

```text
[agent-event-polling] Service created {"command":"kiro.usageLimits.getUsageLimits","intervalMs":300000,"aggregationDelayMs":120000}
```

这说明 Kiro 自身确实有 `300000ms` 的轮询任务。

## 13. 本次可复原的真实请求

根据抓包、Kiro 日志和本地扩展源码，可以还原为：

```text
GET https://q.us-east-1.amazonaws.com/getUsageLimits?origin=AI_EDITOR&profileArn=<PROFILE_ARN>&resourceType=AGENTIC_REQUEST&isEmailRequired=true
```

说明：

- `isEmailRequired=true` 主要出现在打开账户弹窗时。
- 后台轮询版本通常不带 `isEmailRequired`。
- 请求头里实际还会带 `Authorization: Bearer <access_token>`。

## 14. 返回 JSON 中哪些字段控制 UI

以本次真实返回为例，关键字段映射如下：

| 返回字段 | UI 含义 |
|---|---|
| `userInfo.email` | 弹窗顶部邮箱 |
| `userInfo.userId` | `User ID` |
| `subscriptionInfo.subscriptionTitle` | 套餐标题，如 `Kiro Free` |
| `usageBreakdownList[0].currentUsageWithPrecision` | 已使用额度 |
| `usageBreakdownList[0].usageLimitWithPrecision` | 总额度 |
| `usageBreakdownList[0].nextDateReset` | 重置时间 |

例如：

```json
{
  "subscriptionInfo": {
    "subscriptionTitle": "KIRO FREE"
  },
  "usageBreakdownList": [
    {
      "resourceType": "CREDIT",
      "displayNamePlural": "Credits",
      "currentUsageWithPrecision": 8.68,
      "usageLimitWithPrecision": 50,
      "nextDateReset": "2026-06-01T00:00:00.000Z"
    }
  ],
  "userInfo": {
    "email": "xxx@example.com",
    "userId": "d-..."
  }
}
```

## 15. 复现实操建议

如果你下次要自己重复抓一次，建议按这个顺序来：

1. 用 `SSLKEYLOGFILE` 启动 Kiro。
2. 用 `tshark` 抓 `lo0` 或实际网卡。
3. 在 Kiro 里点开账户弹窗。
4. 在 Wireshark 里搜 `q.us-east-1.amazonaws.com` 和 `getUsageLimits`。
5. 再用 `q-client.log` 搜 `GetUsageLimitsCommand`。
6. 最后用 `extension.js` 交叉验证参数和调用位置。

这样就算 pcap 里的明文没有完全显示，也能把请求链路补齐，不会只停留在“猜接口”。

## 16. 常见问题

### 16.1 看到了 TLS，但没有明文路径

通常是 `SSLKEYLOGFILE` 没生效，或者 Wireshark 没加载 `kiro-sslkeys.log`。

### 16.2 抓不到 Kiro 请求

通常是接口抓错了：

- 走本机代理时抓 `lo0`
- 直连时抓真实网卡

### 16.3 只看到 `q.us-east-1.amazonaws.com`，没看到参数

先看 `q-client.log`，它一般会把 `input` 和 `output` 一起打出来。

### 16.4 `profileArn` 每个账号都一样吗

不是。它跟当前 Kiro 账户绑定，换账号后通常会变化。

## 17. 本次证据文件

本次实际分析用到的本机文件如下：

- 抓包文件：`/Users/vpen/Documents/Codex/2026-05-12/wireshark-kiro/captures/kiro-usage.pcapng`
- TLS key log：`/Users/vpen/Documents/Codex/2026-05-12/wireshark-kiro/captures/kiro-sslkeys.log`
- Kiro 请求日志：`/Users/vpen/Library/Application Support/Kiro/logs/20260512T193917/window1/exthost/kiro.kiroAgent/q-client.log`
- Kiro 扩展日志：`/Users/vpen/Library/Application Support/Kiro/logs/20260512T193917/window1/exthost/kiro.kiroAgent/Kiro Logs.log`
- Kiro 本地扩展代码：`/Applications/Kiro.app/Contents/Resources/app/extensions/kiro.kiro-agent/dist/extension.js`

## 18. 和本项目的关系

当前 `kiro-gateway` 已按同一条接口实现了后台轮询：

- 每 `300000ms` 请求一次 `getUsageLimits`
- 提取：
  - `subscriptionInfo.subscriptionTitle`
  - `usageBreakdownList[*].currentUsageWithPrecision`
  - `usageBreakdownList[*].usageLimitWithPrecision`
- 保存到 `kiro_accounts` 表的当前用量字段上
- 每次轮询只覆盖更新一次，不再追加历史快照行
- 在 `/admin` 的 Accounts 页面展示账户当前用量
