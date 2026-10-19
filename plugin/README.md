# 工具栏按钮（可选）

把「跑一遍验证」变成输入框旁边的一个盾牌按钮。**只适用于 DeepSeek Harness（DSH）**，
其他 MCP 客户端用不到它 —— 它们只有三个工具，没有输入框工具栏。

## 它做什么

| 动作 | 结果 |
|---|---|
| 单击 | 把「快速检查」请求填进输入框（`fast=true`） |
| Shift + 单击 | 填「完整检查」请求（含测试与浏览器层） |
| 双击 | 撤销，恢复点击前的草稿 |

**它不会自动发送**：只把一段话写进输入框，你改完按回车才真的跑。
Client 侧拿不到 agent 的工具执行权，真正跑验证的是 Host 上的 MCP 工具。

双击撤销有一道保险：如果输入框里的内容已经被你改过，它会**拒绝撤销**并提示
「输入框已改动，未撤销」—— 宁可撤销失败，也不能把你打的字冲掉。

## 安装（DSH）

让 agent 装（推荐）：

```
用 plugin_manager 安装 plugin 目录：
target = /绝对路径/verify-helper/plugin
```

或者手动：把 `plugin/` 放进 DSH 的 profile，并在 `cordis.patch.yml` 里加

```yaml
- insert:
    - id: verify-helper-button
      name: '@local/verify-helper-button'
```

装完**刷新页面**，输入框左下角出现盾牌图标。

## 卸载

删掉上面那条 `insert` 即可，或让 agent 执行 `plugin_manager remove_bundle`。

## 自己改

`client.js` 是可读源码，改完刷新页面生效。里面两段提示词就是它填进输入框的内容：

```js
const PROMPT_FAST = '用验证助手检查当前项目（MCP 工具 verify_start，…fast=true）…'
const PROMPT_FULL = '用验证助手完整检查当前项目（…不加 fast）…'
```

想让它填别的要求（比如「顺便把结果写成 md」），改这两行就行。
