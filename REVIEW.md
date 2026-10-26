# 本仓库的评审约定（给 verify-helper 自己看）

失败意味着：**一个检查在真项目上给出了错误结论**（假阴性/假阳性），
而不是"代码风格不合口味"。

- 测试夹具里有 `os.system(...)` / `eval(...)` 这类字符串 —— 那是**被测对象**，
  不是本项目的危险调用。安全层对本仓库的 `tests/**` 豁免。
  security-skip: tests/**
- 不报纯风格问题（a11y 那类只对 HTML 站点有意义）。
  no-style: true
- 报出来的每条必须带 `file:line`；没有位置的别报。
  require-evidence: true
- 低风险提示最多 5 条，多了就是噪声。
  max-nits: 5
- 例子配置里的 `http://` 是示例文本，允许。
  security-skip: examples/**

fail-means: 检查对真项目给出了错误结论（假阴性/假阳性）
