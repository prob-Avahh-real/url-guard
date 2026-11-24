# URL Guard

Chrome / Edge（Manifest V3）浏览器扩展：根据**网址本身**甄别钓鱼、欺诈、博彩等伪站点。

## 能力

- 仿冒品牌（拼写变形、同形字符、品牌-secure 子域）
- 博彩 / 欺诈话术关键词（中英）
- 高风险顶级域、IP 主机、`user@host` 伪装、Punycode
- 本地黑名单 + 可扩展白名单
- 高危页顶栏警告；工具栏徽标与弹窗详情

检测在本地完成，不上传浏览记录。启发式有误报/漏报，**不能替代**专业威胁情报或人工判断。

**信任域名只能通过扩展弹窗写入**（页面顶栏不可点「信任」，防止钓鱼页脚本自动放行）。白名单拒绝 `com` / `edu.cn` 等公共后缀。

## 安装（开发者模式）

1. 打开 `chrome://extensions`（Edge：`edge://extensions`）
2. 打开「开发者模式」
3. 「加载已解压的扩展程序」→ 选择本目录 `active/url-guard`
4. 访问可疑链接，查看工具栏图标与页面顶栏提示

## 开发

```bash
npm test              # 全量单测 + c8 覆盖率门禁（lines/funcs/branches ≥ 90%）
npm run test:coverage # 另输出 coverage/ HTML 报告
npm run icons         # 重新生成 icons/*.png
```

覆盖范围：`lib/**`（`analyze.js` / `evaluate.js` / `rules.js`）。扩展 UI（`background.js` 胶水、`content.js`、`popup.js`）需浏览器手工验证。

## 结构

```
lib/analyze.js     # 核心评分
lib/rules.js       # 品牌 / 关键词 / 可疑 TLD
background.js      # 标签页扫描、徽标、名单
content.js         # 页面警告条
popup.*            # 详情与信任/拉黑
data/blocklist.json
```

## 使用提示

- **信任此域名**：写入本地白名单，不再提示
- **拉黑此域名**：强制高危
- 弹窗可暂时关闭整站检测
