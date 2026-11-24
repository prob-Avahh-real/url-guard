# url-guard

URL Guard Chrome / Edge（Manifest V3）浏览器扩展：根据**网址本身**甄别钓鱼、欺诈、博彩等伪站点。 能力 - 仿冒品牌（拼写变形、同形字符、品牌-secure 子域） - 博彩 / 欺诈话术关键词（中英） - 高风险顶级域、IP 主机、`user@host` 伪装、Punycode - 本地黑名单 + 可扩展白名单 - 高危页顶栏警告；工具栏徽标与弹窗详情 检测在本地完成，不上传浏览记录。启发式有误报/漏报，**不能替代**专业威胁情报或人工判断。

## 用途与 Target 判定

浏览器扩展：按 URL 甄别钓鱼站点

- 移动端：不适用
- 智能硬件：不适用

## 目标平台

本目录**不是**需双 Target 交付的消费级 App（见用途）。按实际形态维护即可。

## 技术栈信号

- 检测到：browser-extension, node

## 命令

```bash
# Chrome → 扩展程序 → 加载已解压的扩展程序 → 选本目录
npm test   # 若有
```

## 助手约束

- Loop：先定可验证 Done 与停止条件；每切片过验证环；失败回灌；详见 docs/LOOP_ENGINEERING.md
- Harness：遵循根 AGENTS「Harness Engineering」；Guide=本文件，Sensor=测试/CI；同类失误二次须沉淀规则或测试（棘轮）。详见 docs/HARNESS_ENGINEERING.md
- 遵循仓库根 `AGENTS.md`：通用性/扩展性、分阶段里程碑、默认双 Target（**仅当用途适合**）
- 可选 Target 未做时可搁置；不要为不适用形态硬加 APK/穿戴
- 改动保持聚焦；公共逻辑抽到 shared/`tools/`，禁止静默失败

## 验证环 / Done

```bash
npm install
npm test          # 若有
npm run build     # 或 build:web
npx cap sync android   # 若有 android/
# 可选：JAVA_HOME=…/openjdk@17 npm run apk:debug
```

**Done 示例**：测试通过（若有）+ web 产物进 `www/`/`dist/` + `cap sync` 无报错。可选穿戴未做可搁置，不纳入强制 Done。
