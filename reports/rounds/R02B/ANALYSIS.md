# R02B 分析（观察，不是创新声明）

依据 `artifacts/r02b/runs/2026-09-17T141202+0000` 与 `run_index.json`。语义指标未经真人核验，保持 null。

## 五个问题

1. **实际完成多少个独立版本、完整对、episode、模型请求？分母是什么？**
   - catalog 24 个登记对象全部 unique_match；22/24 两侧 cited blob 独立存在。
   - R02B actor：8 个 version-bound instance，4 个 complete_version_pairs（2 conventional + 2 logic drafts）。分母：selection 4 对 × 2 版本。
   - 第一批协议分母：1 对 × 2 instance × 2 表示 × 1 顺序 × 4 步 = 16 主请求，加上 E0 2 次，合计 18。实际 `requests_attempted=18`。
   - 完整矩阵 128 主请求未跑。logic drafts 的义务仍 generic，不进入语义合格集。

2. **G0 是否都通过？真实 prompt 的公共证据对齐记录在哪里？**
   - G01–G12 pytest 57 passed（含 R01 `model_calls_allowed=0` fixture replay）。
   - 运行时每步 `render_fair_prompts` 后比较；`run_manifest.fairness_hashes` 与各 episode `fairness` 字段记录公共 evidence block sha256。同一 instance 的 history/sbs 在 form/read_0/read_1/final 上哈希一致。form 步无已读证据，clip_bounds 为 `[0,0]`。

3. **模型主要失败是输出格式、证据引用、假设质量、规格不足还是上下文不足？**
   - **主失败是输出格式。** 18/18 `parse_status=parse_error`。原响应被原样保存。典型模式：用 markdown 围栏包住 JSON；部分 `verdict` 为 `"True"` 而非 supported/refuted/unresolved。执行端没有剥离围栏或改写 verdict。
   - 因此引用绑定未应用（`ref_status=parse_error`），无法在本轮判断引用错误 vs 假设质量。
   - 上下文：输入约 110–385 tokens，远低于 3072；未出现 `context_insufficient`。
   - 规格：logic 草案仍 generic，本批用的是 conventional pair-01。

4. **未做语义核验前，哪些是可以报告的工程指标，哪些必须 null？**
   - 可报告：请求数、token、时延、parse/ref 状态、fairness hash、version-bound 计数、catalog unique_match。
   - 必须 null：accuracy / F1 / GPC / reward / human_verified。草案标签不是奖励。
   - 模型 refuted 的只是它自己的假设，不能等同于目标漏洞不存在；本轮甚至没有合法 JSON verdict。

5. **下一轮首要工作？**
   - 优先继续修输入与输出契约：允许一次仅修格式的计数重试（仍禁止改结论），或更强的 JSON-only 约束；不要在 1.5B 解析失败上宣称表示干预有效。
   - 逻辑样本仍缺非 generic 义务依据，扩模型或训 Q 都不会补上。
   - 真人核验仍未做。不自行启动 R03。

## 轨迹摘录（失败优先）

- E0 `e0_0.txt`：合法键集合但围栏 JSON，`parse_error`。
- pair-01 history final：围栏 JSON 且 `verdict=True`，`parse_error`。两条轨迹的公共 evidence hash 在同一步上与 SBS 一致。

原始全文仅本地 `artifacts/r02b/runs/`，远程 `content_not_remotely_reviewed`。
