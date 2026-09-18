# R02C 任务总结

## 实际身份

- 仓库：`skadiscarlet/iclr`
- 分支：`research/naacl2027-r02`
- 已复核基线（祖先）：`148f59948200bfe5d25a30c8c5115f613dc4f9fb`
- 冻结运行所用实现 SHA：`4243137c57b2bee6db26662893a89e6e71b0c18f`
- 更早实现提交：`c254c6f4a582b545a8af8506557f50c1a9cff266`（契约/诊断）、`8b392fdb0054bd1989f7d00fd608e0484f9d083f`（chat-template mapping 计数）
- 报告 SHA：见后续 B 提交（本文件写入时尚未推送）
- UTC 运行结束：`2026-09-18T04:49:52+00:00`
- engineering=completed；data=partial；model_run=completed；human_annotation=not_checked；delivery=not_pushed（pre-push）；review=pending
- 训练=not_started_by_design。新 CVE 发现=none_by_design。语义分数/reward/QV=null。

CLI 实际名称：`python -m sbs diagnose-output|prepare-pilot|validate-pilot|run-pilot|validate-reports`，`--task R02C`。

## 这次改变了什么

| 子任务 | 状态 | 观察 |
|---|---|---|
| C00 | completed | 路由改为 R02C；祖先检查通过；未覆写 R02B raw |
| C01 | completed | 三登记运行 38 个唯一事件；保守消耗 38；0 模型调用 |
| C02 | completed | 三类契约、SBS 原子卡、E0 硬门、runtime 不读 evaluator；C-T01–C-T18 假模型通过 |
| C03 | completed | 8 实例与原 blob 切片一致；两张逻辑卡 `concrete_unreviewed`；HUMAN_CHECK 两个问题 |
| C04 | completed | 锁定同一 Qwen 1.5B revision；E0 6 案；1/6 schema 合格；E1 generate=0 |
| C05 | running | 本报告；推送前 delivery 不得 completed |

## 旧失败到底是什么

38 是报告下限，本地唯一事件也是 38（uncertainty=none）。历史 parser 把 37 条有 raw 的响应都叫 `parse_error`；离线分层：37 条去掉整响应围栏后 JSON 语法有效，其中 5 条形状合格（自建 E0 `verdict=supported`），32 条形状非法（E1 常见 `"verdict":"True"` / `"Yes"`）。1 条 pre-A E0 缺 `e0_0.txt`（FileNotFoundError）。去围栏可解析 **不是** 恢复的 SBS 轨迹。

## 修复是否进入真实调用路径

`sbs.output_contract.parse_response`、`sbs.r02c_state.apply_sbs_card`、`run_r02c_pilot` 的 E0 门与 `validate_r02c_manifest` 是实际 runner。测试入口：`python -m unittest discover -s tests/r02c_contract -v` 与 `pytest tests/sbs/test_r02c.py`。假模型证明 validation 失败不加载模型、E0 失败则 E1=0。

## 新模型实际结果

- 新预约 24（AttributeError 空生成 12 + 调试 generate_chat 1 + 本协议 E0 11）
- 有正文的生成 12（调试 1 + E0 11）；缓存命中 0
- E0 first-pass 1/6（probe-01 history_note）；after-reprompt 仍 1/6
- E1 gate=`e0_schema_or_refs_failed`；E1 generate=0（接受的模型运行结局）
- 项目保守消耗 38+24=62 ≤ 192；本轮 ≤ 48
- 主 run：`artifacts/r02c/runs/2026-09-18T044445+0000`，code_sha=`4243137c57b2bee6db26662893a89e6e71b0c18f`
- 自建 E0 全文见 `reports/rounds/R02C/e0_public/`

## 数据和真人工作

两张逻辑卡均为 **concrete_unreviewed**，不是模板 `obligation_generic=True`。`human_verified=false`。HUMAN_CHECK.md 两个问题。pair-13 `getItem` 截断；pair-15 仅为 for-loop 片段。

## 边界

真实样本 raw 未远程审阅。E1 未跑，没有真实 SBS 卡片链。单证据接口先导即使将来 E1 通过也不能证明证据选择学习。小模型未过 E0 六案门槛。
