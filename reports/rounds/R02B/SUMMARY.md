# R02B 任务总结

## 实际版本与任务状态

- 仓库：`skadiscarlet/iclr`
- 分支：`research/naacl2027-r02`
- 已复核基线（祖先）：`26e86bccfa656e59b3e234fd3fd05e4c83e357ec`
- Implementation SHA（当前代码，含稳定 ledger）：`5d3e468a029262cb2c25a734572b52db8242c14d`
- 冻结模型运行所用 SHA：`59301b66c98cdb960bc35550939d0c0fcecbefd7`
- engineering=completed；data=partial；model_run=completed；human_annotation=not_checked；delivery=checkpoint_verified；review=pending
- G0=passed。训练=not_started_by_design。新 CVE 发现=none_by_design。

CLI 实际命令：`python -m sbs prepare-pilot` / `validate-pilot` / `run-pilot` / `validate-reports`。

## 这次改变了什么

| 子任务 | 状态 | 观察 |
|---|---|---|
| B00 | completed | `AGENTS.md` 增加 R02B 路由；未覆写 R01/R02A |
| B01 | completed | catalog 300 条 complete；24/24 unique_match；execute-only 未读 `excluded_nonblocking` |
| B02 | completed | History 含 material；最终 prompt 公共证据对齐；G01–G12 通过；R01 fixture 仍 `model_calls_allowed=0` |
| B03 | completed | 8 version-bound instance / 4 complete pairs；旧 R01 包未覆写；logic 2 对仍 generic |
| B04 | completed | 锁定 `Qwen/Qwen2.5-Coder-1.5B-Instruct` revision `2e1fd397ee46e1388853d2af2c993145b0f1098a`，cpu/fp32，`trust_remote_code=false` |
| B05 | completed | 第一批 1 对 ×2×2×1×4=16 加上 E0 2，共 18 真实请求；第二次 CLI 运行同样 18 条非空响应 |
| B06 | completed | 报告 + 稳定 request ledger（`open_request_ledger`）；G12 二次打开续计 seq |

最终 prompt 正文对齐：见 `run_manifest.fairness_hashes` 与 ANALYSIS。

## 真正的数据量

见 `DATA_AUDIT.md`。catalog_records=300；legacy_ready_flag_pairs=2（历史字段）；complete_version_pairs=4；human_verified=0；independent_group_count=null。

## 模型与运行

- 型号+revision：Qwen/Qwen2.5-Coder-1.5B-Instruct @ `2e1fd397ee46e1388853d2af2c993145b0f1098a`
- 权重 sha256：`sha256:c1b9b30e907950516ba3c646bdf570d8084c25a6410a0cdca80cf04b11bc13a8`
- tokenizer sha256：`sha256:c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539`
- device/dtype：cpu / float32；greedy seed 17
- 主 run：`artifacts/r02b/runs/2026-09-17T141202+0000`，18 请求，4 episode
- 全部 `parse_error`（围栏 JSON / 非法 verdict）；raw 已存；未修语义
- 语义指标：null

## 本地未提交内容

`reports/LOCAL_ASSETS.md`。catalog 行值、第三方源码、完整模型输出、权重不上传。

## 失败与下一步依据

18/18 格式解析失败。G0 与公平哈希通过，所以瓶颈在模型 JSON 契约而不是公共证据对齐。logic 义务仍 generic。不启动 R03。

## Git交接

冻结运行 A=`59301b66c98cdb960bc35550939d0c0fcecbefd7`。稳定 ledger 实现=`5d3e468a029262cb2c25a734572b52db8242c14d`（B 之前 `git ls-remote` 已观察到）。B=`58301377eb85a6c41ecbc07e03342b381fecd605`（推送后远程 SHA 匹配）。C 回执只记录该已观察远程 SHA，不自哈希。R01/R02A 历史未覆写。
