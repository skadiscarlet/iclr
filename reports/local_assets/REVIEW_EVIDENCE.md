# 本地资产远程审阅证据

状态：已填写。下列证据支持结构/计数/隔离关系，不证明标签语义为真，也不构成负责人已阅读原文。

## 证据 E-X01

| 字段 | 真实内容 |
|---|---|
| 支持的主张 | 跟踪的候选 registry 有 24 个不重复 pair 行，每行是一对而非单文件；catalog 文件本轮未 profile |
| 输入资产及快照 | A-R01-CANDIDATES `sha256:ec6afbbf07a9cf39c5115bb0f28b27e4402b4afc642799534df6c6b37db1c9a6`；A-EGSI-T1-CATALOG profile=`symlink_not_followed` |
| 运行命令/代码 SHA | `python -m sbs validate-registry --input metadata/r01_candidates.jsonl`；`tools/local_asset_xcheck.py`；collection `e154e27dad197253b2594405a4c253bf857c2744` |
| 真实输出摘要 | X01 status=partial；`catalog_record_count=not_profiled_this_round` |
| 原始本地输出哈希 | scan inventory `sha256:a5bbcb4abf5baee7ab299e595977b0e066a8e63fe38537224b8f205bb61a7619`（不是数据集内容哈希） |
| 可以公开的最小材料 | 字段名列表与 pair 计数；不公开 catalog 行 |
| 证据不能证明什么 | 不能证明 24 行覆盖了整个上游 catalog，也不能证明类别主张语义正确 |
| 真人或负责人核验 | pending / not_remotely_reviewed |

## 证据 E-X02

| 字段 | 真实内容 |
|---|---|
| 支持的主张 | `ready=yes` 的两对在 `local_data/r01/actor/<pair_id>/` 有 case.json 与 evidence body/json；body sha256 与 metadata 一致；actor 对象无答案字段 |
| 输入资产及快照 | A-R01-READINESS；A-R01-ACTOR-PACKS 文件 sha256 见 `reports/local_assets/index.jsonl` |
| 运行命令/代码 SHA | `tools/local_asset_xcheck.py` 调用 `sbs.schema.parse_case_view` / `reject_answer_fields` |
| 真实输出摘要 | X02 passed；ready=2；actor_ok=2；missing_dirs=0 |
| 原始本地输出哈希 | actor 文件级 sha256 已写入 index；不发布 body |
| 可以公开的最小材料 | 字段名、文件存在性、哈希对照 |
| 证据不能证明什么 | 哈希一致不能证明摘录覆盖了被引用的产品义务，也不能证明许可可再分发 |
| 真人或负责人核验 | pending / not_remotely_reviewed |

## 证据 E-X04

| 字段 | 真实内容 |
|---|---|
| 支持的主张 | 四个 fixture 的 History 与 SBS 观察 ID/顺序一致；SBS `material` sha256 与 `fixtures/r01/<case>/evidence/<id>.body` 一致（9/9） |
| 输入资产及快照 | A-R01-FIXTURES material `sha256:6493329cf01d7a08aa955712dc438b23a9c60805d299dc44342b98c79127b398`；A-R01-SMOKE |
| 运行命令/代码 SHA | `sbs.views.views_share_evidence` + body 哈希；experiment SHA `dcf80581b7d887a761d9acf484f6fef13a516d8c` |
| 真实输出摘要 | X04 passed；`history_events_with_material=0`（History schema 不含正文） |
| 原始本地输出哈希 | 见 run_manifest `material_sha256` |
| 可以公开的最小材料 | 合成 fixture 已在 Git；此处不重复粘贴 Java 片段 |
| 证据不能证明什么 | 合成例子不能证明真实样本的 History/SBS 公平性；只比 ID 不够，因此额外做了 body 哈希 |
| 真人或负责人核验 | pending；synthetic_example |

## 证据 E-X05

| 字段 | 真实内容 |
|---|---|
| 支持的主张 | 跟踪的 R01 run_manifest 与 gitignored `artifacts/r01_smoke/run_manifest.json` 在 mode/seed/split/model_calls/config/material/code_sha 上一致；config 与 fixture material 哈希可重算；输出文件存在；`model_calls=0` |
| 输入资产及快照 | `reports/rounds/R01/run_manifest.json`；`configs/r01_smoke.json`；`fixtures/r01` |
| 运行命令/代码 SHA | `sbs.replay.material_hash` + `canonical_json_bytes`；未重跑 replay |
| 真实输出摘要 | X05 passed；`code_sha=dcf80581b7d887a761d9acf484f6fef13a516d8c` |
| 原始本地输出哈希 | config `sha256:8e08f410ccaae54b7971b69508ef06198a53ca8d33da73e5c216105f3fad1454` |
| 可以公开的最小材料 | 已跟踪 manifest |
| 证据不能证明什么 | 不能证明这是真实模型实验；不能把 collection_code_sha 当成 experiment SHA |
| 真人或负责人核验 | pending |

## 证据 E-X06 / E-X07

| 字段 | 真实内容 |
|---|---|
| 支持的主张 | `human_verified_pairs=0`；R01 status 五项计数与 `count_inventory` 重算一致 |
| 输入资产及快照 | `metadata/r01_candidates.jsonl`、`metadata/r01_readiness.csv`、`reports/rounds/R01/status.json` |
| 运行命令/代码 SHA | `sbs.registry.count_inventory` / `human_verified_count` |
| 真实输出摘要 | X06 passed；X07 passed；discrepancies=none（计数）；catalog 覆盖仍为缺口 |
| 可以公开的最小材料 | 计数表 |
| 证据不能证明什么 | 0 个 human_verified 不是“标签都错/都对”；只是没有真人记录 |
| 真人或负责人核验 | 未进行 |

## 证据 E-X08

| 字段 | 真实内容 |
|---|---|
| 支持的主张 | R01 fixture 回放重建入口都在 Git（`src/sbs/replay.py`、`configs/r01_smoke.json`、`fixtures/r01`）。真实 actor 包重建还依赖 gitignored `local_data/` 与未跟随的 `data/`。`providers.local.toml` 等忽略文件不是 R01 replay 依赖 |
| 输入资产及快照 | A-R02A-SCANNER；A-IGNORED-LOCAL-TOOLING（名称存在，内容未读） |
| 运行命令/代码 SHA | 路径存在性检查；collection SHA `e154e27dad197253b2594405a4c253bf857c2744` |
| 真实输出摘要 | X08 partial；ignored_local_present_count=6 |
| 可以公开的最小材料 | 跟踪路径列表 |
| 证据不能证明什么 | 不能证明忽略文件不含秘密；本轮故意不打开它们 |
| 真人或负责人核验 | pending |

没有可公开的真实样本正文时，远程语义核验受限：`semantic_content_not_reviewable_remotely`。不把 AI 摘要当作已审阅。
