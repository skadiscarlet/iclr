# 本地未提交资产总览

> 状态：已根据 `artifacts/local_asset_scan/r02/` 扫描、`metadata/r01_*` 与 X01–X08 填写。远程内容审阅未进行。`scan_complete=false`。

## 1. 快照和覆盖范围

| 字段 | 实际填写 |
|---|---|
| round / collection code SHA | R02A / `5a6cb24d4c5448194277ed924b31dd0c8b5339e6`（允许声明根 `data/` 符号链接按别名清点） |
| experiment implementation SHA（可以不同） | `dcf80581b7d887a761d9acf484f6fef13a516d8c`（R01 fixture replay / registry 实现，未改） |
| 采集时间（带时区） | 2026-09-17T13:10:18.604101+00:00 |
| 资产工作区别名 / 交付工作区别名 | `primary_workspace` / `delivery_workspace`（同一工作树；无独立空 worktree） |
| 扫描目录与明确排除范围 | roots: `data` `local_data` `artifacts` `.work` `metadata` `configs` `scripts` `src`。排除 `.git` `.venv` `venv` `node_modules` `__pycache__` 及提取器自身输出。声明根可以是目录符号链接，只通过 `data/` 别名走，**不把目标绝对路径写入输出**；嵌套符号链接仍不跟随。 |
| 完整性 | **partial**。`data/` 已按别名清点：`declared_root_is_symlink=true`，提取器前缀 21896 文件（budget 为 `.work` 留位）；`find -H data -type f` 为 398686（`raw/` 为主）。`scripts/` 3 个 execute-only `PermissionError`。`listing_complete_within_declared_scope=false`。 |
| 扫描器版本/内容哈希 | collection_code_sha 如上；工具 `tools/local_asset_handoff.py` |
| 原始扫描结果清单哈希 | `sha256:7e66924b7f052e8eb5ab54005c30d43dbf4d11063d839439f8403fb2dc1e3a7c`（file_inventory.jsonl；**不是**数据集内容哈希；该清单不提交） |
| 人工核验与负责人远程读取状态 | `human_verified_pairs=0`；`content_not_remotely_reviewed`；`review_status=pending` |

扫描两次 CLI 均 exit 0，`files_observed=28879`，各 root status 一致，`publication_status=local_review_required`。catalog profile `complete`，`scanned_records=300`。

## 2. 资产总表

| asset_id | 内容和用途 | 记录单位与真实规模 | 质量状态 | 为何未提交 | 远程可用证据 | 影响下一任务 |
|---|---|---|---|---|---|---|
| A-R01-CANDIDATES | 每行一个问题对元数据（版本定位、类别主张、split） | pair 行 24；project_family 24；完整读取 tracked jsonl | 自动化 registry；非真人核验 | 已跟踪 | metadata_and_checks + 文件 sha256 | R02 仍按这 24 对，不扩未授权集合 |
| A-R01-READINESS | 每行一对的 ready/blocker 静态表 | csv 行 24，其中 ready=yes 2 | 静态检查；logic ready=0 | 已跟踪 | metadata_and_checks + profile enum | 不能把 ready 当 human_verified |
| A-EGSI-T1-CATALOG | 上游 catalog；每行一条问题对 JSON | 7 个 catalog 文件；`cases.jsonl` **300** 条 complete；`data/` 树 find 398686 文件（提取器前缀 21896） | 可读；非真人核验；R01 只用其中 24 对 | 第三方语料，gitignore `/data` | metadata_and_checks（schema/enum，无行值） | 24 是抽样，不是全量 |
| A-R01-ACTOR-PACKS | 两个 ready 对的 actor case + 一段源码摘录 | 2 目录 / 6 文件；body 哈希与 evidence json 一致 | 材料就绪（conventional 2）；非真人核验 | 真实摘录，gitignore `local_data/` | metadata_and_checks（无正文） | 重建依赖 gitignored `data/` 源码缓存 |
| A-R01-EVALUATOR | 对应两对的 evaluator 答案文件 | 2 个 answers.json；值未导出 | 标签未远程审阅 | 答案隔离 | summary_only（仅文件哈希） | 禁止进入 actor 视图或 Git |
| A-R01-FIXTURES | 四个合成 fixture | 4 目录 / 28 文件；material_sha256 已重算 | synthetic；不可支撑真实样本结论 | 已跟踪 | metadata_and_checks | 与 real ready 计数分开 |
| A-R01-SMOKE | R01 离线回放输出 | 13 文件；model_calls=0 | fixture 产物；非真实模型运行 | 完整 artifacts 被忽略；报告侧 manifest 已跟踪 | metadata_and_checks | 本补充不重跑 |
| A-EGSI-WORK-CACHE | EGSI 历史目录与 venv | files_observed=6879；约 777 MiB 扫描字节的主要来源 | unverified_legacy_result | 缓存/venv，gitignore `.work/` | summary_only | 不用于 SBS 主张 |
| A-IGNORED-LOCAL-TOOLING | providers.local、lock、signer、locked launchers | 名称存在性；3 个不可读 | 非 SBS 输入 | 机器本地/密钥相邻 | summary_only | 不要提交或读取内容 |

注意：file_count、record_count、pair_count、instance_count、project_name_count、independent_group_count 口径不同。catalog 记录数为本轮 **300**（完整 profile），不是 0，也不是 R01 的 24。

## 3. 重要资产详细卡

### asset_id：A-R01-CANDIDATES

**内容与来源：** 每行是一个问题对元数据，含 `pair_id`、两个版本定位、`category_claim`、`split=dev_pilot`。`dataset_origin=egsi_t1_catalog`（registry 自报）。12 conventional + 12 logic_authorization_claim。无重复 `pair_id`。

**当前用途：** `sbs.registry` 与 `validate-registry`；X01/X06/X07。当前研究登记集，不是 actor 可见对象。

**结构和规模：** 24 行 / 24 project_family。文件 sha256 `ec6afbbf07a9cf39c5115bb0f28b27e4402b4afc642799534df6c6b37db1c9a6`。完整文件哈希，不是抽样外推。

**生成与重建：** 输入 A-EGSI-T1-CATALOG（300 行 catalog 中抽出 24 对）→ 已跟踪 `metadata/r01_candidates.jsonl`。命令模板：`python -m sbs validate-registry --input metadata/r01_candidates.jsonl`。

**质量和限制：** `human_verified=0`。`evidence_draft` 2 行（ready 对），其余 `source_resolved`。Agent 不得自报 human_verified。

**为什么不提交：** 已在 Git。

**负责人能看到什么：** metadata_and_checks。`content_not_remotely_reviewed`（未读原始 catalog 行）。

**与当前报告的差异：** 与 `reports/rounds/R01/status.json` 的 24/2/0/24/4 一致。catalog 本体未重哈希。

### asset_id：A-R01-READINESS

**内容与来源：** CSV，一行一对。`ready=yes` 仅 `r01-pair-01`、`r01-pair-12`，且 `actor_view_generated=yes` 与之相同。

**当前用途：** 静态就绪表；X02 用它找 actor 包。

**结构和规模：** 提取器 profile `complete`，`scanned_records=24`。enum：`ready` yes=2 / no=22；`split` 全 `dev_pilot`；`category_claim` conventional=12 / logic_authorization_claim=12。未导出任意单元格原文。

**生成与重建：** `src/sbs/static_check.py`（experiment SHA）。无单独 CLI。

**质量和限制：** logic ready 仍为 0；5 行 `license_clear=no`；1 行缺 citation range。这些是 R01 已记录缺口，本轮不改表。

**为什么不提交：** 已跟踪。CSV 中的上游键名不在本摘要中复述。

**负责人能看到什么：** metadata_and_checks。

**与当前报告的差异：** 无计数差异。

### asset_id：A-EGSI-T1-CATALOG

**内容与来源：** 通过仓库别名 `data/`（声明根目录符号链接，目标路径不写入报告）读取。`data/catalog/` 7 个文件均在提取器清单中。`data/catalog/cases.jsonl` profile **complete**，300 条 nonempty JSON 行。R01 registry 的 `dataset_revision=sha256:295bc9751161b4d04af1920bb464d94eb6369790936496394306bb60a7019455` 仍是 R01 自报，本轮未把整文件当数据集内容哈希发布。

**当前用途：** EGSI T1 catalog；R01 从中抽样 24 对进 `metadata/r01_candidates.jsonl`。

**结构和规模：** 记录单位=nonempty_json_line。enum：`split` train=200 / dev=60 / other=40。`status`/`category_claim` 与 R01 registry 词表不同（catalog 侧记为 `<other>`/`<missing>`，不是失败）。`data/` 整树 `find -H data -type f` = 398686（`raw/` 386579）；提取器前缀 21896（含 catalog 7、cache 8515、artifacts 3067，以及 `raw/` 的一部分）。未导出记录值。

**生成与重建：** 外部本地语料；不上传。重建入口是本地 `data/` 别名，不是 Git。

**质量和限制：** 300≠24。许可与行语义仍未远程核验。

**为什么不提交：** 第三方语料与大体量 `raw/`；gitignore `/data`。

**负责人能看到什么：** metadata_and_checks（计数与 schema/enum）。正文 `content_not_remotely_reviewed`。

**与当前报告的差异：** R01 只登记 24 对；本轮 catalog 全量 profile 为 300。不改写 R01 历史文件。

### asset_id：A-R01-ACTOR-PACKS

**内容与来源：** `local_data/r01/actor/{r01-pair-01,r01-pair-12}/`。每包 `case.json` + `evidence/ev-src-1.json` + `.body`（4000 字节）。`generation_id=r01-static-1`。`split=dev_pilot`，`material_kind=real`。Actor JSON 无答案字段；包内无 `answers.json`。

**当前用途：** IsolatedStore 的 actor 根。R01 smoke replay **没有**使用这些包。

**结构和规模：** 6 文件。body sha256 与 evidence `content_sha256` 一致（X02/X03）。

**生成与重建：** `src/sbs/static_check.py:build_actor_view`，experiment SHA。输入依赖 gitignored `data/` 源码缓存（`raw/` 为主，提取器仅前缀）。

**质量和限制：** 仅两个 conventional ready 对。摘录语义未经负责人阅读。

**为什么不提交：** 真实第三方源码摘录；`local_data/` 被忽略。

**负责人能看到什么：** metadata_and_checks（哈希与字段名）。正文 `content_not_remotely_reviewed`。

**与当前报告的差异：** 与 readiness `ready=yes` 一致；不是 fixture。

### asset_id：A-R01-EVALUATOR

**内容与来源：** `local_data/r01/evaluator/{pair}/answers.json` 各一份。本摘要不导出字段值。

**当前用途：** 仅 evaluator；审查运行器读取该根必须失败关闭。

**结构和规模：** 2 文件；给出文件 sha256，不给内容。

**生成与重建：** `not_rebuildable_yet`（无已跟踪 builder 命令）。

**质量和限制：** 不能当作已核验真值发布。

**为什么不提交：** 答案隔离。

**负责人能看到什么：** summary_only。

**与当前报告的差异：** 无。R01 已声明 actor 不得见答案。

### asset_id：A-R01-FIXTURES 与 A-R01-SMOKE

**内容与来源：** 合成四例 `support/counter/insufficient/budget`。回放命令（R01 已跑，本轮不重跑）：`python -m sbs replay --config configs/r01_smoke.json --out artifacts/r01_smoke`。`model_calls=0`。`config_sha256` 与 `material_sha256` 已用 `sbs.schema.canonical_json_bytes` / `sbs.replay.material_hash` 重算，与 tracked `reports/rounds/R01/run_manifest.json` 及 gitignored 本地 manifest 一致。`code_sha` 仍为 experiment SHA，不是本扫描器提交。

**History/SBS：** 四例 ID 与观察顺序一致。History JSON **不含** `material`。正文核对是 SBS `material` 的 sha256 对 fixture `.body`（9/9 匹配），不是只比 ID。

**为什么不提交完整 artifacts：** gitignore `artifacts/`；报告侧已有 provenance manifest。

**负责人能看到什么：** metadata_and_checks。合成示例不能证明真实样本。

### asset_id：A-EGSI-WORK-CACHE 与 A-IGNORED-LOCAL-TOOLING

**内容与来源：** `.work` 为历史 EGSI 运行与 venv（扫描 6879 文件）。忽略的 `configs/providers.local.toml`、lock、signer 记录和 locked launchers 只确认路径存在；**未读内容**。三个 execute-only launcher 无法哈希。

**当前用途：** 非 R01 SBS 回放输入。

**为什么不提交：** gitignore 已覆盖；含绝对路径库存或注入密钥风险。

**负责人能看到什么：** summary_only。

## 4. 数据流与缺失环节

| 输入资产 ID | 转换代码/命令 | 输出资产 ID | 可重建性 | 证据/未知项 |
|---|---|---|---|---|
| A-EGSI-T1-CATALOG | R01 登记（抽样 24 / catalog 300） | A-R01-CANDIDATES | 输出已跟踪；catalog 已 profile | 不是 1:1 全量导出 |
| A-R01-CANDIDATES | `src/sbs/static_check.py` classify/build_actor_view | A-R01-READINESS, A-R01-ACTOR-PACKS | builder 已跟踪；源码缓存未知 | 仅 2 个 actor 包 |
| （独立） | unknown | A-R01-EVALUATOR | not_rebuildable_yet | 值未导出 |
| A-R01-FIXTURES | `python -m sbs replay --config configs/r01_smoke.json --out artifacts/r01_smoke` | A-R01-SMOKE | 已跟踪 fixtures+代码 | 本轮未重跑；X05 哈希一致 |
| A-R01-SMOKE | 复制 provenance | `reports/rounds/R01/run_manifest.json` | 已跟踪 | 与 gitignored 本地 manifest 字段一致 |
| A-EGSI-WORK-CACHE | unknown / legacy | （无 SBS 输出） | 不需要 | unverified_legacy_result |

## 5. 数字交叉核对

| 主张 | 实际依据 | 核对结果 | 影响/下一动作 |
|---|---|---|---|
| candidate_pairs=24 | `sbs.registry.count_inventory` ← `metadata/r01_candidates.jsonl` | 与 R01 status.json 一致 | 无改写 |
| real_ready_pairs=2 | readiness `ready=yes` 行数，且 actor 包存在 | X02 passed | 保持 |
| human_verified_pairs=0 | `human_verified_count`；无真人记录 | X06 passed | 禁止自报 |
| project_families=24 | unique `project_family` | 与 R01 一致 | 无 |
| fixture_cases=4 | `fixtures/r01` 子目录 | 与 R01 一致；不计入 real ready | 无 |
| catalog 记录数 | `profile_file(data/catalog/cases.jsonl)` complete 300 | 与 R01 的 24 对不一致（抽样） | 不改写 R01；24 不是全量 |
| 真实模型运行 | run_manifest `model_calls=0` `mode=fixture_replay` | 无真实模型运行 | 本轮不调用模型 |

## 6. 需要负责人决定的事项

1. **Catalog 300 vs registry 24：** catalog 已通过 `data/` 别名 profile。是否在 R02 扩大登记集，还是继续只用 24 个 `dev_pilot` 对？远程仍看不到行正文。
2. **Logic ready 仍为 0：** 与 R01 相同。本补充不开始义务标注或 frozen-model pilot。是否授权真正的 R02 研究仍待决定。
3. **远程正文审阅：** actor 摘录与 evaluator 答案均 `content_not_remotely_reviewed`。需要负责人实际阅读后才能提高可见性；执行端不会设置 `content_reviewed_remotely` 或 `human_verified`。

## 7. 可见性声明

本摘要由本地执行端整理。目录、哈希和结构检查不等于代码语义、标签或许可得到独立验证。尚未获负责人远程内容审阅的资产：A-EGSI-T1-CATALOG 行正文、`data/raw/` 源码树、A-R01-ACTOR-PACKS 正文、A-R01-EVALUATOR 答案、A-EGSI-WORK-CACHE、A-IGNORED-LOCAL-TOOLING 文件内容。Fixture 材料可跟踪但只是 synthetic_example。`reports/latest.json` 的 `round_id` 保持 `R01`。
