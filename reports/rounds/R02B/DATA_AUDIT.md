# R02B 数据审计

> 定点读取 `data/` 根符号链接后的 `catalog/cases.jsonl` 与 tracked `metadata/r01_candidates.jsonl`。未跟随嵌套链接。未读取无关 execute-only/signer/launcher。完整 catalog 行值不提交。

## 口径

| 字段 | 值 | 来源 |
|---|---|---|
| catalog_records | 300 | `tools/r02b_catalog_probe.py` 完整读取；`catalog_sha256=sha256:295bc9751161b4d04af1920bb464d94eb6369790936496394306bb60a7019455` |
| registered_candidate_pairs | 24 | tracked registry |
| legacy_ready_flag_pairs | 2 | `metadata/r01_readiness.csv` `ready=yes`；历史字段，不作为 `complete_version_pairs` |
| single_version_actor_packages | 0 | R02B `count_complete_version_pairs` |
| version_bound_actor_instances | 8 | R02B actor 根；`instance_id+revision+generation` |
| complete_version_pairs | 4 | 两侧 version manifest 存在、绑定、可读且 body 哈希不同 |
| human_verified_pairs | 0 | agent 不得自报 |
| project_name_count | 24 | registry `project_family` 字符串数 |
| independent_group_count | null | 未做独立同源去重 |
| catalog_profile_status | complete | 探针 `catalog_complete=true` |
| full_workspace_scan_status | partial_by_design | 不扫描 `.work` / 受限脚本 |
| ignored_protected_tools | excluded_nonblocking | 三个 execute-only 文件未读 |

匹配字段仅为 `case_id`（与 registry `local_catalog_key`）。24 个登记对象均为 `unique_match`。

## 24 个登记对象

每行：唯一 catalog 匹配、两 revision 是否可定位、两侧源码是否独立存在、许可指针、缓存是否在钉扎 data 根内、引用路径类型。许可不做法律结论；不知道记 unknown。

详见 `data_audit.json` 的 `registered_objects`。摘要：

- 24/24 unique catalog match；commits 与 registry 一致。
- catalog 映射的 bare git cache 均在 `cache/git` 前缀下、位于钉扎根内。
- 22/24 在 cited_path 上两侧 blob 可读且内容哈希不同。
- `r01-pair-20`：citation_range_missing。
- `r01-pair-24`：fixed 侧 cited blob 不存在（`single_version_available`）。
- 引用类型：多数 `java_implementation`；`r01-pair-03` release_notes；`r01-pair-06`/`r01-pair-10` build_file；`r01-pair-24` other。
- 许可：`license_file_not_found` 或 unclassified 记 `unknown`；`detected_from_pinned_revision` 记 pointer_present_not_legal_conclusion。

## R02B actor 材料

新目录 `local_data/r02b/`，不覆写 R01 包。selection：`r01-pair-01`、`r01-pair-12`（conventional）与 `r01-pair-13`、`r01-pair-15`（logic drafts，obligation 仍为 generic family template，不合格为语义样本）。`gold_assisted_context=true`，`task_scope=given_location_frozen_evidence`。Actor 无 CVE/gold/patch/pair-role。`source_revision=None` 不能 version-bound ready。

## 限制

`raw_content_not_remotely_reviewed`。独立项目组未核验。逻辑草案义务依据仍 generic，不得改名凑配额。
