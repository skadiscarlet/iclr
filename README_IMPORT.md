# R02A — 给本地编程 agent 的执行细化与资产交接包

这是 R02 的补充，不替换已下发的 R02 研究计划，也不重跑已完成实验。没有替本地工作区扫描数据或修改远程 GitHub。本包只提供任务书、规范、只读工具和模板。

## 导入并执行

按相对路径合并到目标仓库；同名文件先比较，不覆盖 WIP。先确认实际 data 所在工作区，防止独立 worktree 没有 gitignored 数据而被误判为空。

```text
/goal 执行 plans/rounds/R02A_EXECUTOR_AND_LOCAL_ASSET_HANDOFF.md。先读取 plans/EXECUTION_CONTRACT.md。按步骤清点实际工作区中未提交的 data、local_data、artifacts 和其他关键材料；运行只读提取器，生成 reports/LOCAL_ASSETS.md、机器索引、交叉检查和当轮总结。原始 data 不整体上传，不重跑已完成的 R02 实验，不调用模型或训练。将可发布的脚本、报告和总结提交到 R02 任务分支，实际推送并核对远程 SHA。
```

## 主要文件

- `plans/EXECUTION_CONTRACT.md`：后续每轮读取的执行约定。
- `plans/rounds/R02A_EXECUTOR_AND_LOCAL_ASSET_HANDOFF.md`：逐步任务、输入输出、检查、失败处理、Git 交接。
- `tools/local_asset_handoff.py`：标准库、无模型/网络调用的本地元数据提取器。
- `tests/local_asset_handoff/test_inventory.py`：只使用临时自建材料的工具测试。
- `templates/`：报告和机器索引模板；不是实际本地数据结果。
- `validation/`：本交付环境中的工具自测日志；不是对用户仓库或数据的验证。

本地原始扫描结果留在 `artifacts/local_asset_scan/`。只有经过范围、隐私、许可和盲测边界检查的摘要进入公开 reports。模式匹配跳过常见敏感路径，不构成完整秘密检测保证。
