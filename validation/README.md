# 交付工具自测范围

此目录记录的是本交付环境中的工具测试，不是用户仓库验收或真实数据核验。

- 标准库 unittest：16 项通过。
- CLI：仅在临时自建 synthetic metadata 工作区运行。
- 没有读取用户本地 data，没有执行第三方代码，没有模型或网络调用。
- 常见敏感路径过滤和受限字段导出不构成完整秘密检测保证；发布前仍须审核。

源文件：`tools/local_asset_handoff.py`、`tests/local_asset_handoff/test_inventory.py`。
