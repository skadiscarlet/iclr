# R02B 任务总结（模板，不是完成记录）

## 实际版本与任务状态

实际分支、已复核基线、implementation SHA、collection SHA、执行时间。
分别填写engineering/data/model_run/human_annotation/delivery/review；不知道就未知。

## 这次改变了什么

逐项对照B00—B06：输入、实际代码/命令、产物路径、观察结果、剩余问题。
没有做的不要写成完成。列G0各检查，特别指出最终prompt的正文对齐。

## 真正的数据量

catalog记录、候选pair、旧ready标志、独立版本instance、完整pair、逻辑草案、真人核验。
解释各项计数来源和未知值；不能用文件数或项目字符串数量替代数据量。

## 模型与运行

真实model/revision、权重与tokenizer哈希、dtype/device、token与时延、attempts、episode数。
未运行说明具体阻塞。没有human review时语义指标null；已有raw响应不等于准确率已评估。

## 本地未提交内容

读 `reports/LOCAL_ASSETS.md` 能理解哪些内容？有哪些原始内容负责人仍不能看到？
给生成命令、配置与内容hash，不只列目录。

## 失败与下一步依据

至少一个失败/未决/不满足前置条件的真实案例，或明确本轮未出现。
说明数据、工程、模型能力和语义核验的不同瓶颈，不自行启动R03。

## Git交接

A实现、B报告、C回执的实际SHA与核验。旧R01/R02A历史是否保持。
