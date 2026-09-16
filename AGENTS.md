# 项目级 Agent 指令

## 当前阶段

`CURRENT_PHASE: prototype_development_and_experiment`

项目当前处于**原型开发 / 实验阶段**。现阶段的首要目标是完成可运行、可测试、可重放的完整工程实现，并获得能够决定论文主张是否成立的实验结果。

## 阶段化参考规则

### 原型开发 / 实验阶段（当前）

处理架构、代码、接口、Schema、Agent 行为、审计自动机、训练环境、数据生成、reward、测试和评测任务时，按以下优先级参考：

1. `idea-stage/EVIDENCE_GUIDED_AUDIT_DESIGN.md`：完整工程实现与端到端工作流；
2. `idea-stage/ACTION_DSL.schema.json`：Action DSL、primitive 和字段约束；
3. `idea-stage/AUDIT_AUTOMATON.yaml`：自动机状态、转移、不变量和终止语义；
4. `idea-stage/TRAINING_SPEC.yaml`：数据、reward、训练阶段、课程和评测配置；
5. `idea-stage/IDEA_REPORT.md`：idea 排名、相关工作与新颖性风险。

当前阶段不得为了迎合预设论文叙事而隐藏失败结果、跳过基线、放松验证器，或把尚未完成的组件描述为已实现。实现细节与本文档不一致时，以可执行规范和已验证实验状态为准，并记录差异。

### 论文阶段（后续）

只有在用户明确表示“进入论文阶段 / 开始论文写作 / 组织投稿”，或显式修改 `CURRENT_PHASE` 后，才将以下文档作为论文主线的首要参考：

- `paper-stage/ICLR_PAPER_NARRATIVE.md`

论文阶段使用该文档组织研究问题、核心叙事、贡献边界、主张、实验论证和论文结构；工程文档仍用于核对实现事实，但不把模块数量、工作流复杂度或普通工程机制自动写成论文创新。

## 文档职责边界

- **工程文档回答**：系统具体如何实现、运行、训练、测试和复现。
- **论文叙事回答**：为什么问题重要、核心学习问题是什么、哪些主张值得提出、需要什么证据支持。
- **实验记录回答**：哪些主张已经得到支持、被证伪或仍不确定。

不得用论文叙事覆盖工程事实，也不得用工程模块堆叠代替论文贡献。

## 同步原则

1. 原型阶段新增或修改实现时，优先更新对应工程规范与测试；只在概念边界发生变化时同步论文叙事。
2. 实验结果出现后，保留成功、失败和负结果，不提前将结果占位符改成确定性结论。
3. 进入论文阶段后，从已验证结果反推最终 Claims、贡献顺序和摘要数字。
4. `paper-stage/ICLR_PAPER_NARRATIVE.md` 是论文叙事固定入口；带时间戳文件是历史版本，不直接编辑。
5. `idea-stage/` 是原型和实验规范入口；`paper-stage/` 是论文级叙事入口，二者不得混作同一职责。

## 当前执行默认值

若任务同时包含工程实现和论文表达，当前阶段先完成并验证工程实现，再把得到的事实以“支持 / 不支持 / 尚不确定”同步到论文叙事；不得反向依据论文期望篡改实验判定。

## NAACL 2027 / SBS 并行研究轨（R01+）

本仓库另有 NAACL 2027 方向：SBS（具体约束失效假设 + 证据状态）。该方向**不替换**上文 EGSI / ICLR 原型规则。

R01 范围：仓库盘点、可回退整理、actor/evaluator 数据隔离、离线 fixture 回放。R01 不训练 Q/V，不调用模型 API，不计算检测 accuracy/F1，不声称新 CVE 发现。

执行时额外遵守：

1. 规范入口：`plans/rounds/R01.md`（本轮任务书）、`plans/ROADMAP_NAACL2027.md`、`docs/r01_research_contract.md`、`docs/r01_data_protocol.md`。
2. Actor 可见对象不得包含 CVE、gold label、patch 或修复配对；审查运行器不得读取 evaluator 根或 actor root 之外的路径。
3. R01 接触过的真实样本一律 `split=dev_pilot`；`human_verified` 不得由 agent 自报。
4. `review_status=accepted` 只能由后续负责人审阅后变更。
5. 不得执行 `git reset --hard`、`git clean -fd`、`git push --force` 或改写公共历史。
