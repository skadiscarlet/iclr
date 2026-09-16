# 从程序路径遍历到证据驱动的安全调查

**英文暂定题目**：*From Program Traversal to Evidence-Guided Security Investigation: Learning What to Audit Next*  
**方法代号**：EGSI（Evidence-Guided Security Investigation）  
**目标会议**：ICLR  
**文档角色**：论文级叙事源（paper narrative source）  
**状态**：研究假设与拟议主张；实验结果产生前，不将结果占位符写成已验证结论  
**生成日期**：2026-08-24

> 本文档回答“论文为什么成立、核心学习问题是什么、应当用什么证据支持主张”。它不承担接口、状态机、Schema、工具适配和部署参数等工程规范职责。当前原型开发与实验阶段应优先参考 `idea-stage/EVIDENCE_GUIDED_AUDIT_DESIGN.md` 及其机器可读规范。

## 1. 一句话论文叙事

现有代码审计 Agent 往往把漏洞发现近似为代码阅读、程序图遍历或自然语言工具调用；我们主张，真正的核心问题是：**在大型代码库、部分可观测证据和有限审计预算下，学习选择哪一个安全调查操作，能够最快把一个漏洞假设推进到可验证的证实或证伪。**

## 2. 核心研究问题

给定一个仓库、初始审计入口、可调用的程序分析工具和固定预算，Agent 在任意时刻只掌握局部事实。它需要连续回答四个问题：

1. 当前最重要的漏洞假设是什么？
2. 该假设距离证实或证伪还缺少哪项 proof obligation？
3. 哪个可执行审计动作最可能消除这一关键未知量？
4. 何时继续、切换分支、回溯、拒绝结论或终止？

因此，论文研究对象不是静态的“代码是否有漏洞”分类，而是动态的、预算敏感的 **next-investigation decision**。

## 3. 为什么现有问题表述不够

### 3.1 程序路径不等于审计决策

CFG、CG、DDG 或 PDG 描述程序结构，却不能直接表达审计者真正关心的问题，例如：

- 调用身份是否在跨进程边界后发生变化；
- 当前路径上是否存在有效权限检查；
- 某字段是否仍受外部输入控制；
- 同类安全实现是否揭示了缺失的不变量；
- 现有证据是否足以支持真实可达性、影响和漏洞结论。

程序图应当成为 Agent 可查询的外部世界模型，而不是学习策略的动作空间本身。

### 3.2 自由工具调用缺少稳定的学习单位

当 Action 是任意自然语言、Shell 命令或代码阅读请求时，同一调查意图具有大量表面形式，导致动作稀疏、轨迹难以比较、奖励难以归因。我们将动作规范化为中等粒度、带参数的审计 primitive，使策略学习的是安全调查语义，而不是命令字符串。

### 3.3 漏洞置信度不等于调查价值

令价值函数直接预测“当前代码有漏洞的概率”，会退化为漏洞分类。论文需要学习的是：在当前证据状态下执行某项调查，能否以较低成本提高最终独立验证成功率。

## 4. 概念转变：漏洞审计是一种证据获取策略

我们把一次仓库级审计形式化为近似 belief-state Semi-MDP：

\[
\mathcal{M}=(\mathcal{S},\mathcal{A},T,R,\gamma,\mathcal{B}).
\]

### 4.1 结构化调查状态

\[
s_t=(C_t,F_t,H_t,E_t,U_t,B_t),
\]

其中：

- \(C_t\)：当前调查焦点，如入口点、符号、组件和边界；
- \(F_t\)：由工具确认的程序事实；
- \(H_t\)：待验证的漏洞假设及其支持/反对证据；
- \(E_t\)：具有 provenance 的类型化证据图；
- \(U_t\)：尚未解决的关键未知量或 proof obligations；
- \(B_t\)：剩余 token、工具调用、时间和分析预算。

该状态不追求复制整个仓库，而是压缩“当前知道什么、还缺什么、哪些结论可被追溯”。

### 4.2 参数化安全审计动作

动作不是程序图边，而是可执行的审计操作：

\[
a_t=(g_t,o_t,p_t,x_t,\tau_t),
\]

其中 \(g_t\) 是调查目标，\(o_t\) 是待解决的 proof obligation，\(p_t\) 是审计 primitive，\(x_t\) 是目标实体，\(\tau_t\) 是工具或控制动作。典型目标包括：

- `VERIFY_REACHABILITY`
- `VERIFY_ATTACKER_CONTROL`
- `VERIFY_SECURITY_CHECK`
- `VERIFY_SINK_SEMANTICS`
- `VERIFY_IMPACT`
- `EXPLORE_ALTERNATIVE_PATH`

典型 primitive 包括调用关系、前向/后向数据流、别名、字段流、Guard、身份、权限、同类实现对比、假设生成与终局验证。

### 4.3 工具落地的状态转移

LLM 可以提出“查什么”，但事实更新必须尽量来自静态分析、代码检索、类型层级、构建/测试和独立验证器。一次动作执行生成结构化 observation、证据增量、成本和工具回执，再由状态更新器形成 \(s_{t+1}\)。

这一分工减少让 LLM 同时猜测调用链、数据流、权限语义和漏洞结论造成的自洽幻觉。

## 5. 方法叙事

### 5.1 候选生成：把开放式推理约束成可比较决策

语义 Planner 根据当前状态提出少量候选调查目标与动作参数；Candidate Compiler 将其规范化为类型化 Action DSL，补全实体引用、工具能力与成本，并在执行前应用合法性约束。候选召回率必须单独测量，避免把“没有提出正确动作”误算为 selector 的排序失败。

### 5.2 Proof-obligation-conditioned 层次策略

策略按以下层次进行选择：

\[
H \rightarrow O \rightarrow P \rightarrow X \rightarrow Tool/Control.
\]

高层决定当前应推进哪个漏洞假设及缺失证明义务；中层选择审计 primitive 和目标实体；低层根据工具能力、可靠性和成本完成路由，同时显式建模 branch、backtrack、reject、abstain 和 terminate。

价值函数的目标是：

\[
Q(s_t,a_t)=\mathbb{E}\left[r_t+\gamma^{\Delta t}V(s_{t+1})\mid s_t,a_t\right],
\]

其中最终效用由独立验证结论、错误确认/拒绝以及调查成本共同决定。

### 5.3 Verifier-grounded progress

中间奖励只认可可重放的证据增量，例如解决关键 Unknown、闭合 proof obligation、发现有效反证或消除矛盾；不奖励模型自报置信度、推理文本长度、读取代码数量或未经验证的 checklist 完成度。

这使训练信号与“最终能否独立验证漏洞”保持方向一致，并为假阳性施加强约束。

### 5.4 Counterfactual Branch Replay

单条成功轨迹不能说明当时的动作是否优于其他候选。我们在同一 pinned state 上执行多个合法候选，并给予相同的短期 continuation 预算，记录：

- verified proof delta；
- critical unknown delta；
- \(k\)-step return；
- 归一化成本；
- 若到达终态时的独立验证结果。

这些同状态分支形成 listwise ranking 和保守离线 RL 的反事实监督，缓解长轨迹信用分配与行为策略混杂。

## 6. 论文的主张结构

以下均为**待实验验证的候选主张**。

### Claim 1：学习语义调查策略优于路径遍历和自由工具调用

在相同 backbone、工具集合、候选预算和总成本下，EGSI 应提高 `Verified Finding Rate@Budget`，或在相同验证成功率下降低工具调用与时间成本。

### Claim 2：显式 Evidence/Unknown/Proof 状态是有效学习抽象

相较原始代码上下文、扁平历史摘要或仅程序图状态，结构化调查状态应减少重复调查、非法动作和过早终止，并提高跨仓库迁移能力。

### Claim 3：Proof-obligation 层次分解改善泛化

相较 flat primitive 分类或 LLM 直接排序，`Hypothesis → Obligation → Primitive → Entity` 分解应在 repository-disjoint、vulnerability-family-held-out 和 tool-shift 条件下保持更高的动作价值估计与终局性能。

### Claim 4：Verifier-grounded Branch Replay 改善信用分配

相较 terminal-only reward、LLM judge reward 和单一成功轨迹模仿，同状态反事实分支应提高过程奖励与独立终态的相关性，并降低 patched hard negatives 上的错误确认率。

若 Claim 3 或 Claim 4 未获得稳定证据，应将其降级为实现或分析，不保留为 headline contribution。

## 7. 训练叙事

训练数据以 vulnerable/fixed commit pair、可复现安全任务、人工审计轨迹、静态分析 oracle、patched/secure hard negatives 和受控变异漏洞为基础。公开漏洞描述与利用链只提供任务入口、终态或弱监督，不直接视为完整决策轨迹。

训练按以下顺序推进：

1. **环境与合同验证**：先确保 Action、状态转移、回执、证据 provenance 和终态证书可重放；
2. **SFT/Behavior Cloning**：学习状态规范化、proof obligation、动作因子化和实体指针；
3. **Value/Reward 预训练**：使用同状态候选比较、proof delta 和终态校准训练价值头；
4. **Conservative Offline RL**：以 BC warm start，使用 IQL/CQL 类目标限制分布外动作；
5. **DAgger/Failure Mining**：集中纠正过早停止、错误分支、重复查询、工具失败误读和 patched negative 假确认；
6. **条件式在线 RL**：只有 process reward 与独立终态显著相关后才启动，并保留 verifier write gate；
7. **课程与泛化**：从单文件单 Unknown 逐步扩展至跨过程、别名、动态分派、多假设和工具故障。

核心原则是：**LLM 模拟轨迹用于提出候选和冷启动，真实工具转移与独立验证结果用于决定学习标签。**

## 8. 实验叙事与研究问题

### RQ1：在固定预算下，是否更容易得到可验证漏洞？

比较自由 ReAct、程序图启发式、信息增益贪心、LLM 直接选择、flat learned policy、hierarchical policy 和完整 EGSI。主指标为：

- `Verified Finding Rate@Budget`
- `Verified Reject Rate`
- patched negative false-confirmation rate
- cost-to-verification 与 wall-clock

### RQ2：性能来自候选质量、状态抽象还是 selector？

固定候选集合分别测量 Candidate Oracle Recall、selector regret、Top-k next-action accuracy 和终局性能；用 raw code、history summary、evidence graph、evidence+unknown、完整 proof state 做状态消融。

### RQ3：层次策略是否带来跨分布泛化？

采用 repository-disjoint、project-family-disjoint、time-disjoint、vulnerability-family-held-out 和 tool-capability-shift 划分，比较 flat 与 hierarchical policy，并控制参数量和候选集合。

### RQ4：过程奖励是否真的预测终态？

比较 terminal-only、LLM judge、checklist、verified potential 和 verified potential + Branch Replay，报告 reward/outcome 相关性、校准、错误确认率及离线策略提升。

### RQ5：系统在哪些条件下失败？

按候选漏召回、工具能力不足、错误 obligation、证据污染、预算捕获、动态行为缺失和 verifier blind spot 分类，展示失败率及其对最终结论的影响。

## 9. 必要基线与公平比较合同

所有主比较必须固定：

- 相同语义 backbone 或明确报告模型差异；
- 相同工具集合与工具版本；
- 相同候选生成器，或单独报告候选召回；
- 相同 token、调用次数、分析单元和时间预算；
- 相同漏洞任务、终态验证器与隐藏信息规则；
- 补丁父子、fork、mirror、backport、AST clone 和共享依赖去重。

只有在这些条件下，收益才能被归因于调查策略，而不是更强工具、更多上下文或标签泄漏。

## 10. 新颖性边界

以下内容不单独作为论文创新：

- Evidence Graph 或 Hypothesis Graph；
- 多 Agent 角色数量；
- 普通 JSON Action Schema；
- 使用 CFG/CG/DDG/CodeQL；
- 常规 verifier、build 或 PoC；
- 将 PPO、GRPO、IQL 或 CQL 直接用于工具 Agent。

论文的新颖性应集中在它们如何共同形成一个**可学习且可证伪的安全调查决策问题**，尤其是：

1. proof-obligation-conditioned 的状态与动作抽象；
2. 在相同候选和预算下学习 next investigation value；
3. 由独立验证器与同状态反事实分支提供信用分配。

最近邻工作与持续更新的文献边界记录在 `idea-stage/IDEA_REPORT.md`；投稿前必须重新执行时间敏感的 novelty check。

## 11. 可证伪条件

出现以下任一结果时，应收缩或重写对应主张：

- 简单 information-gain greedy 与 learned policy 无显著差异；
- 候选 Oracle Recall 过低，selector 上限不足；
- typed state 的收益完全来自更多上下文或人工安全规则；
- hierarchy 在匹配参数量后没有跨仓库优势；
- process reward 与 independent terminal outcome 弱相关；
- Branch Replay 仅提高中间证书完成度，却不提高真实验证率；
- 在 patched/secure hard negatives 上假阳性显著上升；
- 训练/测试之间存在补丁、项目家族或代码克隆泄漏。

负结果也应保留，因为它们能够回答：漏洞审计中的 learned search 是否真的优于合理启发式，以及显式 proof state 是否是必要抽象。

## 12. 预期贡献表述

在实验支持的前提下，论文贡献可表述为：

1. **Problem**：提出预算约束的 evidence-guided security investigation，将仓库级漏洞发现形式化为 next-investigation decision，而非路径遍历或静态分类；
2. **Method**：提出 proof-obligation-conditioned hierarchical policy，在结构化证据状态上选择可执行审计操作、实体、工具和控制决策；
3. **Learning**：提出 verifier-grounded counterfactual branch training，从同状态候选执行结果学习调查价值；
4. **Evaluation**：建立过程与终局联合评测，在严格跨仓库和 hard-negative 条件下分离候选召回、策略排序、证据质量与最终漏洞验证。

最终论文只保留被实验明确支持的贡献。

## 13. 摘要叙事骨架

> Repository-level vulnerability discovery is often treated as program traversal or open-ended tool use. This view overlooks the central decision faced by an auditor: under partial evidence and a limited budget, what should be investigated next? We formulate vulnerability auditing as evidence-guided security investigation, where the state explicitly represents verified facts, hypotheses, proof obligations, provenance-linked evidence, and remaining budget, while actions are typed security-auditing operations executed by analysis tools. We introduce a proof-obligation-conditioned hierarchical policy that selects investigation goals, primitives, entities, and tools, and train it with verifier-grounded progress and counterfactual branch replay. On `[BENCHMARK_SUITE]`, under matched models, tools, and budgets, the method achieves `[RESULT_VERIFIED_RATE]` on verified finding rate and `[RESULT_COST]` on investigation cost, with gains persisting under `[GENERALIZATION_SPLITS]`. Analysis attributes the improvement to `[SUPPORTED_COMPONENTS]` and identifies `[FAILURE_BOUNDARY]` as the principal remaining limitation.

## 14. 论文结构建议

1. **Introduction**：从“读下一段代码”与“解决下一项安全未知量”的差异切入；
2. **Related Work**：仓库级漏洞 Agent、Agentic RL、程序分析与验证、主动信息获取；
3. **Problem Formulation**：belief state、proof obligations、typed actions、预算与终态；
4. **Method**：候选编译、层次 selector、状态转移与 verifier-grounded credit；
5. **Training Environment**：数据来源、Branch Replay、离线到在线训练与泄漏控制；
6. **Experiments**：RQ1–RQ5、公平比较、消融、泛化和失败分析；
7. **Limitations**：工具盲区、动态行为、标签完整性、计算成本和误用边界；
8. **Conclusion**：总结“学习调查策略”而不是“增加 Agent 数量”。

## 15. 与工程文档的职责边界

| 问题 | 首要参考文档 |
|---|---|
| 为什么值得研究、论文主线是什么 | 本文档 |
| 哪些是主张、需要什么实验支持 | 本文档 |
| 系统模块、状态机、Agent 角色和全流程 | `idea-stage/EVIDENCE_GUIDED_AUDIT_DESIGN.md` |
| Action 字段、primitive 与校验 | `idea-stage/ACTION_DSL.schema.json` |
| 自动机状态、不变量与转移 | `idea-stage/AUDIT_AUTOMATON.yaml` |
| 数据、reward、训练阶段和评测配置 | `idea-stage/TRAINING_SPEC.yaml` |
| idea 排名、近邻与新颖性风险 | `idea-stage/IDEA_REPORT.md` |

原型阶段的实现决策可以比本文档更具体；这些细节不自动升级为论文贡献。论文阶段应从实验结果反推最终主张，再更新本文档中的结果占位符、贡献顺序和失败边界。
