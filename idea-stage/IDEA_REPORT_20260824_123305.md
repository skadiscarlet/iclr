# Research Idea Report

**Direction**：Evidence-Guided Security Investigation for Code Auditing Agents  
**Generated**：2026-08-24  
**Ideas evaluated**：11 generated → 11 passed objective feasibility gate → 5 mechanically consolidated → 3 core candidates → 0 piloted → 2 unconditional recommendations  
**完整设计**：`EVIDENCE_GUIDED_AUDIT_DESIGN.md`

## Landscape Summary

仓库级 LLM 代码审计已明显从单函数分类转向按需探索、数据流记忆和验证。[RepoAudit](https://arxiv.org/abs/2501.18160) 使用 demand-driven 路径探索和 validator 缓解上下文与幻觉问题；[JitVul](https://arxiv.org/abs/2503.03586) 表明 interprocedural ReAct 优于单点 LLM，但仍有误判 guard 和不一致问题；[VulnGym](https://arxiv.org/abs/2608.02001) 进一步把仓库级任务拆成 localization、critical operation 和 vulnerability trace，为过程评测提供了细粒度标注。

“证据图 + 假设验证”已不是空白。[Hound](https://github.com/scabench-org/hound) 已实现 graph-driven belief/hypothesis 与 strategic planning；[VulAgent](https://arxiv.org/abs/2509.11523) 明确采用 hypothesis-validation multi-agent；[VulnAgent-R2](https://arxiv.org/abs/2603.13384) 已覆盖 evidence calibration、counterfactual reweighting、build-aware verification 和 cost-risk scheduling。因此，原始文档中的 Evidence Graph、Hypothesis、Unknown 和多 Agent 分工应定位为系统基础，而非单独的新颖性。

Agentic RL 方面，[Agent-as-Tool](https://arxiv.org/abs/2507.01489) 和 GLIDER 说明分层策略有助于解耦推理与工具；VerlTool、Similar、ReVeal 等工作分别推进异步多轮 tool-use RL、step-wise reward 和 turn-level verification credit。这些近邻把创新门槛推到更严格的位置：必须证明 security-specific proof obligation、typed transition、合法动作、停止/回溯和可验证 reward 真正改善独立终态，而不是把现成 RL 算法堆在一个新工作流上。

结构性空缺是：现有系统多以自然语言 planner、固定流程或启发式调度决定下一步；尚缺一套把审计状态转化为可执行 transition contract，并在相同候选、工具和预算下专门学习 `next investigation action` 的完整方案。最有价值的问题不是“模型是否认为代码有漏洞”，而是“当前证据缺少哪项证明，哪种调查动作最值得执行，以及何时停止、回溯或分支”。

## Recommended Ideas (ranked)

### Idea 1：Executable Typed Audit Automaton

- **Method (what we actually do)**：1) 将 Observation、Fact、Derived Claim、Hypothesis、Unknown、Proof State 和 Budget 分型；2) 为每个 primitive 定义 precondition、effect、failure effect、cost 和 idempotency；3) 在执行前编译 hard legality mask；4) 用事件溯源实现 branch/backtrack/stop，并以 proof certificate 定义终态。
- **Hypothesis**：机器可检查的 transition/effect/terminal semantics 能减少事实污染、非法动作、重复调查和过早停止，而不显著降低漏洞发现率。
- **Minimum experiment**：自由 ReAct、JSON DSL、post-hoc validator、typed hard mask、mask+learned control 的五组对照。
- **Expected outcome**：Valid Action ≥95%，重复/无效调用下降 ≥25%，verified finding rate 下降不超过 2pp；否则设计被证伪或需要放松 hard mask。
- **Novelty**：7.5/10 — 最近工作为 Hound、RepoAudit、VulAgent；差异在 executable transition contract、pre-execution semantic legality 和终态证明语义。
- **Feasibility**：LOW；3–4 周实现，主要为 CPU/工具 replay。
- **Risk**：LOW/MEDIUM；类型系统可能过重，mask 可能固化静态分析盲区。
- **Contribution type**：method + system + diagnostic。
- **Pilot result**：SKIPPED / NEEDS_PILOT；本地没有 replay benchmark。
- **Reviewer's likely objection**：只是 workflow engine + JSON schema + action mask 的工程包装。
- **Why we should do this**：它是后续 RL 的可重复环境，也是最先能被小规模实验直接证伪的核心抽象。

### Idea 2：Proof-Obligation-Conditioned Hierarchical Selector

- **Method (what we actually do)**：1) 高层选择 hypothesis 与缺失 proof obligation；2) 中层选择 30 个 typed primitive 和目标实体；3) 低层依据 capability/cost/reliability 路由工具；4) 显式学习 branch/backtrack/terminate。
- **Hypothesis**：`Hypothesis → Obligation → Primitive → Entity → Tool/Control` 的分解比 flat action policy 更易学习，也更能迁移到未见仓库和工具组合。
- **Minimum experiment**：在同候选集上比较 flat raw、hierarchical raw、flat role、hierarchical role、proof-obligation greedy 和 matched-capacity LLM ranker。
- **Expected outcome**：未见仓库 verified rate +10pp，或同等 verified rate 下成本 -20%；Candidate Oracle Recall 必须单独报告。
- **Novelty**：8/10 — 通用层级 RL 已存在；本设计把 option 绑定到可验证漏洞证明义务，并以 security-role entity pointer 实现跨仓库动作价值迁移。
- **Feasibility**：MEDIUM；离线 ranking 4–6 周，完整 RL 6–10 周。
- **Risk**：HIGH；候选召回、错误 obligation、角色抽象和参数量可能解释全部收益。
- **Contribution type**：method。
- **Pilot result**：SKIPPED / NEEDS_PILOT。
- **Reviewer's likely objection**：普通 factorized policy，加上人工安全规则后自然变强，未证明 RL 的必要性。
- **Why we should do this**：这是上限最高、最能回答“下一步调查什么”的核心学习贡献。

### Idea 3：Verifier-Grounded Counterfactual Credit

- **Method (what we actually do)**：1) 仅奖励 verifier 接受的 proof-obligation delta；2) 在同一 pinned state 执行多个 legal candidate；3) 为每个候选运行相同 k-step continuation；4) 用 listwise ranking、IQL/CQL 和条件式在线 RL 学习 Q。
- **Hypothesis**：可验证的 proof progress 和 Branch Replay 可缓解长轨迹 credit assignment，同时减少 reward hacking 与 offline action confounding。
- **Minimum experiment**：terminal-only、LLM judge、checklist、verified potential、verified potential+Branch Replay。
- **Expected outcome**：`Verified Finding Rate@20` 相对提升 ≥15%，patched hard negative 误报不增，reward 与 independent outcome 相关性提高。
- **Novelty**：6.5/10 — step reward、counterfactual 和 offline-to-online RL 均有近邻；研究性取决于 verifier-grounded credit 是否更接近真实终态。
- **Feasibility**：MEDIUM；分支 replay 与 verifier 成本较高。
- **Risk**：MEDIUM/HIGH；可能只学会完成易验证证书。
- **Contribution type**：training method。
- **Pilot result**：SKIPPED / NEEDS_PILOT。
- **Reviewer's likely objection**：Potential reward、IQL/CQL、PPO/GRPO 的组合，缺少独立算法贡献。
- **Why we should do this**：只有在 Pilot 2 成功后才升级为第三项核心贡献；失败时保留更简单的 offline ranker。

## Integrated Supporting Ideas

| Idea | 处理 |
|---|---|
| 状态契约 legality mask | 与 Idea 1 合并，区分 hard mask 与 soft preference |
| 可学习 branch/backtrack/stop | 与 Idea 1/2 合并，设置 heuristic、beam 与 oracle 对照 |
| Investigation curriculum | 作为训练协议，不单列主贡献 |
| Security-role state abstraction | 作为 Idea 2 的跨仓库泛化模块 |
| Replayable evidence certificate | 作为基础设施和主指标可信来源 |
| Tool-capability conditioned routing | 作为 Idea 2 的低层策略 |
| Secure Contrast | 作为 `compare_peer` primitive 和消融 |

## Eliminated / Downgraded Ideas

| Idea | Reason eliminated or downgraded |
|---|---|
| Evidence/Hypothesis Graph 作为主创新 | Hound、VulAgent、VulnAgent-R2 已明显覆盖 |
| 自由 shell/tool action RL | 粒度不一致、不可学习、奖励难对齐 |
| Flat vulnerability probability value | 退化为分类，不能回答 next investigation |
| 端到端在线 RL from scratch | 当前数据与 verifier 环境不足，预计超过一周有效 GPU/工具时间 |
| 多 Agent 数量作为贡献 | 逻辑角色可共享模型，Agent 数量不产生方法新颖性 |
| 普通 verifier/build/PoC 作为 headline | RepoAudit、SEC-bench、VulnAgent-R2 已有强近邻 |

## Pilot Experiment Results

| Idea | GPU | Time | Key Metric | Signal |
|---|---|---:|---|---|
| Typed Automaton | RTX 5070 Laptop 8GB available | not run | Valid Action / Verified Rate | NEEDS_PILOT：缺本地 replay states |
| Verified Credit | RTX 5070 Laptop 8GB available | not run | Verified Finding Rate@20 | NEEDS_PILOT：缺 verified trajectories/verifier env |
| Cross-Repo Hierarchy | RTX 5070 Laptop 8GB available | not run | unseen-repo verified rate | NEEDS_PILOT：需 repository-disjoint dataset |

本轮任务是设计转换，且环境初始化、数据生成与基线搭建预计超过每项 2 小时，因此没有启动虚构或不可比较的 pilot。

## Suggested Execution Order

1. 先实现 typed state、30 primitive、legality mask、event log 和 certificate；
2. 建立 500–1000 个保存状态，完成 Pilot 1；
3. 采集 Branch Replay，训练 flat 与 hierarchical next-action ranker；
4. 只有 Candidate Oracle Recall 足够高后再解释 selector 性能；
5. 先做 Verified Credit 的奖励相关性 pilot，再决定是否投入在线 PPO/GRPO；
6. 最后扩展到 repository/family/time/tool-shift 端到端评测。

## Next Steps

- [ ] 实现 `AUDIT_AUTOMATON.yaml` 的状态与 transition tests；
- [ ] 用 `ACTION_DSL.schema.json` 生成 30 个 primitive registry；
- [ ] 从 paired vulnerable/fixed repositories 构造保存状态；
- [ ] 预注册 Pilot 1–3 的成功与证伪阈值；
- [ ] 固定 backbone、工具、候选集和预算，避免把工具差异误归因于 policy；
- [ ] 在结果成立后再组织论文贡献，避免提前声称 Evidence/Hypothesis Graph 新颖。

