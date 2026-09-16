# Evidence-Guided Security Investigation：面向代码审计 Agent 的状态-动作空间设计

## 1. 核心动机

传统的程序分析式漏洞挖掘往往把搜索过程建模为程序图上的路径遍历，例如：

- 状态 \(S\)：当前路径中的代码或当前程序节点；
- 动作 \(A\)：CFG/CG 上的下一条边；
- 搜索过程：不断沿控制流、调用流或数据流扩展。

这种建模对于纯静态分析是自然的，但对于 **LLM 驱动的代码审计 Agent** 来说过于受限。

代码审计并不只是“决定下一条程序边走哪里”，更核心的问题是：

> 在当前已有证据下，下一步应该调查什么，才能以最低成本验证或否定一个潜在漏洞假设？

例如，在某个 IPC Handler 中看到：

```cpp
void HandleRequest(Request &req) {
    auto uid = req.GetUid();
    Process(uid, req.data);
}
```

如果动作空间仅仅来自 CFG，则 Agent 能选择的通常只有：

```text
HandleRequest -> GetUid
HandleRequest -> Process
```

但真正具有安全审计价值的下一步操作可能是：

```text
1. 判断 HandleRequest 是否可被外部进程调用
2. 反向追踪 req.GetUid() 的数据来源
3. 检查 Process() 内 uid 是否用于权限校验
4. 判断 req.data 是否流入危险 API
5. 判断 uid 在后续是否发生身份转换或覆盖
6. 查询类似 Handler 中是否存在权限校验
7. 查看 Process() 的 override / implementation
8. 基于当前证据生成潜在漏洞假设
```

因此，更合适的建模方式不是 **program-path traversal**，而是：

> **Evidence-Guided Security Investigation（证据驱动的安全调查）**

---

# 2. 整体建模

可以将代码审计 Agent 建模为带预算约束的 POMDP / Belief-State MDP：

\[
\mathcal{M}=(S,A,T,R,\gamma,B)
\]

其中：

- \(S\)：当前审计状态；
- \(A\)：Agent 可执行的审计操作；
- \(T\)：执行动作后，通过程序分析工具或 LLM 获得新证据并更新状态；
- \(R\)：一次调查操作带来的审计收益；
- \(\gamma\)：折扣因子；
- \(B\)：Token、工具调用、时间或程序分析成本等预算。

核心变化在于：

\[
\boxed{
S \neq \text{当前程序路径}
}
\]

并且：

\[
\boxed{
A \neq \text{CFG 出边}
}
\]

而是：

\[
\boxed{
S=\text{当前调查所掌握的程序事实、证据、假设与未知项}
}
\]

\[
\boxed{
A=\text{参数化的安全审计操作集合}
}
\]

CFG、CG、DDG、PDG、Pointer Analysis、CodeQL 等程序分析结构不再直接构成 Agent 的动作空间，而是成为 **Agent 可以调用的外部世界模型和工具能力**。

---

# 3. 状态空间：从“当前代码”升级为 Investigation State

推荐将状态定义为：

\[
S_t=(C_t,F_t,H_t,E_t,U_t,B_t)
\]

其中分别表示：

- \(C_t\)：Current Focus，当前调查焦点；
- \(F_t\)：Program Facts，程序分析确认的确定性事实；
- \(H_t\)：Hypotheses，当前漏洞假设；
- \(E_t\)：Evidence Graph，累积证据图；
- \(U_t\)：Unknowns，尚未回答的关键安全问题；
- \(B_t\)：Budget，剩余调查预算。

---

## 3.1 Current Focus：当前调查焦点

表示当前 Agent 正在关注的实体，例如：

```yaml
function: HandleRequest
symbol: req.uid
component: AccountService
entrypoint: IPC interface
current_hypothesis: H1
```

Current Focus 的主要作用是避免整个 Repository 的上下文无限膨胀，使每一步决策都围绕当前调查目标展开。

---

## 3.2 Program Facts：程序事实

这一部分应尽可能由程序分析工具产生，而不是完全依赖 LLM 推测。

例如：

```yaml
caller:
  - IPCStub::OnRemoteRequest

callees:
  - GetUid
  - Process

dataflow:
  - req.uid -> uid
  - uid -> Process(arg0)

guards:
  - none_observed

external_control:
  req.data: attacker_controlled
```

程序事实可以来自：

- Call Graph；
- CFG / Dominator；
- Def-Use；
- Interprocedural Data Flow；
- Pointer / Alias Analysis；
- Type Hierarchy；
- CodeQL；
- Semgrep；
- clangd / LSP；
- AST；
- Repository Search。

这一层的基本原则是：

> **LLM 负责决定“查什么”，静态分析工具负责确认“事实是什么”。**

---

# 4. 漏洞假设 Hypothesis

代码审计不应是漫无目的地遍历程序图，而应围绕一个或多个安全假设推进。

定义：

\[
H_t=\{h_1,h_2,\dots,h_n\}
\]

例如：

```yaml
H1:
  type: authorization_bypass
  confidence: 0.62

  statement:
    externally supplied uid may reach privileged Process()

  supporting_evidence:
    - uid originates from IPC request
    - uid reaches Process(arg0)

  missing_evidence:
    - privilege semantics of Process()
    - upstream caller identity validation
    - whether target uid must match caller uid
```

整个漏洞挖掘过程可以理解为：

\[
Evidence
\rightarrow
Hypothesis
\rightarrow
Information\ Gathering
\rightarrow
Hypothesis\ Update
\]

因此，Agent 真正搜索的对象不是单纯的程序路径，而是：

\[
\boxed{
\text{Hypothesis Space}
}
\]

---

# 5. Evidence Graph：用结构化证据替代无限代码上下文

对于大型代码库，不应该持续将所有已访问代码原文放进 LLM Context。

更合理的方法是维护一个 **Evidence Graph**。

例如：

```text
External IPC
    |
    v
HandleRequest
    |
    | attacker-controlled
    v
req.uid
    |
    v
Process(uid)
    |
    | unknown authorization
    v
SensitiveOperation
```

节点可以表示：

- Function；
- Variable；
- Object；
- Field；
- Entry；
- Sink；
- Permission；
- Identity；
- Resource；
- Lifecycle Entity。

边可以表示：

```text
CALL
DATA_FLOW
CONTROL_DEP
ALIAS
FIELD_FLOW
IDENTITY_CHANGE
AUTH_GUARD
SANITIZE
LIFECYCLE
RESOURCE_OWNERSHIP
```

每条边最好带有来源信息：

```yaml
edge:
  type: DATA_FLOW
  source: req.uid
  target: Process.arg0
  confidence: confirmed
  provenance:
    tool: CodeQL
    location: service/account.cpp:123
```

这样 LLM 获取的是：

> 当前调查图 + 当前关键代码片段

而不是整个 Repository 的无差别代码。

---

# 6. Unknowns：显式维护“还不知道什么”

Unknowns 是整个方案中非常关键的一部分。

例如：

```yaml
U1:
  question: Is Process privileged?
  importance: high

U2:
  question: Is uid attacker-controlled?
  importance: resolved

U3:
  question: Is caller identity checked upstream?
  importance: critical

U4:
  question: Can the path be triggered remotely?
  importance: high
```

下一步动作选择实际上可以理解为：

\[
a_t=
\arg\max_a
\operatorname{ExpectedInformationGain}(a,U_t)
\]

也就是说：

> 优先执行最可能解决当前关键未知项的调查操作。

例如：

```text
InspectUnrelatedCaller(foo)
```

对于当前 Authorization Hypothesis 基本没有价值；

而：

```text
FindAuthorizationGuard(HandleRequest -> Process)
```

可以直接回答 U3，因此价值明显更高。

---

# 7. 动作空间：Agent Auditing Operations

动作建议定义为参数化 primitive：

\[
a=(op,target,args)
\]

而不是自由文本或程序图边。

例如：

```text
TraceCaller(foo)
TraceCallee(foo)
TraceDataFlow(x, direction=backward)
FindSource(x)
FindSink(x)
FindGuard(foo)
CheckSanitizer(x)
TrackAlias(x)
TrackField(obj.field)
ExpandTypeHierarchy(BaseClass)
InspectImplementation(interface)
InspectOverride(method)
SearchSiblingHandler(foo)
ComparePatch(function)
AskSemanticQuestion(region, question_type)
GenerateHypothesis(region)
ValidateHypothesis(h)
```

因此：

\[
A=
A_{structural}
\cup
A_{dataflow}
\cup
A_{security}
\cup
A_{semantic}
\cup
A_{investigation}
\]

---

# 8. 推荐的 Action Taxonomy

建议控制在约 15–30 个中等粒度 primitive，而不是允许 LLM 任意调用 shell。

## 8.1 Structural Actions

用于探索代码结构：

```text
FindCaller(function)
FindCallee(function)
FindReferences(symbol)
InspectImplementation(interface)
InspectOverride(method)
ExpandTypeHierarchy(class)
FindSiblingHandler(function)
```

---

## 8.2 Data-Flow Actions

用于确认数据流、别名和字段传播：

```text
TraceForward(value)
TraceBackward(value)
FindSource(value)
FindSink(value)
TrackAlias(value)
TrackField(object.field)
TraceInterproceduralFlow(value)
```

---

## 8.3 Security Actions

安全审计特化操作：

```text
FindGuard(path)
FindPermissionCheck(function)
TraceCallerIdentity(function)
FindSanitizer(value)
CheckAuthorizationRelation(subject, object)
CheckLifecycleConstraint(resource)
CheckOwnership(resource)
FindRateLimit(entry)
FindResourceRelease(resource)
```

---

## 8.4 Semantic Actions

由 LLM 或 LLM + 静态事实共同完成：

```text
ClassifyOperation(code)
InferSecurityInvariant(region)
ExplainSensitiveOperation(function)
IdentifyTrustBoundary(component)
InferResourceSemantics(object)
```

---

## 8.5 Investigation Actions

用于控制整个调查过程：

```text
GenerateHypothesis()
RankHypotheses()
TestHypothesis(h)
RejectHypothesis(h)
ValidateFinding(h)
SummarizeEvidence(h)
ExploreAlternativePath(h)
```

---

# 9. Action DSL

所有操作最好都统一成结构化格式，而不是直接输出自然语言。

例如：

```json
{
  "operation": "trace_dataflow",
  "target": "request.uid",
  "direction": "forward",
  "scope": "interprocedural",
  "goal": "determine whether attacker-controlled uid reaches privileged sink"
}
```

或：

```json
{
  "operation": "find_guard",
  "target": "Process",
  "guard_type": "authorization",
  "scope": "caller_chain"
}
```

这种 DSL 的好处包括：

1. 动作空间离散、可学习；
2. 工具执行可控；
3. 易于记录训练轨迹；
4. 易于比较不同策略；
5. 避免 Agent 退化成任意 shell 使用；
6. 可直接用于 Q-learning / policy model。

---

# 10. 为什么不能把 A 定义成“任意 Agent 操作”

理论上可以：

\[
A=\{\text{all possible agent actions}\}
\]

但实践中会带来严重问题。

例如 LLM 可能生成：

```text
grep ...
read_file ...
search ...
read 200 lines ...
search another keyword ...
```

这种 action representation：

- 粒度不一致；
- 语义高度稀疏；
- 几乎无法学习稳定 Q 值；
- Reward Assignment 困难；
- Tool Choice 与 Security Reasoning 强耦合。

因此更推荐：

> **固定的 Security Investigation Primitive + 参数化目标**

即：

\[
A=\{a_1(\theta),a_2(\theta),...,a_n(\theta)\}
\]

其中 \(n\) 保持较小。

---

# 11. Hierarchical Action Space

进一步可以把动作拆为两层：

\[
a=(a^{goal},a^{tool})
\]

第一层选择调查目标，第二层选择具体程序分析工具。

---

## 11.1 High-Level Investigation Goal

例如：

```text
VERIFY_REACHABILITY
VERIFY_ATTACKER_CONTROL
VERIFY_SECURITY_CHECK
VERIFY_SINK_SEMANTICS
VERIFY_IMPACT
VERIFY_LIFECYCLE
EXPLORE_ALTERNATIVE_PATH
COMPARE_SECURE_PATTERN
```

---

## 11.2 Low-Level Tool Action

例如：

```text
VERIFY_SECURITY_CHECK
        |
        +-- FindGuard
        +-- SearchCaller
        +-- TraceCallerIdentity
        +-- SearchSiblingImplementation
        +-- SearchPermissionCheck
```

这种分层很适合代码审计，因为高层语义目标和低层程序分析工具天然存在区别。

---

# 12. LLM 的职责

LLM 不应该承担所有工作。

不推荐：

```text
LLM:
理解代码
  ->
猜调用链
  ->
猜数据流
  ->
猜权限
  ->
判断漏洞
```

这种方式容易出现 Hallucination。

更合理的角色是：

### LLM 负责

- 识别当前安全语义；
- 生成漏洞假设；
- 找出关键未知项；
- 生成候选调查动作；
- 判断什么证据最值得获取；
- 根据事实更新 Hypothesis；
- 判断是否已经达到可验证漏洞状态。

### 静态分析工具负责

- Call Graph；
- CFG；
- Data Flow；
- Alias；
- Def-Use；
- Control Dependency；
- Type Hierarchy；
- Search；
- Program Location；
- Source/Sink Matching；
- Path Extraction。

---

# 13. 总体系统架构

```text
                +----------------+
                |   LLM Planner  |
                +--------+-------+
                         |
                  candidate actions
                         |
               +---------v---------+
               | Q / V Policy      |
               | or Search Policy  |
               +---------+---------+
                         |
                    selected action
                         |
       +-----------------v-------------------+
       |       Program Analysis Layer        |
       |                                     |
       | CFG / CG / DDG / PDG                |
       | Pointer / Alias                      |
       | Taint Analysis                       |
       | CodeQL / Semgrep                     |
       | LSP / Repository Search              |
       | Type Hierarchy / Git History         |
       +-----------------+-------------------+
                         |
                  structured facts
                         |
                +--------v--------+
                | State Updater   |
                +--------+--------+
                         |
                         v
                    S_{t+1}
```

其中 LLM 可以先产生：

```text
A_candidate =
{
  FindGuard(Process),
  TraceForward(req.uid),
  InspectCaller(HandleRequest),
  SearchSiblingHandler(HandleRequest),
  InspectSensitiveOperations(Process)
}
```

再由 Policy Layer 决定最值得执行的动作。

---

# 14. Q/V 的定义

不推荐：

\[
V(S)=P(\text{当前代码存在漏洞})
\]

因为这会让系统退化成 Vulnerability Classification。

推荐定义为：

\[
V(S)=
\mathbb{E}
[
\text{最终能够发现并验证漏洞的效用}
\mid S
]
\]

对应：

\[
Q(S,a)=
\mathbb{E}
[
R_t+\gamma V(S_{t+1})
]
\]

也就是说，Q 学习的是：

> 在当前审计证据下，执行某个调查操作到底值不值得。

---

# 15. Reward 设计

Reward 可以由几部分组成：

\[
R=
R_{evidence}
+
R_{hypothesis}
+
R_{validation}
-
R_{cost}
-
R_{redundancy}
\]

---

## 15.1 Evidence Reward

动作获得新的关键事实：

```text
+ attacker-controlled confirmed
+ sensitive sink confirmed
+ missing guard confirmed
+ caller identity resolved
```

---

## 15.2 Hypothesis Reward

Hypothesis Confidence 发生有效变化：

```text
0.42 -> 0.78
```

或者某个重要 Unknown 被解决。

---

## 15.3 Validation Reward

最高奖励来自：

```text
confirmed vulnerability
reproducible path
PoC-ready finding
```

---

## 15.4 Cost Penalty

例如：

- Token 消耗；
- CodeQL Query 成本；
- 大规模数据流分析成本；
- Repository Search 次数；
- 无效文件读取；
- LLM 调用次数。

---

## 15.5 Redundancy Penalty

对于重复调查：

```text
ReadSameFunction
TraceSameFlow
SearchSameKeyword
```

给予惩罚。

这样可以避免 Agent 出现 ReAct 中常见的循环探索。

---

# 16. 一条完整的漏洞挖掘轨迹

假设分析一个 OpenHarmony IPC 权限问题。

---

## S0

```yaml
entry:
  type: IPC
  function: HandleRequest

facts:
  externally_reachable: true

unknowns:
  - attacker_control
  - authorization
  - sensitive_sink
```

### A0

```text
InspectHandler(HandleRequest)
```

---

## S1

发现：

```text
HandleRequest(req)
    ->
ProcessRequest(req)
```

### A1

```text
TraceAttackerControlledData(req)
```

---

## S2

得到：

```text
req.uid
  ->
userId
  ->
GetResource(userId)
```

### A2

```text
GenerateHypothesis()
```

---

## H1

```yaml
type: authorization_bypass

statement:
  attacker may select another user's resource

missing_evidence:
  - whether userId must equal callingUid
  - whether authorization is performed upstream
```

### A3

```text
FindAuthorizationGuard(userId)
```

---

## S3

结果：

```text
No guard dominates GetResource(userId)
```

### A4

```text
SearchSiblingHandler(HandleRequest)
```

---

## S4

发现其它 Handler 中存在：

```cpp
if (userId != GetCallingUid()) {
    return ERR_PERMISSION_DENIED;
}
```

这形成一个非常有价值的 Secure Contrast。

### A5

```text
TraceCallerIdentity(HandleRequest)
```

---

## S5

发现：

```text
callingUid is available but unused
```

### A6

```text
ValidateHypothesis(H1)
```

---

## S6

最终：

```yaml
status: confirmed

evidence:
  - IPC externally reachable
  - attacker controls userId
  - sensitive resource selected by userId
  - no authorization guard
  - sibling APIs enforce caller-user relation
  - callingUid available but unused
```

此时可以进入 PoC Generation / Manual Validation。

---

# 17. 训练数据形式

整个 Agent 过程天然可以转换为：

\[
(S_t,a_t,R_t,S_{t+1})
\]

例如：

```json
{
  "state": {
    "focus": "HandleRequest",
    "hypothesis": "authorization bypass",
    "unknowns": [
      "caller identity validation"
    ]
  },
  "action": {
    "operation": "find_guard",
    "target": "Process"
  },
  "reward": 0.8,
  "next_state": {
    "facts": [
      "no authorization guard found"
    ]
  }
}
```

因此可以用于：

- Offline RL；
- Imitation Learning；
- Preference Learning；
- Q Learning；
- Process Reward Model；
- MCTS Value Training；
- Self-Play / Self-Improvement。

---

# 18. 与传统 ReAct Agent 的差异

传统代码 Agent 通常是：

```text
Thought
 ->
Tool
 ->
Observation
 ->
Thought
```

其问题是 Tool Space 非常大，而且缺乏明确的 Search Objective。

本方案则是：

```text
Evidence State
     |
     v
Security Hypothesis
     |
     v
Critical Unknown
     |
     v
Candidate Investigation Actions
     |
     v
Value / Policy Selection
     |
     v
Program Analysis
     |
     v
New Evidence
```

因此核心研究问题变成：

> 如何学习一个 security investigation strategy，在有限审计预算下选择最有价值的证据获取动作？

而不是：

> 如何让 LLM 更好地调用工具？

---

# 19. 对论文创新点的潜在表达

可以考虑将核心贡献概括为：

## Contribution 1: Investigation-Centric Formulation

首次将代码漏洞审计从程序路径遍历重新建模为：

> evidence-guided security investigation

状态表示当前已经获得的安全证据和漏洞假设，而不是单一程序位置。

---

## Contribution 2: Security Audit Action Space

设计一组参数化、可学习的 Security Investigation Primitives，将：

- Program Structure；
- Data Flow；
- Security Guard；
- Semantic Analysis；
- Hypothesis Validation

统一进 Agent Action Space。

---

## Contribution 3: Evidence / Hypothesis State

提出同时包含：

```text
Program Facts
Evidence Graph
Security Hypothesis
Critical Unknowns
```

的结构化审计状态，减少 LLM 对原始长代码上下文的依赖。

---

## Contribution 4: Learned Investigation Policy

学习：

\[
Q(S,a)
\]

而不是学习：

\[
P(vulnerability|code)
\]

即：

> 判断“下一步调查什么最有价值”，而不是判断“当前代码像不像漏洞”。

---

# 20. 最终建议的研究问题

整个方案可以最终浓缩为一个非常清晰的问题：

> **Given a large codebase, limited auditing budget, and partial security evidence, what investigation operation should an agent perform next to most efficiently confirm or reject a vulnerability hypothesis?**

中文：

> **在大型代码库、有限审计预算和不完整安全证据的条件下，代码审计 Agent 应当选择哪一个调查操作，才能最高效地将潜在漏洞假设推进至证实或证伪？**

这比“在 CFG 中寻找漏洞路径”更加符合真实人工代码审计过程。

---

# 21. 一句话总结

本方案的核心不是：

> 让 LLM 学习怎样遍历 CFG。

而是：

> **让 Agent 学习怎样进行安全调查。**

因此：

\[
\boxed{
S=\text{Evidence / Belief State}
}
\]

\[
\boxed{
A=\text{Security Investigation Operations}
}
\]

\[
\boxed{
CFG/CG/DDG=\text{Agent 可查询的程序世界模型}
}
\]

\[
\boxed{
Q(S,a)=\text{该调查动作对于最终验证漏洞的预期价值}
}
\]

最终形成：

> **Evidence-Guided, Hypothesis-Driven, Value-Optimized Code Auditing Agent**

这可以作为后续整个漏洞挖掘 Agent 状态机、训练方法和论文方法部分的核心抽象。
