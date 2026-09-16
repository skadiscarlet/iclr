# EGSI Java Web 训练流水线工程设计

**状态**：已确认设计  
**阶段**：prototype development and experiment  
**日期**：2026-08-28  
**Context V2 实现更新**：2026-08-30  
**上位规范**：

- `EVIDENCE_GUIDED_AUDIT_DESIGN.md`
- `ACTION_DSL.schema.json`
- `AUDIT_AUTOMATON.yaml`
- `TRAINING_SPEC.yaml`
- `DATA_COLLECTION_GUIDE.md`

## 1. 目标与边界

本工程聚焦 Java Web 漏洞调查，使用强 LLM 生成经约束的训练轨迹，训练
0.5B–3B 的小型 selector。训练目标不是漏洞二分类器、自由式渗透 Agent 或自动修复器，而是：

> 给定当前审计状态、剩余预算、未完成 proof obligations、候选 Action DSL 动作与工具能力，选择下一步最有价值的调查动作，并在证据不足时正确继续、回溯或停止。

强 teacher 只能产生 `Hypothesis`、`Derived Claim`、候选动作和结构化解释；
`Fact`、reward、certificate 与 terminal outcome 只能由确定性 verifier 或可重放 receipt 产生。

第一轮覆盖：

| Family | CWE | 语义 |
|---|---|---|
| Source-to-Sink | CWE-22 | Path Traversal |
| Source-to-Sink | CWE-78 | OS Command Injection |
| Source-to-Sink | CWE-79 | XSS |
| Source-to-Sink | CWE-89 | SQL Injection |
| Source-to-Sink | CWE-611 | XXE |
| Source-to-Sink | CWE-918 | SSRF |
| Authorization | CWE-639 | IDOR/BOLA/object-level authorization |
| Authorization | CWE-862 | Missing Authorization |
| Authorization | CWE-863 | Incorrect Authorization |

CWE-264/269/284/285 作为原始或历史标签保留，只有在记录 `mapping_reason` 后才映射到当前 authorization proof template；不得覆盖原始标签。

## 2. 已验证的数据基线

`data/` 当前链接到大容量本地数据目录。2026-08-28 的只读复核结果为：

- 2,460 个 Java/Maven 目标 CWE 候选；
- 300 个 revision-resolved T1 root cases；
- 206 个独立 upstream repositories；
- A 类 213、B 类 87；
- train/dev/time+repo-OOD 为 200/60/40；
- 300/300 包含 vulnerable commit、fixed commit、fix patch、policy view、oracle view 和 hash-linked manifest；
- 300/300 尚未执行 build，`poc_status=not_collected`；
- repository、project family、patch lineage、AST clone cluster、shared dependency cluster 在 train/dev 与 Time-OOD 间的重叠均为 0；
- `validate_catalog.py` 和 collected-case 只读校验均通过，collected-case 校验报告 errors 为空。

因此这些数据是可训练的 patch-grounded seeds，不得描述为已动态复现的 PoC。

## 3. 放宽后的证据分级

数据是否进入训练由其能支持的 loss 决定，不要求所有案例达到动态 Gold 标准。

| Tier | 最低准入条件 | 允许用途 | 禁止用途 |
|---|---|---|---|
| T0 Curriculum | benchmark label 或 vulnerable/secure pair 可解析 | primitive、DSL、role/state normalization SFT | 真实 CVE 数量、terminal exploit reward |
| T1 Patch-grounded | vulnerable/fixed revision、patch/changed paths、family/CWE 和 provenance 可解析 | teacher enrichment、localization、proof template、BC/SFT、候选动作监督 | 动态确认、PoC-confirmed terminal reward |
| T2 Replayable | T1 加 build、静态 oracle、官方 regression test 中任一可重放证据 | SFT、Branch Replay、value/ranking、受限 terminal label | 没有动态证据时冒充 exploit/impact confirmation |
| T3 Executable | 可执行 PoC 或 vulnerable/fixed security differential | terminal reward、certificate、端到端最终评测 | 无 |

没有 PoC、build 失败或无法稳定动态复现时，案例保持 T1/T2，而不是被删除。PoC 状态使用：

```text
not_collected
url_only
available_unverified
adapted
replayed
```

PoC 和 T2/T3 升级采用增量策略，不设阻塞 Stage-1 训练的硬配额。

## 4. 标准数据接口

### 4.1 CaseManifest

每个 root case 由 `CaseManifest` 归一化，必须包含：

```json
{
  "case_id": "ghsa-...",
  "evidence_tier": "T1",
  "family": "authorization",
  "cwe_normalized_primary": "CWE-863",
  "repository": {
    "url": "https://github.com/org/repo",
    "vulnerable_commit": "40-hex-sha",
    "fixed_commit": "40-hex-sha"
  },
  "affected_locations": [],
  "artifacts": {
    "patch_path": "...",
    "proof_obligations_path": "...",
    "poc_status": "not_collected"
  },
  "views": {
    "policy_view_path": "...",
    "oracle_view_path": "...",
    "redaction_manifest_sha256": "sha256:..."
  },
  "split_groups": {},
  "provenance": {}
}
```

### 4.2 Oracle/Policy 双视图

`oracle_view` 可引用 advisory、CWE、patch、fix commit、gold locations 和 gold obligations，用于离线 teacher enrichment、标签恢复和验证。

`policy_view` 只允许包含 vulnerable snapshot、先前 observations、预算、当前 state、unknowns 和 candidate actions。训练、rollout 和 evaluation loader 必须拒绝以下字段：

```text
cwe, aliases, advisory, fixed_commit, patch,
gold_locations, gold_proof_obligations, authorization_model
```

每次 redaction 生成 manifest 与 SHA-256。oracle view 不得被 selector loader 读取。

#### 4.2.1 Context V2 的 bounded patch recovery

Teacher-only `OracleContext` 使用 `context_version=2.0` 与
`selection_policy_id=patch-hunk-v1`。原始 patch 首先经过 bounded safe read
（最多 2 MiB、单行最多 64 KiB），然后始终进入同一个严格 unified/Git diff
parser；不得修正、猜测或忽略错误 hunk counts。

当且仅当原始 patch 已通过 safe read、但严格 parser 因结构损坏而拒绝时，允许
从同一个已验证 bare Git cache 生成 fallback：

```text
git diff --no-ext-diff --no-textconv --binary --full-index --no-color \
  <exact-vulnerable-40-hex> <exact-fixed-40-hex> --
```

两个 OID 必须同时来自 catalog、oracle repository 和 artifact manifest
resolution 的一致 40-hex commitments，并各自验证为 `commit` object；接口不接收
revision expression 或 pathspec。Git 子进程禁用 replace objects、lazy fetch、
external diff/textconv、system/global config 和继承的 `GIT_*` redirect，使用固定
argv（无 shell）和固定 `C` locale。fallback 每次创建权限 `0700` 的临时最小
bare shell（常量 `config` / `HEAD`、空 `objects/`），commit probes 与 diff 只在该
shell 中运行；唯一注入的 Git 重定向是指向已验证原 object store 的受控
`GIT_ALTERNATE_OBJECT_DIRECTORIES`（单路径按 Git path-list C-style grammar
quote/escape），因此合法路径中的 separator / quote 不会被拆分。原 bare repo 的
local config、`include.path` 和 diff settings 不参与输出；固定
`core.attributesFile=/dev/null` 与 `GIT_ATTR_NOSYSTEM=1` 同时隔离 caller 的
user/system attributes，但保留 pinned commits 内 `.gitattributes` 的语义。

所有 Git 子进程使用独立 process group。主执行阶段只有一个 10 秒 deadline，
stdout 上限为 2 MiB；timeout、overflow 或 read failure 都对完整 group 执行
`SIGTERM`、短固定 cleanup grace、`SIGKILL`，并有界完成 parent wait、stdout close
和 reader join，不允许 cleanup 重新进入无界 `communicate()` / `wait()` /
`join()`。`Popen` 成功后的 reader buffer 分配、reader 构造或 thread start 任一
异常也进入同一个 `finally` cleanup；生命周期显式区分 `reader_started` 与
`process_reaped`，未成功启动的 thread 禁止 join。fallback 输出仍必须通过同一个
严格 parser；任何 nonzero、timeout、oversize、malformed 或 commit mismatch
都使 context 构建失败。

`SelectionReceipt` schema `1.1` 同时提交：

- 原始 artifact 的 `raw_patch_sha256` / `raw_patch_byte_count`；
- `effective_patch_source = raw | canonical_git_diff`；
- 完整 effective patch 的 SHA-256 / byte count；
- bounded patch evidence、source blobs、ordered chunks 和 receipt commitment。

因此 fallback 是对 pinned commits 的可重放恢复，不是放松 parser；raw patch
有效时不得调用 fallback。receipt 进入 canonical context render/hash，旧 context、
prompt 与 teacher cache 会自然失效。

全量 gate 使用：

```bash
egsi validate-contexts --catalog data/catalog/cases.jsonl --root . \
  --repeat 2 --max-chars 64000 \
  --report .work/context-v2-validation.json
```

硬门槛为 catalog 恰好 300、两次 render/context hash/receipt commitment 一致、
300/300 构建成功、每个 context 不超过 64,000 characters、P0/P1 frozen lists
完整且不与 `time_ood_test` 重叠。报告必须通过现有 safe atomic writer 写入，并仅
暴露稳定失败类别与 case IDs。报告中的 `built` 只计入所有 repetitions 均成功的
case，`failed` 计入任一 repetition 失败的 case，并强制
`requested = built + failed`；当 `repeat >= 3` 时，即使某次失败，其余成功
snapshots 仍全部互比并在不一致时进入 `hash_mismatch_case_ids`，同时 gate 保持
`overall_valid=false`。

### 4.3 输出目录

```text
data/
  catalog/cases.jsonl
  derived/enrichment/<case_id>.json
  derived/episodes/<episode_id>.jsonl
  derived/trajectories/{train,dev,time_ood}.parquet
  reports/enrichment-summary.json
  reports/trajectory-validation.json
  artifacts/<case_id>/
    patch/
    labels/
    views/
    receipts/
    manifest.json
```

大文件 receipt 采用 content-addressed storage；event log append-only。

## 5. 工程模块

在现有 `egsi/` 建议结构上增加：

```text
egsi/
  data/
    manifest.py
    provenance.py
    admission.py
    dedup.py
    splits.py
    materializer.py
    adapters/
  teacher/
    client.py
    openai_adapter.py
    anthropic_adapter.py
    prompts.py
    structured_output.py
    cache.py
  proof_templates/
    source_to_sink.yaml
    authorization.yaml
  generation/
    context_builder.py
    enrichment.py
    episode_factory.py
    rollout.py
    branch_replay.py
    verifier_gate.py
    redaction.py
    writer.py
  training/
    dataset.py
    selector_model.py
    sft.py
    value.py
    offline_rl.py
  eval/
    contract_tests.py
    metrics.py
    replay.py
    baselines.py
```

模块职责：

1. `materializer` 从 pinned Git revision 按需恢复 vulnerable/fixed snapshot；
2. `context_builder` 读取 advisory、patch、changed files 与必要源码窗口，构造 oracle-phase context；
3. `enrichment` 调用 teacher 恢复结构化安全语义；
4. `redaction` 生成 hash-linked policy-facing 数据；
5. `episode_factory` 初始化 Typed Audit Automaton；
6. `rollout` 只执行 typed primitives；
7. `verifier_gate` 决定 observation、Fact、reward 和是否写入训练集；
8. `writer` 原子写入事件、trajectory 与 manifest。

## 6. Proof Templates

### 6.1 Source-to-Sink

```text
attacker-controlled source
→ reachable propagation
→ guard/sanitizer effectiveness
→ security-sensitive sink
→ observable impact（可未知）
→ patched-negative differential（仅 T2/T3）
```

不同 CWE 替换 sink 和安全 invariant，公共 Action DSL 保持一致。

### 6.2 Authorization

```text
attacker identity
→ requested action
→ protected resource/object
→ expected owner/role/tenant/permission relation
→ actual guard and dominance
→ cross-principal behavior
→ observable confidentiality/integrity/privilege impact（可未知）
→ patched-negative differential（仅 T2/T3）
```

T1 中 `resource/action/actual_check` 可以保持 `unknown`。对应 expert action 应是
`inspect_changed_files`、`trace_identity`、`find_guard`、`check_ownership` 或
`check_auth_relation`，而不是丢弃案例或伪造完整 authorization model。

## 7. Teacher Enrichment 与轨迹生成

### 7.1 Provider 接口

统一接口：

```python
TeacherClient.generate_structured(
    state,
    proof_template,
    candidate_context,
    output_schema,
)
```

支持 OpenAI-compatible 与 Anthropic adapter。主 teacher 由配置选择，可使用
`gpt-5.6-sol` 或 `claude-opus-5`；第二 provider 仅用于约 10% 的稀缺、冲突或高价值状态复核。模型分歧触发额外 verifier 或人工抽查，不能直接产生 Fact。

记录 provider、完整 model identifier/revision、prompt hash、temperature、token budget、request ID、latency、usage 和 structured-output validation result。

### 7.2 API 配置

API key 按用户要求写入配置文件：

```text
configs/providers.example.toml
configs/providers.local.toml
$HOME/.config/egsi/providers.toml
```

示例：

```toml
active_provider = "openai"

[providers.openai]
base_url = "https://api.openai.com/v1"
api_key = "replace-me"
model = "gpt-5.6-sol"
timeout_seconds = 180
max_retries = 3

[providers.anthropic]
base_url = "https://api.anthropic.com"
api_key = "replace-me"
model = "claude-opus-5"
timeout_seconds = 180
max_retries = 3
```

加载优先级：CLI `--provider-config`、`EGSI_PROVIDER_CONFIG` 路径、
`$HOME/.config/egsi/providers.toml`。实际 key 文件权限为 `0600`，加入 `.gitignore`；key 不进入日志、trajectory、receipt、manifest 或异常文本。

### 7.3 Rollout 数据流

```text
CaseManifest
→ materialize vulnerable snapshot
→ oracle-phase teacher enrichment
→ validate locations/proof/action skeleton
→ redact oracle-only fields
→ initialize Audit Automaton
→ rule/graph/retrieval/teacher candidate generation
→ Action DSL schema validation
→ hard legality mask
→ teacher expert selection
→ real typed-tool execution
→ normalize observation
→ verify receipt
→ update Fact/Claim/Unknown/Proof state
→ compute verifier-grounded reward
→ append transition
```

限制：

- teacher 每步最多提出 8 个语义候选；
- Candidate Compiler 合并后最多 64 个候选；
- teacher 不能自由生成 shell；
- teacher 不能生成 tool result、Fact、reward 或 certificate；
- 在线 rollout 中，selected teacher action 只有在 verifier 确认 proof delta、有效 counter-evidence、contradiction resolution 或正确停止后，才作为 verifier-backed BC positive；
- T1 oracle-phase trace skeleton 可在通过 patch-location、Action DSL、provenance 与 redaction 校验后作为 `patch_grounded_bc` positive，但必须携带该 label scope，不能赋予动态 reward；
- 无 proof delta、重复读取和错误终止保留为 ranking negative。

### 7.4 Branch Replay

在高信息状态保存 checkpoint，从合法候选选择 3–8 个 alternative actions；使用相同 state、budget 与 tool versions，各继续三步。记录：

```text
verified proof delta
critical unknown delta
k-step return
normalized cost
redundancy
terminal outcome（如实际到达）
```

T1 若没有可执行工具反馈，只生成静态/结构化 ranking label；不得合成动态 terminal reward。

## 8. Selector 模型

固定使用同一模型家族：

| 用途 | 模型 |
|---|---|
| pipeline/低成本基线 | `Qwen2.5-Coder-0.5B-Instruct` |
| 主模型 | `Qwen2.5-Coder-1.5B-Instruct` |
| 容量上界 | `Qwen2.5-Coder-3B-Instruct` |

模型输入包含 canonical state、proof frontier、bounded history、budget 与最多 64 个候选。自定义 `EgsiSelectorForCandidateRanking` 包含：

```text
shared decoder backbone
candidate ranking head
hypothesis/obligation auxiliary heads
operation/entity/tool factor heads
stop/outcome head
value/cost/information-gain/redundancy heads
```

hard legality mask 在模型外执行，模型不能覆盖。

### 8.1 Stage 1：SFT/BC

```text
L1 =
1.0 * listwise_candidate_CE
+ 0.3 * factorized_action_CE
+ 0.2 * stop_outcome_CE
+ 0.2 * fact_claim_boundary_CE
```

不训练自然语言 CoT，只训练结构化 decision 与审计标签。

### 8.2 Stage 2：Value Learning

使用实际 Branch Replay 的 k-step return、proof/unknown delta、cost、redundancy 和 terminal outcome 训练 quantile-Q 与辅助 heads。只对有对应 evidence 的样本启用 loss mask。

### 8.3 Stage 3：Offline RL

仅在 Stage 1/2 工程门槛通过且已有足够 replay labels 时启用：

```yaml
algorithm: discrete_IQL
expectile_tau: 0.7
advantage_beta: 3.0
cql_alpha: 0.1
warm_start: behavior_cloning
```

第一轮不启动在线 PPO/GRPO。

### 8.4 QLoRA

```yaml
load_in_4bit: true
quant_type: nf4
compute_dtype: bfloat16
double_quant: true
lora_rank: 32
lora_alpha: 64
lora_dropout: 0.05
target_modules:
  - q_proj
  - k_proj
  - v_proj
  - o_proj
  - gate_proj
  - up_proj
  - down_proj
max_sequence_length: 16384
gradient_checkpointing: true
micro_batch_size: 1
gradient_accumulation_steps: 16
optimizer: paged_adamw_8bit
learning_rate: 0.0001
warmup_ratio: 0.03
epochs: 2
```

ranking/value heads 使用 BF16 全量训练。

## 9. 远端执行

训练机为 `ai@10.8.0.11`。2026-08-25 的只读核验显示两张目标卡均为 A800 80GB：GPU 7 当时约 48GB 空闲且利用率 0%，GPU 4 约 66GB 空闲但利用率 98%。调度不能只判断显存。

### 9.1 分工

| GPU | 任务 |
|---|---|
| GPU 7 | 0.5B smoke、1.5B 主实验与 seeds |
| GPU 4 | 3B capacity run，空闲检测通过后启动 |
| CPU/Docker | Git materialization、Java build、静态分析、PoC/receipt replay |

不做异构 DDP。每张卡运行独立 job。

### 9.2 启动门槛

连续三次、间隔 30 秒满足：

```text
utilization < 20%
free memory >= requested memory + 8GB
no EGSI lease
disk free >= 500GB
Docker healthy
```

建议申请显存：0.5B 12GB、1.5B 24GB、3B 40GB。

### 9.3 远端目录与恢复

```text
$HOME/egsi/
  source/<source_bundle_hash>/
  datasets/<dataset_fingerprint>/
  caches/{huggingface,codeql,maven,gradle}/
  runs/<run_id>/
  leases/{gpu-4.lock,gpu-7.lock}
```

不使用 `rsync --delete`。每个 run 保存 dataset fingerprint、split hash、base model revision、adapter config hash、container digest、GPU、seed、command、exit code 和 best checkpoint。checkpoint 每 500 optimizer steps 保存 latest、validation best、final 与最近三个恢复点。

OOM 只自动重试一次，减小 candidate chunk 或 micro-batch，不改变数据。dataset fingerprint 不一致时拒绝 resume。

## 10. 失败语义

| 失败 | 处理 |
|---|---|
| teacher 非法 JSON | 最多两次 schema repair；仍失败则写 failure receipt，不写 positive transition |
| build 失败 | 保持 T1 或静态 T2；不删除案例 |
| tool timeout/error | 写 partial receipt，进入 `RECOVER_TOOL`；不能解释为漏洞不存在 |
| PoC 不稳定 | 保持 `available_unverified/adapted`；不产生 T3 terminal reward |
| teacher/verifier 冲突 | 保留 counter-evidence，允许 `ABSTAIN` |
| receipt 无法重放 | trajectory quarantine；root case 保留 |
| oracle/policy 泄漏 | episode 作废并记录 contamination reason |
| API 失败 | 重试后记录失败；不得生成负标签 |

## 11. 测试与评测

### 11.1 T0/T1 指标

```text
structured-output parse rate
Action DSL legality rate
changed-file/method/symbol localization recall
proof-obligation coverage
Candidate Oracle Recall@64
next-action Top-1/Top-k/NDCG
duplicate-loop rate
premature-stop rate
policy-view leakage count
event replay rate
```

### 11.2 T2/T3 指标

仅在有相应证据时启用：

```text
verified finding rate at budget
confirmed precision/recall/F1
patched-negative false-confirmation rate
cost per confirmed finding
certificate replay pass rate
```

不适用的指标输出 `not_applicable`，不得填 0 或合成数字。

### 11.3 Baselines

使用相同 state、候选集、hard mask 和 budget：

1. masked random；
2. proof-obligation greedy；
3. greedy information gain；
4. cost-risk heuristic；
5. flat BC；
6. hierarchical BC；
7. hierarchical BC + Branch Replay value；
8. 0.5B/1.5B/3B capacity comparison。

Free-form ReAct 只作端到端对照，不与受约束 selector 的 DSL parse rate 混合比较。

### 11.4 自动测试

- Schema、Automaton transitions、Fact/Claim、budget、duplicate 与 `ABSTAIN` contract tests；
- manifest/hash/revision、policy/oracle、split、provider-key redaction 与 idempotency data tests；
- teacher structured output、location existence、Action DSL、Fact/reward ownership tests；
- state version、candidate/legal membership、receipt、reward provenance 与 event replay trajectory tests。

第一轮工程门槛：

```text
policy/oracle leakage        = 0
manifest/hash validation     = 100%
Action DSL parse after gate  = 100%
selected illegal action      = 0
event replay success         >= 98%
teacher structured parse     >= 95%
invalid location rate        <= 5%
```

这些门槛只判断流水线是否正确，不预设模型性能提升。失败结果必须保留。

## 12. Pilot 与实现顺序

### P0：10 cases

覆盖 CWE-22/78/89/611/918/639/862/863，完成 case → enrichment → redaction → candidate compilation → transition JSONL → replay validation，不训练模型。

### P1：30 cases

A 18、B 12；生成 expert trace skeleton 和关键状态的至少三个 alternative branches；人工抽查 source/sink/guard/auth relation。

### P2：260 train/dev cases

批量 enrichment 和 Stage-1 数据生成；冻结 40 个 Time-OOD cases。T2/T3 有多少使用多少，不设阻塞配额。

### P3：训练

1. GPU 7 跑 0.5B smoke；
2. GPU 7 跑 1.5B 主实验三 seeds；
3. GPU 4 空闲后跑 3B capacity run；
4. 有足够真实 branch labels 后再启动 Stage 2/3。

实现顺序：

1. enrichment/trajectory Schema；
2. provider config 与 adapters；
3. Git snapshot materializer；
4. oracle context builder；
5. teacher enrichment；
6. policy redaction gate；
7. candidate compiler 与 trajectory writer；
8. replay validator；
9. 10-case、30-case pilot；
10. 0.5B smoke；
11. 扩展到 260 cases 和 1.5B/3B。

## 13. 明确不做

- 不因缺少 PoC 丢弃 T1 训练案例；
- 不把 LLM 输出当作 Fact、reward 或动态 ground truth；
- 不让 selector 读取 patch/advisory/gold obligation；
- 不把 micro-benchmark 数量描述为独立真实漏洞数量；
- 不在第一轮做在线 RL；
- 不为符合论文预期而放松 verifier、隐藏负结果或提前声称 family-OOD/T3 结果。
