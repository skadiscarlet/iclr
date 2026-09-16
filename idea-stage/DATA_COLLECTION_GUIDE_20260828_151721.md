# Java Web 漏洞数据收集指南（第一阶段）

**项目**：Evidence-Guided Security Investigation（EGSI）  
**阶段**：prototype development / experiment  
**数据冻结日**：2026-08-28  
**训练时间截点**：fix/advisory date `<= 2025-12-31`  
**Time-OOD 保留区间**：`2026-01-01` 至 `2026-08-28`

## 1. 先明确收集目标

本项目训练的不是“给代码判一个 CWE 标签”的分类器，而是：

> 给定仓库快照、审计状态、剩余预算、未完成 proof obligations 和合法候选动作，选择下一步最有价值的调查动作。

因此一个真正有用的训练单位是 **root case（根案例）**，而不是一行 CVE 描述或一个孤立函数。每个 root case 最终应尽量提供：

```text
公开仓库 + vulnerable revision + fixed revision
+ advisory/CVE/GHSA/OSV 元数据
+ 受影响入口/方法/数据流或鉴权关系
+ patch 或测试/PoC 证据
+ 可生成多步审计 trajectory 的上下文
```

`TRAINING_SPEC.yaml` 要求 trajectory 至少记录 state、候选动作、合法性 mask、实际动作、observation、evidence delta、verifier decision、reward 和 next state。数据收集阶段不直接生成这些轨迹，但必须为后续生成保留足够的仓库级证据。

## 2. 放宽标准后的四级准入

用户已明确“只要能够用于训练即可”，因此不再要求所有案例都达到可执行 PoC 标准。采用以下四级，而不是把不够 Gold 的样本全部丢弃。

| 等级 | 最低要求 | 可用于什么 | 不可用于什么 |
|---|---|---|---|
| **T0 Curriculum** | 合成/教学样例；CWE 与 vulnerable/secure label 可解析；能定位 source/sink/guard 或 auth check | 作为 trajectory 生成种子；经 verifier 接受后用于 primitive、DSL、角色和状态规范化的 SFT | 真实 CVE 数量、真实跨仓库泛化结论 |
| **T1 Patch-grounded seed** | 公开 Java/JVM 仓库；pinned vulnerable/fixed ref；CWE/漏洞族；受影响文件或方法；advisory/patch 至少一项 | pinned root-case catalog、teacher investigation seed、候选动作与 proof-obligation 构造 | 不能直接当作 SFT/BC transition；不能产生独立 CONFIRMED 终态 |
| **T2 Replayable** | T1 + 可构建，或有官方 regression test / 静态 oracle / 可重放 patch differential | 经 verifier 接受后用于 SFT/BC、branch replay、value/ranking、部分 terminal reward | 没有动态证据时不得冒充 PoC-confirmed |
| **T3 Executable / eval** | 同一安全 harness 在 vulnerable/fixed 上产生明确 differential；patched negative 可重放 | 独立端到端评测、CONFIRMED/REJECTED、误报率 | 不与训练轨迹、teacher 输出或候选检索索引混用；不得向 policy 泄漏 patch/advisory |

最低不可放宽的三项是：**来源可追溯、revision 固定、训练/测试不泄漏**。否则样本虽多，却会直接污染研究结论。T0/T1/T2 是 root-case 证据等级，不等于 transition 已可训练；进入 `transitions/*.parquet` 的每一步仍必须有 pinned snapshot、pinned tool version、receipt、合法性判定和 verifier-accepted evidence delta。

## 3. 漏洞范围与数量目标

### 3.1 首轮真实 root cases：300 个

其中 **260 个训练/开发 T1+ cases**，另有 **40 个完全隔离的 T3 evaluation cases**。

#### A 类：Source-to-Sink，180 个

| CWE | 目标 | 备注 |
|---|---:|---|
| CWE-22 Path Traversal | 35 | CWE-Bench-Java 可提供主要种子 |
| CWE-78 OS Command Injection | 30 | CWE-Bench-Java、OWASP、真实 CVE |
| CWE-79 XSS | 30 | CWE-Bench-Java、OWASP；避免模板过度重复 |
| CWE-89 SQL Injection | 35 | 重点从 JavaVFC、Project KB、VCC-Eval 和公开 CVE 补齐 |
| CWE-611 XXE | 25 | 稀缺类，优先官方 patch/test |
| CWE-918 SSRF | 25 | 稀缺类，允许厂商标为 CWE-601/611、但需语义重标 |
| **合计** | **180** | |

#### B 类：Authorization，80 个

| CWE | 目标 | 证明重点 |
|---|---:|---|
| CWE-639 IDOR/BOLA | 25 | 主体 A 是否能访问/修改主体 B 的对象 |
| CWE-862 Missing Authorization | 30 | 应存在的 auth check 完全缺失 |
| CWE-863 Incorrect Authorization | 25 | 有检查但对象、角色、租户、路径或操作判断错误 |
| **合计** | **80** | legacy CWE-264/269/284/285 保留原标签并重映射 |

每个 root case 仅计入一个 `cwe_normalized_primary` 配额；链式漏洞的其他 CWE 记入 `cwe_normalized_secondary`，不得重复计入 A/B 总数。报表同时输出 primary count、secondary association count 和去重 root-case count。

### 3.2 候选漏斗与仓库多样性

为得到 260 个训练/开发 cases 和 40 个独立评测 cases，建议实际收集：

```text
600 条 discovered CVE/GHSA/数据集候选
  -> 360 条完成 repo/commit/CWE 归一化
  -> 260 条 train/dev T1+ root cases（A=180，B=80）
  -> 其中至少 100 条提升为 T2 replayable
  -> 另建至少 40 条完全隔离的 T3 executable evaluation cases
```

仓库要求：

- 总计至少 **80 个独立 upstream repositories**；
- A 类至少 50 个仓库；B 类至少 20 个仓库；
- 同一仓库主训练集最多贡献 5 个 root cases，超出部分保留但降采样；
- fork、mirror、backport、同一 root cause 的多 CVE 编号只算一个 root case；
- vulnerable/fixed、同一 patch 的多分支版本必须进入同一 split。

### 3.3 最终训练数据量

首轮目标不是 300 条文本，而是只从 **260 个 train/dev root cases** 生成：

- **25,000 条 verifier-accepted train/val transitions**（可接受范围 20k–50k）；
- **2,500 个 branch-replay states**（可接受范围 2k–5k）；
- 每个 root case 通常生成 60–120 条 transitions；
- A:B 的训练采样约为 `60:40`；B=80 时平均每个 B case 恰好不超过总 transitions 的 `0.5%`；
- 单个 root case 不得超过全部训练 transitions 的 `0.5%`；
- 单个模板簇不得超过 `2%`。

40 个 T3 evaluation cases 必须与 train/val 在 repository、project family、patch lineage、AST clone、shared dependency 和时间上隔离。其 snapshot、trajectory、teacher output、patch/advisory 不得进入训练或候选检索索引。T0 合成数据不计入 300 个真实 root cases；可抽取 3,000–6,000 个相关 testcase，但必须按模板簇降采样。

## 4. 应优先收集的公开数据集/仓库

### 4.1 P0：立即拉取和归一化

| 来源 | 官方入口 | 许可状态 | 已知内容 | 本项目用途 | 注意事项 |
|---|---|---|---|---|---|
| **CWE-Bench-Java** | https://github.com/iris-sast/cwe-bench-java | MIT | 120 个真实 Java CVE；CWE-22/78/79/94；buggy/fixed source 与修复位置 | A 类真实仓库主种子 | 不包含 CWE-89/611/918；不要把 CWE-94 错算成 CWE-89 |
| **Vul4J+** | https://github.com/tuhh-softsec/vul4j-plus | repo/Zenodo 条款需逐项固化 | 191 个 Java 漏洞、每项至少一个 oracle；其中 106 个有容器化 executable test | T2/T3 主来源 | 与原 Vul4J 高度重叠，按 CVE+repo+patch 去重，不能把二者相加 |
| **Vul4J** | https://github.com/tuhh-softsec/Vul4J | GPL-3.0（框架仓库） | vulnerable revision、human patch、PoV test | 用于交叉核验和兼容旧工具 | 下游源码仍按各 upstream 许可；旧依赖可能构建失败 |
| **VCC-Eval Java** | https://github.com/tuhh-softsec/VCC-Eval-A-Manually-Curated-Dataset-of-Vulnerability-Introducing-Commits-in-Java | 需核验 repo/Zenodo 数据条款 | 人工审查的 CVE、CWE、introducing/fixing commit 与行级定位 | T1，恢复 root cause 与修复路径 | 通常无 PoC；不直接产生 terminal reward |
| **SAP Project KB** | https://github.com/SAP/project-kb | Apache-2.0（仓库） | 开源漏洞、fix commits、YAML statement | T1 候选池、CVE→commit 交叉索引 | tangled patch 与方法级标签需复核 |
| **JavaVFC** | https://zenodo.org/records/13731781 | 以 Zenodo record 为准，下载时固化 | 784 条人工验证 Java VFC；16,837 条 heuristic extended VFC | 只把 784 条人工集作为 T1 候选；extended 用于检索 | extended 不能视为已确认漏洞；先限定目标 CWE 和 Java Web 入口 |
| **Java CVE Bench** | https://github.com/MarkLee131/Java_CVE_Bench | MIT | 165 个 Java CVE、方法级定位、部分可下载 vulnerable versions | 定位候选与补充项目多样性 | 不等于有 PoC；与 CWE-Bench/Project KB/Vul4J 去重 |

### 4.2 P0：课程与可执行 fixture

| 来源 | 官方入口 | 许可状态 | 用途 | 计数方式 |
|---|---|---|---|---|
| **OWASP BenchmarkJava** | https://github.com/OWASP-Benchmark/BenchmarkJava | GPL-2.0 | Java Web source/sink/guard 正负课程；可运行 | 只算 T0 template cases，不算真实 CVE |
| **NIST Juliet Java 1.3** | https://samate.nist.gov/SARD/test-suites/111 | 下载时保存 NIST/SARD 条款 | CWE-22/78/79/89/611 等 primitive 课程 | 按 `CWE + source + sink + control-flow template` 聚类，每簇限额 |
| **SasanLabs VulnerableApp** | https://github.com/SasanLabs/VulnerableApp | Apache-2.0 | Spring Boot、attack vector、secure level，覆盖 A/B | T0/T2 fixture；一个 module 可有多个 variants，但 root case 只算 1 |
| **OWASP WebGoat** | https://github.com/WebGoat/WebGoat | 多文件/无单一 SPDX，需保存 LICENSE/NOTICE | IDOR、access control、SQLi、XXE 等可运行课程 | T0/T2 fixture，不当作真实 CVE |
| **DVJA** | https://github.com/appsecco/dvja | MIT | Struts/Spring/Hibernate 教学应用 | 辅助 B 类/SQLi fixture；旧依赖需容器固定 |

### 4.3 P1：只做候选池，不整库直接训练

- OSV API：<https://osv.dev/>，优先 `ecosystem=Maven`；
- GitHub Advisory Database：<https://github.com/github/advisory-database>；
- NVD CVE API 2.0：<https://nvd.nist.gov/developers/vulnerabilities>；
- GitHub Security Advisories、项目 security 页面、官方 fixing commit 与 regression test；
- 公开 PoC 仓库仅在许可证、目标版本和 payload 均核验后入库。

NVD 只负责元数据发现，**不能把“NVD 有一条描述”当成训练案例**。

## 5. NVD/CVE/PoC 的选择方法

### 5.1 查询白名单

第一轮只查询：

```text
A: CWE-22, CWE-78, CWE-79, CWE-89, CWE-611, CWE-918
B: CWE-639, CWE-862, CWE-863
Legacy discovery only: CWE-264, CWE-269, CWE-284, CWE-285
Ecosystem/language: Maven, Java, Kotlin, JVM
Entry: HTTP, Servlet, Spring MVC/WebFlux, JAX-RS, GraphQL/WebSocket,
       Java Web gateway, REST/RPC endpoint
```

候选至少满足：

1. upstream 源码公开且能固定 commit/tag；
2. vulnerable 与 fixed revision 至少能定位其一，优先二者齐全；
3. 有 official advisory、fix commit、regression test 或公开 PoC 中至少一项；
4. 漏洞发生在目标项目自身 Java/JVM 代码，而不只是 `pom.xml` 中的脆弱依赖；
5. 能描述 A 类 source→sink 或 B 类 subject→object→authorization obligation；
6. 许可允许保存元数据、patch、测试胶水；源码是否可再分发单独记录。

### 5.2 首批训练候选（fix/advisory date 不晚于 2025-12-31）

以下是**优先核验队列**，不是“已经本地复现成功”的声明。收集人员应先找官方 patch/regression test，再找第三方 PoC。

#### A-sparse 与 SQLi

| 优先级 | CVE | 项目 | 目标语义 | 首选证据 |
|---|---|---|---|---|
| P0 | CVE-2018-1000844 | Square Retrofit | CWE-611 XXE | upstream PR #2735 + 新增/修改测试 |
| P0 | CVE-2017-5643 | Apache Camel | XXE→SSRF | Apache advisory + fixing commits/tests |
| P0 | CVE-2024-34711 | GeoServer | CWE-611/918 | GHSA `mc43-4fqr-c965` + fix/test |
| P0 | CVE-2024-38374 | CycloneDX Java | CWE-611 | GHSA/upstream fix + parser regression test |
| P0 | CVE-2024-22243 | Spring Framework | URL parsing→SSRF | GHSA `ccgv-vj62-xf9h` + official commits/tests |
| P0 | CVE-2024-22259 | Spring Framework | URL parsing→SSRF | GHSA `hgjh-9rj2-g67j` + official commits/tests |
| P1 | CVE-2020-11885 | WSO2 Enterprise Integrator | XXE→SSRF | advisory；源码/build 可用性需核验 |
| P1 | CVE-2017-14949 | Restlet Framework | CWE-611 | upstream security notes + fix |
| P0 | CVE-2023-41887 | OpenRefine | JDBC URL/SQL injection chain | GHSA `p3r5-x3hr-gpg5`，公开复现描述与 patch |
| P0 | CVE-2024-32888 | Amazon Redshift JDBC | CWE-89 | GHSA `x3wm-hffr-chwm` + 3 个 fix commits/tests |
| P1 | CVE-2022-23305 | Log4j 1.x JDBCAppender | CWE-89 | advisory；因 EOL/无成对修复，仅作 T1 候选 |

为避免数据只覆盖稀缺类，再从 CWE-Bench-Java 中优先抽取 CWE-22/78/79，并从 Project KB、VCC-Eval、JavaVFC 人工集定向补足 CWE-89。常见 A 类不必再盲目抓取大量个人 PoC。

#### B：Authorization

| 优先级 | CVE | 项目 | 目标语义 | 首选证据 |
|---|---|---|---|---|
| P0 | CVE-2024-22257 | Spring Security | CWE-862，null Authentication 路径 | Spring advisory + upstream test/fix |
| P0 | CVE-2023-6394 | Quarkus GraphQL WebSocket | CWE-862，受保护 endpoint 绕过 | Red Hat/Quarkus issue + regression test |
| P0 | CVE-2018-15758 | Spring Security OAuth | privilege escalation / incorrect authorization | GHSA `h8w4-qv99-f7vj` + fix/tests |
| P0 | CVE-2023-37945 | Jenkins SAML SSO Plugin | missing endpoint permission check | Jenkins advisory + plugin commit/test |
| P0 | CVE-2017-1000105 | Jenkins Blue Ocean | missing Run/Artifacts permission | Jenkins advisory + plugin fix/test |
| P0 | CVE-2020-11009 | Rundeck | authenticated user reads unauthorized project execution/job data | GHSA `5679-7qrc-5m7j` + release/fix |
| P1 | CVE-2018-19110 | tianti | Java controller endpoint missing authorization | upstream issue #29；fix/revision 需核验 |
| P1 | CVE-2019-10354 | Jenkins/Stapler | direct view-fragment access bypasses permission checks | Jenkins advisory `SECURITY-534` + core fix/test |
| P1 | CVE-2019-10377 | Jenkins Avatar Plugin | user can change another user's avatar | Jenkins advisory `SECURITY-1099` + plugin fix/test |
| P1 | CVE-2019-10409 | Jenkins Project Inheritance Plugin | missing permission check on project generation | Jenkins advisory `SECURITY-401` + plugin fix/test |

上述 A/B 训练候选的项目、描述和 NVD CWE 已在 2026-08-28 通过 NVD CVE API 2.0 逐项核对；“首选证据”仍需收集人员下载并固定具体 commit/test 后才能升级 evidence tier。B 类标签容易错配，必须同时保存 `cwe_raw_nvd`、`cwe_raw_ghsa`、`cwe_normalized_primary`、`cwe_normalized_secondary` 和 `mapping_reason`，不能仅看标题中的“IDOR”或“auth bypass”。

### 5.3 2026 Time-OOD：收集但绝不进入训练

这些近期公开、源码/patch 较清楚的案例适合作为 time-held-out 候选：

| CVE | 项目 | 类型 | 已知公开证据 |
|---|---|---|---|
| CVE-2026-57168 | OpenRemote | CWE-639/862 cross-tenant IDOR | GHSA `h3m5-97jq-qjrf` + fix commit |
| CVE-2026-44595 | Yamcs | CWE-862 user enumeration | GHSA `p2rj-mrmc-9w29` + source locations |
| CVE-2026-55548 | Yamcs | CWE-862 object-level packet access | GHSA `8xjq-pr36-ccgf` + fix commits |
| CVE-2026-15573 | Keycloak | CWE-863 path normalization bypass | GHSA `2888-g6qc-w4mj` + commit `725d8ae...` + tests |
| CVE-2026-39852 | Quarkus Keycloak Authorization | CWE-863 path normalization bypass | advisory + fix commit/test 待固化 |
| CVE-2026-41728 | Spring Data REST | improper access control in JSON Patch | GHSA `cv39-x4c6-hhp2` + releases/tests |
| CVE-2026-73644 | OpenDJ | CWE-639/285 proxy authorization scope | GHSA `p279-2cqp-84jg` + fix commit |

固定规则：任何 2026 案例即使非常好，也只能进 `time_ood_test` 或 `quarantine`，不能被 teacher 用于训练轨迹生成。

### 5.4 PoC 选择优先级

按以下顺序选择 PoC/oracle：

1. upstream regression test；
2. GHSA/厂商 advisory 中的最小复现；
3. Vul4J/Vul4J+ vulnerability-witnessing test；
4. 论文 artifact 的复现 harness；
5. 有许可证、固定 commit、明确目标版本的第三方 PoC；
6. Exploit-DB/个人博客只作发现线索，不直接入训练。

PoC 只需做到“可用于训练”的最低形式：输入、预期 vulnerable 行为、预期 fixed 行为可描述。暂时不能运行时，标记 `poc_status=available_unverified`，仍可作为 T1；不得标为 executable。

## 6. 数据应整理成什么形式

### 6.1 目录结构

```text
data/
  catalog/
    sources.jsonl              # 数据源级元数据
    candidates.jsonl           # NVD/GHSA/OSV discovered candidates
    cases.jsonl                # 归一化后的 root cases（唯一事实入口）
    rejected_cases.jsonl       # 拒绝/隔离原因
  splits/
    train.txt
    val.txt
    repo_ood_test.txt
    time_ood_test.txt
    family_ood_test.txt
  artifacts/<case_id>/
    manifest.json
    advisory/
      nvd.json
      osv.json
      ghsa.json
    patch/
      fix.patch
      introducing.patch        # 若有
    labels/
      locations.json
      proof_obligations.json
    harness/
      README.md
      setup.sh
      run.sh
      oracle.py
    receipts/
      build.json
      test.json
      static.json
      poc.json
  fetch-locks/
    repositories.lock.jsonl
  derived/
    cases.parquet
    transitions/{train,val,test}.parquet
```

默认不复制/发布第三方完整源码。保存 upstream URL、pinned commit、SHA-256、许可证与获取脚本；本地快照可放在不进入版本控制的 cache。

### 6.2 `cases.jsonl` 最小 Schema

每行一个 root case：

```json
{
  "schema_version": "1.0",
  "case_id": "ghsa-ccgv-vj62-xf9h",
  "status": "seed",
  "evidence_tier": "T1",
  "family": "source_to_sink",
  "cwe_raw_nvd": ["CWE-601"],
  "cwe_raw_ghsa": ["CWE-601"],
  "cwe_raw_other": [],
  "cwe_normalized_primary": "CWE-918",
  "cwe_normalized_secondary": ["CWE-601"],
  "mapping_reason": "validated URL is later fetched by the server",
  "mapping_evidence_urls": ["..."],
  "mapping_reviewer": "...",
  "mapping_reviewed_at": "...",
  "source_dataset": "github_advisory_database",
  "aliases": ["CVE-2024-22243", "GHSA-ccgv-vj62-xf9h"],
  "repository": {
    "url": "https://github.com/spring-projects/spring-framework",
    "upstream_id": "spring-projects/spring-framework",
    "vulnerable_commit": "...",
    "fixed_commit": "...",
    "license_spdx": "Apache-2.0"
  },
  "snapshot": {
    "vulnerable_tree_sha256": "...",
    "fixed_tree_sha256": "...",
    "fetch_lock_id": "..."
  },
  "advisory": {
    "nvd_url": "...",
    "osv_id": "...",
    "ghsa_id": "...",
    "published_at": "...",
    "fixed_at": "..."
  },
  "affected_locations": [
    {"path": "...", "symbol": "...", "start_line": 0, "end_line": 0}
  ],
  "proof": {
    "source": "...",
    "sink_or_resource": "...",
    "guard_or_authorization": "...",
    "impact": "..."
  },
  "artifacts": {
    "patch_path": "...",
    "test_paths": [],
    "poc_url": "...",
    "poc_status": "available_unverified"
  },
  "build": {"system": "gradle", "jdk": "17", "status": "not_run"},
  "dependencies": {
    "resolved_lock_sha256": "...",
    "resolved_coordinates": ["group:artifact:version"]
  },
  "capability_profile": {
    "profile_id": "...",
    "tool_versions": {"codeql": "..."},
    "available_tool_classes": ["static_query", "test_runner"],
    "build_profile_sha256": "..."
  },
  "provenance": {
    "collector": "...",
    "collected_at": "...",
    "source_urls": [],
    "content_sha256": []
  },
  "dedup": {
    "root_cause_key": "sha256:...",
    "patch_semantic_hash": "sha256:...",
    "project_family": "spring"
  },
  "split": "train",
  "split_groups": {
    "repository": "...",
    "project_family": "...",
    "patch_lineage": "...",
    "ast_clone_cluster": "...",
    "shared_dependency_cluster": "...",
    "time_bucket": "pre_2026",
    "tool_capability_bucket": "..."
  },
  "views": {
    "policy_view_path": "...",
    "oracle_view_path": "...",
    "redaction_manifest_sha256": "sha256:..."
  }
}
```

### 6.3 B 类必须额外记录

```json
{
  "authorization_model": {
    "attacker_principal": "authenticated low-privilege user",
    "victim_principal": "resource owner/admin/other tenant",
    "action": "read|update|delete|invoke",
    "resource": "object/endpoint/tenant-scoped record",
    "expected_relation": "owner|role|tenant|permission",
    "actual_check": "missing|wrong-object|wrong-role|wrong-path|fail-open",
    "observable_impact": "confidentiality|integrity|privilege|function-level"
  }
}
```

没有这组字段的 B 类样本很容易退化成“代码里有没有 `hasRole` 字符串”的分类数据。

### 6.4 轨迹格式

每个 case 必须产出两个 hash-linked views：`oracle_view` 保存 patch、advisory、gold obligations/locations；`policy_view` 只保存 snapshot、prior observations、state 和 candidate actions。训练、rollout 与 evaluation loader 只接受 `policy_view`；loader 必须拒绝 oracle-only fields，并记录 redaction-manifest SHA-256。

后续 teacher rollout 写入 `events/<episode_id>.jsonl`，并派生为 Parquet。每个 transition 必须与 `TRAINING_SPEC.yaml` 对齐：

```text
episode_id, state_version, state, candidate_actions, legal_mask,
selected_action, observation, evidence_delta, verifier_decision,
reward_vector, next_state_version, done
```

Patch、advisory label、gold trace、gold obligation 只能用于离线构造 label/oracle，不能出现在 policy 的推理输入中。

## 7. 去重与切分

稳定去重键：

```text
upstream_repo
+ root_cause_commit（未知时用 vulnerable/fixed pair）
+ normalized_CWE
+ affected_method_AST_hash
+ patch_semantic_hash
```

切分顺序：

1. 先按 fork/mirror/project family 聚组；
2. 再把 vulnerable/fixed/backport 放入同一 patch-lineage 组；
3. 2026 案例强制进入 Time-OOD；
4. 在 repository、project-family、patch-lineage、AST-clone、shared-dependency group 全部隔离后，再划分 train/val/repo-OOD；
5. 另选一个完整漏洞子族或 framework sink pattern 做 Family-OOD；
6. 按 `tool_capability_bucket` 构造 capability-shift test；
7. 统计单位使用 repository，而不是 method/transition。

禁止先随机切 method/transition 再去重，这会造成严重训练—测试泄漏。

## 8. 收集任务的执行顺序

### Wave 0：建 catalog（1–2 天）

1. 固化 Schema、状态枚举和目录；
2. 拉取 P0 数据集的 metadata，不先复制全部源码；
3. 建 CVE/GHSA/OSV alias 表和 repo canonicalization；
4. 产出第一版 `sources.jsonl`、`candidates.jsonl`。

**验收**：所有行可解析；URL、许可证、snapshot date、upstream commit 可追溯。

### Wave 1：公开集归一化（3–5 天）

1. 先处理 CWE-Bench-Java、Vul4J+、VCC-Eval；
2. 交叉 Project KB、JavaVFC、Java CVE Bench 去重；
3. 抽取目标 CWE、affected locations、patch；
4. 将 OWASP/Juliet/VulnerableApp/WebGoat 归入 T0/fixture。

**目标**：至少 140 个 T1+ 真实 root cases。

### Wave 2：定向补缺（5–10 天）

1. 优先补 B 类 80 个；
2. 再补 CWE-89/611/918；
3. 对 P0 CVE 找官方 fix/test；
4. 第三方 PoC 只下载元数据和固定版本，暂不批量执行。

**目标**：达到 260 个 train/dev T1+、80 个独立 repo，并保留足够候选供独立评测集筛选。

### Wave 3：提升可重放性（并行进行）

1. 从 train/dev 中选最易构建的至少 100 个升为 T2；
2. 另选 40 个在 repo/project-family/patch-lineage/clone/dependency/time 上与 train/dev 隔离的 T3 evaluation cases；
3. 对 T3 才制作 Docker/localhost harness 和 patched negative；
4. 保持 time-OOD 绝不参与 teacher training。

## 9. 最低质量检查

即使采用宽松训练准入，也必须自动检查：

- `case_id`、repo、commit、CWE、来源 URL 非空；
- commit/tag 在 upstream 可解析；
- patch parent/child 与 split 一致；
- fork/mirror/backport 重复检测；
- 2026 样本没有进入 train；
- T1 至少有 affected location 或可解释 proof obligation，但仅作为 trajectory seed；
- 写入 `transitions/*.parquet` 的任意 step 均具有 pinned snapshot/tool version、合法性判定、receipt 和 verifier-accepted evidence delta；
- T2 的 receipt 能重放；
- T3 的 vulnerable/fixed oracle differential 可重放；
- PoC 来源、许可证、目标版本和 payload 均已记录；
- teacher 生成文本不被写成 `Fact`。

## 10. 安全和许可底线

- 仅针对公开、授权的本地快照和 deliberately vulnerable fixtures；
- PoC 只在 localhost/隔离容器执行，默认禁用公网 egress；
- 使用 canary file、mock HTTP server、测试数据库和无害 sentinel；
- 不扫描或利用任何第三方在线实例；
- 不保存真实凭据、token、个人数据；
- 每个数据源与 PoC 单独记录 SPDX/许可证；
- 发布时默认发布 metadata、fetch lock、patch URL、harness 和 receipt，不重新分发不兼容许可的源码。

## 11. 第一批实际下载清单

按顺序开始：

```text
1. iris-sast/cwe-bench-java
2. tuhh-softsec/vul4j-plus（并交叉原 Vul4J）
3. tuhh-softsec/VCC-Eval-...
4. SAP/project-kb
5. JavaVFC 784 条人工集
6. MarkLee131/Java_CVE_Bench
7. OWASP-Benchmark/BenchmarkJava
8. NIST Juliet Java 1.3（只抽目标 CWE）
9. SasanLabs/VulnerableApp
10. WebGoat/WebGoat
11. OSV Maven + GitHub Advisory + NVD 的定向候选
```

第一批不要从全网 PoC 仓库开始。先利用公开基准和官方 patch/test 建好 catalog；只有在 B 类和 CWE-89/611/918 仍低于配额时，才定向补 PoC-CVE。

## 参考依据

- 工程训练规范：`idea-stage/TRAINING_SPEC.yaml`
- Typed audit 与证据/证书约束：`idea-stage/EVIDENCE_GUIDED_AUDIT_DESIGN.md`
- Action DSL：`idea-stage/ACTION_DSL.schema.json`
- Audit automaton：`idea-stage/AUDIT_AUTOMATON.yaml`
- 前序方案记录：`codex-session-01a03452-a615-7cc3-87cd-9c33e96f9087.md`
- CWE-Bench-Java：<https://github.com/iris-sast/cwe-bench-java>
- Vul4J+：<https://github.com/tuhh-softsec/vul4j-plus>
- Vul4J：<https://github.com/tuhh-softsec/Vul4J>
- OWASP BenchmarkJava：<https://github.com/OWASP-Benchmark/BenchmarkJava>
- VCC-Eval：<https://github.com/tuhh-softsec/VCC-Eval-A-Manually-Curated-Dataset-of-Vulnerability-Introducing-Commits-in-Java>
- SAP Project KB：<https://github.com/SAP/project-kb>
- JavaVFC：<https://zenodo.org/records/13731781>
- NVD API：<https://nvd.nist.gov/developers/vulnerabilities>
- OSV：<https://osv.dev/>
