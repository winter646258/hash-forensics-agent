# HashForensics Agent v2.3 升级书

> **升级主题**：从「演示品」到「长期可用工具」
> **四项内容**：SQLite 底座 · 字典规则引擎 · 容器口令恢复 · 参数级白名单
> **文档性质**：可交接的执行规格——新会话/新执行者拿到本文件即可独立开工，无需了解之前的对话

---

## 0. 执行者须知（先读这一节）

### 工作目录

```
C:\Users\11247\OneDrive\文档\哈希取证智能体\
```

### 现有文件（基线，勿改名）

| 文件 | 行数 | 角色 |
|---|---|---|
| `agent.py` | ≈570 | 智能体主体：感知/决策/反馈 + 审计 + 大模型理解层 |
| `toolkit.py` | ≈430 | 行动层函数库：哈希计算、校验、去重、图形密码破解、SM3 |
| `samples/` | — | 中性演示样本（hello 系列 + screening/） |
| `README.md` | — | 用户文档 |
| `LICENSE`、`.gitignore` | — | 许可证与忽略规则 |

### 硬约束（违反即返工）

1. **仅用 Python 标准库**——`sqlite3`、`zipfile`、`multiprocessing` 都是标准库，可用；
   7z/rar 需第三方库，**列入非目标**（只在文档中说明扩展路径）。
2. **不破坏现有 8 类意图的行为**——每步结束必须跑回归（见第 7 节）。
3. **保持"双理解层"架构**——规则层与 LLM 层输出同一结构，新增意图要同时登记到两处。
4. **每步独立提交**——一步一 commit，验收通过后再进下一步。
5. **不改动 `.gitignore` 已有的忽略项**（数据库文件要新增忽略，见 Step 1）。

### 交付节奏

```
Step 1 → 验收 → commit
Step 2 → 验收 → commit
Step 3 → 验收 → commit
Step 4 → 验收 → commit
Step 5 → 全量回归 → 更新文档 → 最终提交 → 推送
```

---

## 1. 目标与范围

### 目标

| # | 目标 | 解决的问题 |
|---|---|---|
| 1 | **SQLite 底座** | 当前 JSON 对照表每次查询都要全量载入内存，词表超 10 万条即不可用 |
| 2 | **字典规则引擎** | 当前只能匹配「原样明文」，命中率低；缺少变形规则 |
| 3 | **容器口令恢复** | 当前只能处理哈希，不能处理加密 zip / Office 文档 |
| 4 | **参数级白名单** | 当前只校验动作名，未限制文件路径；接 LLM 后存在提示注入读取任意文件的风险 |

### 非目标（明确排除）

- ❌ 7z / rar 支持（需 `py7zr` / `rarfile`，破坏纯标准库约束）
- ❌ GPU 加速 / hashcat 集成
- ❌ Web UI / 打包分发
- ❌ 从哈希反推原文（数学上不存在，见 README 已有说明）

---

## 2. 现状基线（v2.1）

### 已有 8 类意图

| action | 参数 | 行为 |
|---|---|---|
| `identify` | hash | 按长度/字符集判断算法类型 |
| `hash_compute` | content, algo | 正向计算，**并写入本地对照表** |
| `crack` | hash | 查表反查（对照表 → 内置库 → 图形密码全量表） |
| `verify` | path | 双哈希完整性校验 |
| `dedup` | dir | 按 SHA-256 分组去重 |
| `build_table` | file | 词表逐行导入（**当前无规则变形**） |
| `faq` | question | 内置知识库作答 |
| `crack_then_verify` | hash | 组合意图：先破解再比对 |

### 关键数据结构

```python
# agent.py 现有
TABLE_PATH = <项目目录>/hash_table.json       # JSON：{"MD5": {hex: 明文}, "SHA-256": {...}}
def load_table(): ...                          # 全量 json.load → 内存 dict
def save_table(table): ...                     # 全量覆写
def remember(plaintext, table=None): ...       # 正向计算后入表

# 大模型理解层
LLM_ACTIONS = ("identify","crack","verify","dedup","faq",
               "hash_compute","build_table","crack_then_verify")
LLM_TOOLS_SPEC = [...]                          # 工具清单（JSON）
LLM_PROMPT = "..."                              # few-shot 提示词
```

### 当前性能与资源

| 指标 | 现值 |
|---|---|
| 对照表容量上限 | ~10 万条（JSON 全量载入，内存随规模线性增长） |
| 内存峰值 | 89.6 MB（图形密码全量表那 3 秒），日常 30 MB |
| 单条查询 | O(1) dict，但**前置成本是全表载入** |
| 字典变形 | 无 |
| 容器口令 | 不支持 |

---

## 3. 目标架构

```
                    ┌──────────────────────────────────┐
你的话 ────────────→ │ ① 感知层  LLM function calling   │
                    │          或 正则规则表（兜底）    │
                    └───────────────┬──────────────────┘
                                    ↓
                    ┌──────────────────────────────────┐
                    │ ② 决策层  意图路由               │
                    └───────────────┬──────────────────┘
                                    ↓
      ┌─────────────────────────────┴─────────────────────────────┐
      ↓                             ↓                             ↓
┌─────────────┐            ┌─────────────┐              ┌─────────────┐
│ ③a 安全层   │←── 所有文件类意图先过 ──│ ③b 行动层  │              │ ③c 知识层   │
│ sandbox.py  │            │ toolkit.py  │              │ FAQ         │
│ 路径白名单   │            │ +新增三个模块 │              └─────────────┘
└─────────────┘            └──────┬──────┘
                                  ↓
                    ┌─────────────────────────────┐
                    │ ④ 存储层  db.py (SQLite)     │
                    │   hash_index 表 + WAL        │
                    └─────────────────────────────┘
                                  ↓
                    ┌─────────────────────────────┐
                    │ ⑤ 反馈层  结果+审计日志      │
                    └─────────────────────────────┘
```

**新增 4 个模块**（全部新建文件，不改动 toolkit 既有函数）：

```
db.py           SQLite 存储层
rules.py        字典规则引擎
containers.py   容器口令恢复
sandbox.py      路径白名单
```

---

## 4. 分步实施计划

### Step 1 · SQLite 底座（1.5h 编码 + 0.5h 测试）

**目标**：把对照表从 JSON 迁移到 SQLite，内存占用与表规模解耦。

**改动文件**
- 新建 `db.py`
- 改 `agent.py`：`load_table/save_table/remember` 改为调用 `db.py`；保留 JSON 兼容
- 改 `.gitignore`：新增 `*.db`、`*.db-wal`、`*.db-shm`

**数据库设计**

```sql
PRAGMA journal_mode = WAL;          -- 并发读不阻塞
PRAGMA synchronous = NORMAL;        -- 牺牲极小安全性换吞吐
PRAGMA temp_store = MEMORY;
PRAGMA cache_size = -8000;          -- 8MB 页缓存（固定，不随表增长）

CREATE TABLE IF NOT EXISTS hash_index (
  algo       TEXT NOT NULL,         -- 'MD5' | 'SHA-256'
  digest     BLOB NOT NULL,         -- 二进制摘要：MD5=16字节，SHA-256=32字节
  plaintext  TEXT NOT NULL,
  source     TEXT,                  -- 'compute' | 'wordlist:<文件名>' | 'import'
  created_at TEXT,
  PRIMARY KEY (algo, digest)
) WITHOUT ROWID;                    -- 聚簇索引，查询更快、体积更小

CREATE INDEX IF NOT EXISTS idx_plaintext ON hash_index(plaintext);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
```

> **关键优化**：摘要存 `BLOB`（16/32 字节）而非十六进制文本（32/64 字符），
> 磁盘占用省约 30%，查询也更快。对外仍暴露 hex 字符串接口。

**对外 API**

```python
DB_PATH = os.environ.get("HFA_DB_PATH") or os.path.join(_HERE, "hash_index.db")

def connect() -> sqlite3.Connection            # 建表、设 PRAGMA
def remember(plaintext, source="compute") -> int
def lookup(algo, digest_hex) -> str | None     # 未命中返回 None
def import_wordlist(path, algos=("MD5","SHA-256"), rules=None, source=None) -> dict
def stats() -> dict                            # {'MD5': n, 'SHA-256': n, 'size_mb': x}
def migrate_from_json(json_path) -> int        # 迁移旧表，成功后重命名 .migrated.bak
```

**迁移逻辑**：启动时若 `hash_table.json` 存在且 `hash_index` 为空 → 自动迁移 → 原文件改名备份。

**验收标准**

```
□ python -c "import db; db.connect()" 无报错
□ 迁移：旧 JSON 全部条目进入 hash_index，条数一致
□ remember('062481') → lookup('MD5', md5_hex) 返回 '062481'
□ 导入 10 万条后：进程内存峰值 < 100MB（对比：JSON 方案此时已 ~300MB）
□ 单条查询 < 10ms，且与表规模无关
□ 现有 8 类意图回归全绿
```

**提交信息**
```
feat(db): 对照表迁移至 SQLite，内存占用与表规模解耦

- 新增 db.py：hash_index 表（BLOB 摘要 + WITHOUT ROWID）、WAL 模式
- 摘要以二进制存储，磁盘占用省约 30%
- 支持旧 hash_table.json 自动迁移并备份
- agent.py 的 load/save/remember 改为薄封装，外部行为不变
```

---

### Step 2 · 字典规则引擎（2h + 0.5h 测试）

**目标**：从「明文原样匹配」升级为「明文 + 常见变形」，显著提高弱口令命中率。

**改动文件**
- 新建 `rules.py`
- 改 `agent.py`：`build_table` 意图支持规则档位

**规则档位**

| 档位 | 规则集 | 单条扩充倍数 |
|---|---|---|
| `min` | 原名、小写、大写、首字母大写 | ×4 |
| `std`（默认） | min + 后缀 0-9/00-99/年份 1980-2030 + 常见符号后缀 | ×60 |
| `max` | std + leet 替换 + 反转 + 前缀数字 + 双词拼接 | ×500+ |

**接口**

```python
def variants(word: str, level: str = "std") -> Iterator[str]
# 流式生成，不一次性构造全部变体（控制内存）
LEVELS = ("min", "std", "max")
```

**流式导入管道**（内存恒定）

```
读一行词表 → 生成变体 → 计算 MD5/SHA-256 → 批量插入（每 1 万条一事务）
                              ↓
                        可选：多进程分片加速
```

**性能预期**：单进程约 20~50 万次/秒（hashlib 为 C 实现）；
rockyou 1400 万条 × `std` 档 ≈ 8.4 亿次，需 30~70 分钟（`min` 档 ≈ 3~8 分钟）。

**验收标准**

```
□ variants("password","min") 返回 4 个；("password","std") 含 "password123"、"password2026"
□ 导入 1 万条词表 × std 档，内存峰值 < 150MB
□ 命中率对比：对同一批测试哈希，std 档命中数 > 裸字典命中数
□ 断点续传：重复导入同一词表不产生重复行（PRIMARY KEY 保证）
□ 现有意图回归全绿
```

**提交信息**
```
feat(rules): 新增字典规则引擎，支持三档变形

- rules.py：原名/大小写/数字后缀/年份/符号/leet/反转等规则，流式生成
- build_table 意图支持 --rules min|std|max，默认 std
- 批量事务插入，万级词表内存峰值 < 150MB
- 多进程分片作为可选加速路径
```

---

### Step 3 · 参数级白名单（1h + 0.5h 测试）

**目标**：把「能做哪些动作」的控制升级为「能碰哪些文件」，关闭提示注入的路径风险面。

**改动文件**
- 新建 `sandbox.py`
- 改 `agent.py`：所有文件类意图（`verify` / `dedup` / `build_table` / Step 4 的容器意图）先过沙箱

**设计**

```python
ALLOWED_ROOTS = [
    <项目目录>,
    <项目目录>/samples,
] + (env HFA_ALLOWED_ROOTS 以 ; 或 os.pathsep 分隔的额外目录)

def resolve_safe(path: str) -> str     # 规范化绝对路径；越界抛 PathDenied
def is_allowed(path: str) -> bool
class PathDenied(Exception): ...

DENY_PATTERNS = ["..", 系统目录前缀, 用户主目录下的敏感目录]
```

**要点**
- 用 `os.path.realpath` 解析，防符号链接绕过
- 路径比较统一大小写（Windows）
- 拒绝时：返回明确提示 + 写审计日志（`action="denied"`, `ok=false`）
- 允许显式放行：环境变量配置可信目录，不硬编码用户路径

**验收标准**

```
□ 校验 samples/hello.txt → 通过
□ 校验 C:\Windows\System32\drivers\etc\hosts → 被拒绝并说明原因
□ 校验 ..\..\别的目录\文件.txt → 被拒绝
□ 审计日志出现 action="denied" 记录
□ 通过 HFA_ALLOWED_ROOTS 环境变量添加目录后，该目录可访问
□ 现有意图回归全绿
```

**提交信息**
```
feat(sandbox): 参数级路径白名单，关闭提示注入的任意文件读取面

- sandbox.py：realpath 规范化 + 前缀校验 + 拒绝模式
- 所有文件类意图先过沙箱，拒绝时写审计日志
- 可信目录通过 HFA_ALLOWED_ROOTS 环境变量配置，不硬编码本机路径
```

---

### Step 4 · 容器口令恢复（2h + 1h 测试）

**目标**：从「算哈希」扩展到「解加密容器」，支持 zip 与 Office 文档。

**改动文件**
- 新建 `containers.py`
- 改 `agent.py`：新增 `crack_container` 意图

**设计**

```python
def is_encrypted(path) -> bool                    # zip 标志位 & 0x1
def crack_zip(path, candidates, max_attempts=None, progress=True) -> str | None
# candidates 来源（按顺序）：
#   ① db.lookup 中的全部明文（SELECT DISTINCT plaintext）
#   ② rules.variants 对 ① 的变形
#   ③ 内置小词表
# Office（docx/xlsx/pptx）本质是 zip，走同一路径
def crack_7z_or_rar(path, ...): raise NotImplementedError(给出扩展指引)
```

**意图登记**（两处都要加，这是硬约束）

```python
# 规则层：perceive()
"破解 zip secret.zip" / "打开加密压缩包 secret.zip" → crack_container

# LLM 层
LLM_ACTIONS 增加 "crack_container"
LLM_TOOLS_SPEC 增加 {"action":"crack_container","params":["path"],"desc":"..."}
LLM_PROMPT 增加一条示例
```

**性能说明**（诚实标注）

| 格式 | 标准库支持 | 速度 | 可用性 |
|---|---|---|---|
| zip | ✅ `zipfile` | 数百~数千次/秒（Python 层） | 小字典秒级，大字典分钟级 |
| Office | ✅（即 zip） | 同上 | 同上 |
| 7z / rar | ❌ | — | 文档说明扩展路径 |

**验收标准**

```
□ 用系统工具创建加密 zip（口令放字典内）→ crack_container 命中并输出口令
□ 口令不在字典 → 明确返回未命中 + 建议（扩大字典/上规则档位）
□ 加密 Office 文档同样可解
□ 未加密 zip → 提示"该容器未加密"，不浪费算力
□ 7z/rar → 提示需第三方库，附安装建议
□ 现有意图回归全绿
```

**提交信息**
```
feat(containers): 支持加密 zip / Office 口令恢复

- containers.py：zipfile 逐口令尝试，Office（zip 容器）同路径处理
- 候选口令来自 SQLite 明文 + 规则变形 + 内置词表
- 7z/rar 明确列为非目标并给出扩展指引
- 新增 crack_container 意图（规则层与 LLM 层同步登记）
```

---

### Step 5 · 整合与发布（0.5h + 文档 0.5h）

**改动**
- `agent.py`：新增 `db_stats` 意图（"表里有多少条"），BANNER 版本号 → v2.3
- `README.md`：新增 4 节——数据库、字典规则、容器口令、安全沙箱
- `ROADMAP.md`（若项目内无此文件则新建）：勾掉 v2.2~v2.6，标注 v3.0 规划
- 全量回归 + 性能基准表复测

**最终验收**
```
□ 全部 10 类意图（原 8 + crack_container + db_stats）通过
□ 内存/磁盘/速度基准与第 6 节预算表一致
□ README 新增章节齐全
□ git log 显示 5 次清晰提交
□ 推送后从 GitHub 全新克隆，跑通回归
```

**提交信息**
```
docs: 发布 v2.3 —— SQLite 底座 + 规则引擎 + 容器口令 + 路径沙箱

- README 新增数据库、字典规则、容器口令、安全沙箱四节
- ROADMAP 更新至 v2.3，标注 v3.0 多步规划
- 全量回归通过，性能基准复测完成
```

---

## 5. 回归测试清单（每步结束必跑）

```powershell
cd "C:\Users\11247\OneDrive\文档\哈希取证智能体"
$env:PYTHONIOENCODING = "utf-8"

# ① 编译
python -m py_compile agent.py toolkit.py db.py rules.py sandbox.py containers.py

# ② 演示模式（10+ 句预设对话）
python agent.py demo

# ③ 意图路由回归（应 10/10 通过）
python -c "import sys; sys.argv=['agent.py']; sys.path.insert(0,'.'); import agent; \
tests=['这是什么哈希 e10adc3949ba59abbe56e057f20f883e','加密：062481，sha-256', \
'校验 hello.txt','对 screening 去重','为什么要双哈希']; \
print(sum(agent.decide_act(*agent.perceive_any(t))['ok'] for t in tests), '/', len(tests))"

# ④ 端到端闭环（加密→查表命中）
python -c "import sys; sys.argv=['agent.py']; sys.path.insert(0,'.'); import agent; \
r1=agent.step('加密：062481，md5'); r2=agent.step('解密 '+r1['result']); \
print('闭环', 'OK' if r2['result']=='062481' else 'FAIL')"
```

**必须保持不变的既有行为**（回归红线）

1. `校验 hello.txt` → 一致，未篡改
2. `对 screening 去重` → 1 组重复
3. 图形密码 SHA-1 → 命中 `0-1-4-7-6`
4. bcrypt → 主动劝退（不尝试爆破）
5. 无 `LLM_API_KEY` 时自动降级规则层，服务不中断

---

## 6. 资源预算

### 时间

| 步骤 | 编码 | 测试 | 小计 |
|---|---:|---:|---:|
| Step 1 SQLite | 1.5h | 0.5h | 2h |
| Step 2 规则引擎 | 2h | 0.5h | 2.5h |
| Step 3 白名单 | 1h | 0.5h | 1.5h |
| Step 4 容器口令 | 2h | 1h | 3h |
| Step 5 整合文档 | 0.5h | 0.5h | 1h |
| **合计** | **7h** | **3h** | **10h**（约 1.5 个工作日） |

### 内存（关键结论：升级后内存不涨，反而更稳）

| 组件 | 升级前 | 升级后 |
|---|---|---|
| 对照表 | 全量载入，**随规模线性增长**（10 万条≈30MB，1400 万条≈2~3GB） | SQLite 页缓存 **固定 ~8MB** |
| 字典引擎 | — | 流式，**不驻留** |
| 容器口令 | — | 单次尝试，**几十 KB** |
| 白名单 | — | 字符串比较，**≈0** |
| **进程峰值** | 89.6MB（全量表瞬间） | **仍 30~90MB** |

### 磁盘

| 场景 | 占用 | 存放建议 |
|---|---|---|
| 仅日常累积 | < 10MB | 项目目录内即可 |
| rockyou 单索引（MD5） | ~1.0GB | `D:\` |
| rockyou 双索引（MD5+SHA-256，BLOB 优化后） | **~1.5~1.8GB** | `D:\`，**勿放 OneDrive 目录** |
| 数据库路径 | 由 `HFA_DB_PATH` 环境变量指定 | 建议 `D:\HashForensicsDB\` |

> **注意**：项目在 OneDrive 同步目录内。数据库请通过 `HFA_DB_PATH` 指到 `D:\`，
> 避免云同步造成大量流量与占用 C 盘空间。

### CPU

- 字典导入：单进程 20~50 万次/秒（hashlib 为 C 实现，瓶颈在 Python 循环）
- 可选多进程分片可近似线性加速（按 CPU 核心数）
- 容器口令：数百~数千次/秒（Python zipfile 层层调用，属预期）

---

## 7. 风险与回滚

| 风险 | 影响 | 应对 |
|---|---|---|
| 迁移丢数据 | 对照表损坏 | 迁移前自动备份 `hash_table.json` → `.migrated.bak`；迁移后再校验条数 |
| SQLite 并发锁 | WAL 模式下偶发 `database is locked` | 设 `busy_timeout=5000`；单进程写入 |
| 规则档位选择过大 | 导入耗时爆炸 | `max` 档需显式确认；导入前打印预估条数 |
| 白名单过严 | 正常路径被拒 | 提供 `HFA_ALLOWED_ROOTS` 环境变量；拒绝信息里说明如何添加 |
| 容器口令功能被误用 | 合规风险 | 意图只接受本地文件；README 与横幅重申"仅限授权样本" |
| 大数据库污染仓库 | 仓库体积爆炸 | `.gitignore` 忽略 `*.db*`；提交前检查 `git status` |

**通用回滚**：每步一次独立提交，任一步验收失败 → `git reset --hard <上一步>` 即可退回。

---

## 8. 交付清单

**新增文件**
```
db.py             SQLite 存储层
rules.py          字典规则引擎
sandbox.py        路径白名单
containers.py     容器口令恢复
```

**修改文件**
```
agent.py          接入四个模块；新增 2 类意图（crack_container、db_stats）；版本号 v2.3
.gitignore        新增 *.db、*.db-wal、*.db-shm
README.md         新增四节文档
ROADMAP.md        v2.2~v2.6 标为完成
```

**意图总表（升级后 10 类）**

| # | action | 说明 |
|---|---|---|
| 1 | identify | 识别哈希类型 |
| 2 | hash_compute | 正向计算并入库 |
| 3 | crack | 查表反查 |
| 4 | verify | 完整性校验 |
| 5 | dedup | 内容去重 |
| 6 | build_table | 词表导入（支持规则档位） |
| 7 | faq | 知识问答 |
| 8 | crack_then_verify | 组合意图 |
| 9 | **crack_container** | **容器口令恢复（新）** |
| 10 | **db_stats** | **数据库统计（新）** |

**Git 提交序列**
```
feat(db): 对照表迁移至 SQLite，内存占用与表规模解耦
feat(rules): 新增字典规则引擎，支持三档变形
feat(sandbox): 参数级路径白名单，关闭提示注入的任意文件读取面
feat(containers): 支持加密 zip / Office 口令恢复
docs: 发布 v2.3 —— SQLite 底座 + 规则引擎 + 容器口令 + 路径沙箱
```

---

## 9. 一句话验收

> 升级完成后，agent 应当能**导入千万级词表而不爆内存**、
> **用规则变形提高弱口令命中率**、**解开加密 zip 的口令**、
> **拒绝任何越界的文件访问**——同时现有 8 类意图行为一字不变。
