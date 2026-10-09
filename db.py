#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db.py —— HashForensics Agent 存储层（SQLite 底座，v2.3 · Step 1）
================================================================================
把「哈希 → 明文」对照表从 hash_table.json 迁到 SQLite：

  * 内存与表规模解耦：页缓存固定 ~8MB（cache_size=-8000），不再全量载入内存
  * 摘要存二进制 BLOB（MD5=16 字节 / SHA-256=32 字节），比 hex 文本省约 30% 磁盘
  * WITHOUT ROWID 聚簇主键 (algo, digest)：等值查询走 B 树，耗时与表规模无关
  * WAL + busy_timeout=5000：并发读不阻塞，偶发数据库锁自动等待重试

对外 API（agent.py 只依赖这些）：
  connect()                                     建表 + 设 PRAGMA，返回连接
  remember(plaintext, source="compute")         正向算 MD5+SHA-256 入库，返回新增行数
  lookup(algo, digest_hex)                      按 hex 摘要反查明文，未命中返回 None
  import_wordlist(path, algos, rules, source)   词表逐行导入（批量事务，内存恒定）
                                                rules=min|std|max 走 Step 2 规则引擎
  stats()                                       各算法条数 + 磁盘占用
  migrate_from_json(json_path)                  迁移旧 JSON 表，成功后原文件改名 .migrated.bak
  load_view()                                   兼容 agent.py 旧 dict 语义的惰性视图

数据库路径：环境变量 HFA_DB_PATH 优先，默认项目目录下 hash_index.db。
依赖：仅 Python 标准库。
"""
import hashlib
import json
import os
import sqlite3
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))

# 数据库路径（import 时的快照，供外部引用）。实际连接路径由 _resolve_path() 每次解析：
# 显式参数 > 环境变量 HFA_DB_PATH > 默认项目目录下 hash_index.db。
DB_PATH = os.environ.get("HFA_DB_PATH") or os.path.join(_HERE, "hash_index.db")

# 旧表迁移：坏条目占比阈值。≤ 阈值 → 好数据入库 + 坏条目隔离；> 阈值 → 整批放弃。
MIGRATE_SKIP_RATIO = 0.05
# 隔离明细最多保留多少条（防止坏条目极多时 meta 膨胀；总数另记 migrate_skipped_total）
MIGRATE_SKIP_DETAIL_MAX = 500

# 旧 JSON 表的文件名与默认位置（仅迁移时使用；迁移成功后改名 .migrated.bak）
JSON_NAME = "hash_table.json"
JSON_TABLE_PATH = os.path.join(_HERE, JSON_NAME)

DEFAULT_ALGOS = ("MD5", "SHA-256")   # 正向计算默认双索引
BATCH = 10000                        # 批量事务条数：内存恒定，不随词表大小增长
FLUSH_EVERY = 2000                   # 视图写入缓冲阈值（防止调用方一边写一边撑内存）
BASE_CACHE_KB = 8000                 # 稳态页缓存 8MB（Step 1 设计：不随表规模增长）
BULK_CACHE_KB = 32000                # 导入期临时页缓存 32MB（见 _bulk_tuning 注释）
WORKER_LIMIT = 8                     # 多进程导入的最大子进程数（再多就只是抢磁盘了）
CHUNK = 20000                        # 多进程分片的最大原始行数
TARGET_TASK_ROWS = 50000             # 每个子进程任务的回传行数上限（控制 pickle 体积）
BASE_AUTOCHECKPOINT = 8000           # 稳态 WAL 自动检查点（Step 1 的调优值）
BULK_AUTOCHECKPOINT = 32000          # 导入期放宽自动检查点（见 _bulk_tuning 注释）
PARALLEL_MIN_VARIANTS = 200000       # 候选变体超过这个量才值得起进程池（建池约 0.3 秒）

_HASHERS = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
}
_DIGEST_SIZE = {"MD5": 16, "SHA-1": 20, "SHA-256": 32, "SHA-512": 64, "SM3": 32}

_SQL_INSERT = ("INSERT OR IGNORE INTO hash_index(algo, digest, plaintext, source, created_at) "
               "VALUES(?, ?, ?, ?, ?)")
_SQL_UPSERT = ("INSERT OR REPLACE INTO hash_index(algo, digest, plaintext, source, created_at) "
               "VALUES(?, ?, ?, ?, ?)")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hash_index (
  algo       TEXT NOT NULL,         -- 'MD5' | 'SHA-256'（也容纳 SHA-1/SHA-512/SM3）
  digest     BLOB NOT NULL,         -- 二进制摘要：MD5=16 字节，SHA-256=32 字节
  plaintext  TEXT NOT NULL,
  source     TEXT,                  -- 'compute' | 'wordlist:<文件名>' | 'import'
  created_at TEXT,
  PRIMARY KEY (algo, digest)
) WITHOUT ROWID;                    -- 聚簇索引：查询更快、体积更小

CREATE INDEX IF NOT EXISTS idx_plaintext ON hash_index(plaintext);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

# 模块级连接缓存：进程内复用同一个连接（= 同一份 8MB 页缓存，不重复占用）
_CONN = None
_CONN_PATH = None
_RULES_MOD = None      # Step 2 规则引擎的惰性缓存（不传 rules 就不导入 rules.py）


# ---------------------------------------------------------------- 工具
def normalize_algo(algo):
    """算法名归一化：md5 / sha256 / SHA_256 → MD5 / SHA-256。"""
    s = str(algo or "").strip().upper().replace("_", "-").replace(" ", "")
    if s.startswith("SHA") and not s.startswith("SHA-"):
        s = "SHA-" + s[3:]
    return s or "MD5"


def _to_blob(digest_hex):
    """hex 文本 → 二进制 BLOB。非法输入返回 None（不是异常：查表未命中是常态）。"""
    if isinstance(digest_hex, (bytes, bytearray)):
        return bytes(digest_hex)
    if not isinstance(digest_hex, str):
        return None
    s = digest_hex.strip()
    if not s or len(s.replace(" ", "")) % 2:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def _check(algo, blob):
    """摘要长度自检：把"存错长度"这种静默错误挡在写入前。"""
    n = _DIGEST_SIZE.get(algo)
    if n is not None and len(blob) != n:
        raise ValueError("%s 摘要应为 %d 字节，实际 %d 字节" % (algo, n, len(blob)))


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- 连接 / 建表
def _resolve_path(path=None):
    """解析数据库路径：显式参数 > 环境变量 HFA_DB_PATH > 默认项目目录。

    每次调用都重读环境变量，符合"环境变量优先"的直觉——import 之后再设
    HFA_DB_PATH 也照样生效（旧实现只在 import 时读一次，改 env 无效）。
    """
    return os.path.abspath(path or os.environ.get("HFA_DB_PATH")
                           or os.path.join(_HERE, "hash_index.db"))


def connect(path=None):
    """建立（并缓存）数据库连接：建表 + 设 PRAGMA。重复调用返回同一连接。

    路径每次重新解析：显式参数 > HFA_DB_PATH > 默认。目标路径与缓存连接不一致时
    自动切换连接（用于测试与运行中切换数据库）。
    """
    global _CONN, _CONN_PATH
    target = _resolve_path(path)
    if _CONN is not None and _CONN_PATH == target:
        return _CONN
    if _CONN is not None:            # 换路径：先关掉旧连接
        close()
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)   # 支持 HFA_DB_PATH 指向尚不存在的目录
    conn = sqlite3.connect(target, timeout=5.0, isolation_level=None)  # autocommit：PRAGMA 与显式事务都好使
    conn.execute("PRAGMA journal_mode = WAL")     # 并发读不阻塞
    conn.execute("PRAGMA synchronous = NORMAL")   # 牺牲极小安全性换吞吐
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA cache_size = -8000")     # 8MB 页缓存（固定，不随表增长）
    conn.execute("PRAGMA busy_timeout = 5000")    # 偶发锁等待 5 秒再报错
    # 额外调优（文档 PRAGMA 清单之外的补充项，见提交说明）：
    # 默认 autocheckpoint=1000 页（约 4MB），批量导入时每 1 万条一 commit 就会触发回写，
    # 同一批页被反复擦写——实测导入 20 万行因此多花约 1.5 倍时间。放到 8000 页
    # （约 32MB，仍有界）后导入 2.51s → 1.66s。WAL 体积上限仍可控。
    conn.execute("PRAGMA wal_autocheckpoint = 8000")
    conn.executescript(_SCHEMA)
    _CONN, _CONN_PATH = conn, target
    outcome = _auto_migrate(conn)    # 启动时：旧 JSON 存在且表为空 → 自动迁移
    if outcome:                      # 有跳过/失败才发声；正常迁移保持静默
        _warn_migration(outcome)
    return conn


def _conn():
    return _CONN if _CONN is not None else connect()


def close():
    """关闭缓存的连接（测试/基准用；正常使用无需调用）。"""
    global _CONN, _CONN_PATH
    if _CONN is not None:
        try:
            _CONN.close()
        finally:
            _CONN, _CONN_PATH = None, None


def db_path():
    return _CONN_PATH or _resolve_path(None)


def flush():
    """提交未落盘的事务（WAL 下为轻量操作）。"""
    if _CONN is not None:
        _CONN.commit()


def _insert_many(rows, sql=_SQL_INSERT):
    """批量写入：显式事务包裹。返回本次写入的变更行数。

    两个实现要点：
    ① 连接是 autocommit（isolation_level=None），不显式开事务的话 executemany 会退化成
       「逐条 INSERT 各自提交」——每条一次 fsync，导入 20 万行要三十秒。
    ② 计数用 `conn.total_changes` 前后差值。`rowcount` 在批量插入下同样可靠（实测一致），
       但对 `INSERT OR REPLACE` 两者都会把"同键替换"计为变更、而表内并未新增行。
       故本函数返回值只表示"写了多少次"，**不能**当作"表内条数增量"用——
       需要条数的地方一律回查 `count(algo)`（迁移校验就是这么做的）。
    """
    if not rows:
        return 0
    conn = _conn()
    before = conn.total_changes
    try:
        conn.execute("BEGIN")
        for i in range(0, len(rows), BATCH):
            conn.executemany(sql, rows[i:i + BATCH])
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return conn.total_changes - before


# ---------------------------------------------------------------- 写入 / 查询
class _bulk_tuning(object):
    """导入期临时放大页缓存的上下文管理器（Step 2 性能补充）。

    为什么需要：摘要 BLOB 近似随机分布，WITHOUT ROWID 聚簇主键的插入会随机触碰
    B 树页；Step 1 固定的 8MB 缓存（cache_size=-8000）在库涨到几百 MB 后命中率极低，
    每次插入近乎一次随机页读。实测导入 84 万行：
        8MB / synchronous=NORMAL  → 66.0 秒（12.7k 行/秒）
        32MB / synchronous=NORMAL → 46.0 秒（18.3k 行/秒）  峰值 RSS 66.9MB
    取 32MB 而非更大的 64/128MB：32MB 已拿到主要收益，且峰值 RSS 稳稳落在
    升级书第 6 节「30~90MB」预算内（64MB → 102MB、128MB → 169MB 会顶破预算）。

    **不关闭 synchronous**：sync=OFF 再快 1.5 倍，但代价是断电/崩溃可能损坏整个
    数据库文件；口令对照表重算成本极高，这个赌注不值当。

    退出时恢复 8MB 稳态缓存——"页缓存固定"仍是本模块的常态，放大只发生在导入期间。
    """

    def __init__(self, cache_kb=BULK_CACHE_KB):
        self.cache_kb = cache_kb
        self.conn = None

    def __enter__(self):
        self.conn = _conn()
        self.conn.execute("PRAGMA cache_size = %d" % (-self.cache_kb,))
        self.conn.execute("PRAGMA wal_autocheckpoint = %d" % (BULK_AUTOCHECKPOINT,))
        return self.conn

    def __exit__(self, *exc):
        try:
            self.conn.execute("PRAGMA cache_size = -%d" % (BASE_CACHE_KB,))
            self.conn.execute("PRAGMA wal_autocheckpoint = %d" % (BASE_AUTOCHECKPOINT,))
        except Exception:
            pass
        return False


def _checkpoint(conn):
    """把 WAL 收回主库文件（导入收尾用）。失败不影响导入结果，只是磁盘可能偏大。"""
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return True
    except Exception:
        return False


def remember(plaintext, source="compute"):
    """正向算 MD5 + SHA-256 并写入 hash_index。返回实际新增的行数（重复条目计 0）。"""
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    data = plaintext.encode("utf-8")
    ts = _now()
    rows = [(a, _HASHERS[a](data).digest(), plaintext, source, ts) for a in DEFAULT_ALGOS]
    return _insert_many(rows)


def lookup(algo, digest_hex):
    """按 hex 摘要反查明文；未命中返回 None。等值查询走聚簇主键，与表规模无关。"""
    blob = _to_blob(digest_hex)
    if blob is None:
        return None
    row = _conn().execute(
        "SELECT plaintext FROM hash_index WHERE algo = ? AND digest = ?",
        (normalize_algo(algo), blob)).fetchone()
    return row[0] if row else None


def put(algo, digest_hex, plaintext, source="compute", replace=True):
    """写入一条（hex 摘要入参）。返回受影响行数（0 = 已存在且未替换）。

    摘要长度与算法不符时直接返回 0（宽容落盘，不打断调用方）。
    """
    blob = _to_blob(digest_hex)
    if blob is None:
        return 0
    a = normalize_algo(algo)
    n = _DIGEST_SIZE.get(a)
    if n is not None and len(blob) != n:
        return 0
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    row = (a, blob, plaintext, source, _now())
    conn = _conn()
    cur = conn.execute(_SQL_UPSERT if replace else _SQL_INSERT, row)
    n_rows = cur.rowcount or 0
    conn.commit()
    return n_rows


def count(algo=None):
    """条数统计；algo=None 时返回总行数。"""
    conn = _conn()
    if algo is None:
        return conn.execute("SELECT COUNT(*) FROM hash_index").fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM hash_index WHERE algo = ?",
                        (normalize_algo(algo),)).fetchone()[0]


def _estimate_variants(path, level, sample=64, limit=None):
    """估算词表在给定档位下的变体总数（导入前预估，回答"这条命令要写多少行"）。

    抽样 ``sample`` 条有效行求平均，再乘总行数——避免为了报个数把整表展开一遍
    （max 档 ×800，全表展开一次就是纯浪费）。词表短于 sample 时全量精确计数。
    """
    if level is None:
        return _count_wordlist(path, limit)
    mod = _load_rules()
    texts, total = [], _count_wordlist(path, limit)
    if total == 0:
        return 0
    with open(path, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            texts.append(line.decode("utf-8", errors="replace"))
            if len(texts) >= sample:
                break
    if not texts:
        return 0
    if total <= len(texts):                      # 短词表：精确
        return sum(mod.count_variants(t, level) for t in texts)
    avg = sum(mod.count_variants(t, level) for t in texts) / float(len(texts))
    return int(round(avg * total))


def _plan_tasks(path, level, limit=None):
    """把词表切成若干任务，且**不让单个任务的回传体积过大**。

    关键：max 档单条约 ×800，fixed 行数分片会让一个任务回传几十万行、
    pickle 一大块内存。这里按"估算变体数"折算每个任务该分多少原始行：
    目标每任务 ≤ TARGET_TASK_ROWS 个候选明文，行数再被 CHUNK 封顶。
    任务数由数据量决定（多于进程数才能让 worker 之间负载均衡）。
    """
    total = _count_wordlist(path, limit)
    if total == 0:
        return []
    est = max(_estimate_variants(path, level, limit=limit), 1)
    rows_per_task = max(1, min(CHUNK, TARGET_TASK_ROWS * total // est))
    n = max(1, -(-total // rows_per_task))       # 向上取整
    tasks, start = [], 0
    for _ in range(n):
        if start >= total:
            break
        tasks.append((start, rows_per_task))
        start += rows_per_task
    return tasks


def _load_rules():
    """惰性导入 Step 2 的规则引擎。rules.py 缺失时给出明确中文错误，不静默降级。

    惰性导入的好处：不传 rules 时 rules.py 不参与、也不影响旧调用方的加载时间。
    """
    global _RULES_MOD
    if _RULES_MOD is None:
        try:
            import rules as _rules
        except ImportError as exc:
            raise ImportError("规则档位需要同目录的 rules.py（Step 2 模块）：%s" % exc)
        _RULES_MOD = _rules
    return _RULES_MOD


def _normalize_level(rules):
    """rules 参数归一化：None/''/raw → 裸字典 None；否则返回校验过的档位名。

    Step 1 里传非空值会抛 NotImplementedError；Step 2 起真正接上 rules.variants。
    档位非法仍抛 ValueError——不静默降级，免得用户以为跑了 std 其实只跑了裸字典。
    """
    if rules is None or rules is False or rules == "":
        return None
    if rules is True:
        return _load_rules().DEFAULT_LEVEL
    if not isinstance(rules, str):
        raise ValueError("rules 应为 min/std/max 或 None，收到 %r" % (rules,))
    lv = rules.strip().lower()
    if lv in ("none", "raw", "off", "0"):
        return None
    mod = _load_rules()
    if lv not in mod.LEVELS:
        raise ValueError("未知规则档位 %r（可选：%s）" % (rules, " / ".join(mod.LEVELS)))
    return lv


def _resolve_processes(processes):
    """解析 processes 参数：None/0/1 → 单进程；'auto' → min(CPU 核数, WORKER_LIMIT)。"""
    if processes in (None, 0, 1, "1"):
        return 1
    if isinstance(processes, str):
        s = processes.strip().lower()
        if s in ("auto", "true", "yes", "on"):
            return max(1, min(os.cpu_count() or 1, WORKER_LIMIT))
        try:
            processes = int(s)
        except ValueError:
            raise ValueError("processes 应为整数或 'auto'，收到 %r" % (processes,))
    n = int(processes)
    if n < 1:
        return 1
    return min(n, 64)                      # 上限兜底，防止手滑传 9999


def _count_wordlist(path, limit=None):
    """数一遍词表有多少条有效行（空行不计）——多进程分片边界与进度用。

    相对哈希计算这是极廉价的一次遍历（1 万行约几毫秒）。
    """
    n = 0
    with open(path, "rb") as f:
        for raw in f:
            if raw.rstrip(b"\r\n"):
                n += 1
                if limit and n >= limit:
                    break
    return n


def _iter_lines(path, limit=None):
    """流式读词表：逐行 yield (序号, 原始字节, 文本)，空行跳过。内存恒定。"""
    i = 0
    with open(path, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            i += 1
            yield i, line, line.decode("utf-8", errors="replace")
            if limit and i >= limit:
                return


def _hash_rows(words, algos, src, ts):
    """候选明文（bytes）→ 待插入行。返回 (rows, 候选条数)。

    批内按 (algo, digest) 再去一次重：词表重复行、规则档位把不同词条映射到同一变体
    都属常见，去掉后能省下可观的 executemany 开销（SQLite 反正也会 OR IGNORE）。
    """
    rows, seen, n = [], set(), 0
    for w in words:
        if not w:
            continue
        n += 1
        text = None
        for a in algos:
            d = _HASHERS[a](w).digest()
            key = (a, d)
            if key in seen:
                continue
            seen.add(key)
            if text is None:
                text = w.decode("utf-8", errors="replace")
            rows.append((a, d, text, src, ts))
    return rows, n


def _gen_candidates(path, level, limit=None):
    """候选明文流：裸字典 = 原样行；规则档位 = 每行经 rules.variants 变形。

    这是文档里"流式管道"的核心——生成器套生成器，全程不构造完整列表，
    所以内存占用与词表规模、档位扩充倍数都无关。
    """
    for _i, line, text in _iter_lines(path, limit):
        if level is None:
            yield line
        else:
            for v in _load_rules().variants(text, level):
                yield v.encode("utf-8")


def _row_sort_key(row):
    """批内排序键：(algo, digest)。让聚簇主键的插入页访问局部化。"""
    return (row[0], row[1])


def _import_single(path, algos, level, src, limit=None, progress=False):
    """单进程流式导入：生成候选 → 每 BATCH 条一事务。返回 (变更行数, 候选条数)。

    批内按摘要排序后再 executemany：主键是聚簇的 (algo, digest)，乱序插入会
    随机触碰 B 树页，排一下让同批的页访问局部化（实测 84 万行 40.9 → 34.1 秒）。
    """
    ts = _now()
    buf, inserted, n = [], 0, 0
    for cand in _gen_candidates(path, level, limit):
        buf.append(cand)
        if len(buf) >= BATCH:
            rows, k = _hash_rows(buf, algos, src, ts)
            rows.sort(key=_row_sort_key)
            inserted += _insert_many(rows)
            n += k
            buf = []
            if progress and n % (BATCH * 10) == 0:
                sys.stderr.write("  [import] 已处理 %d 条候选…\n" % n)
                sys.stderr.flush()
    if buf:
        rows, k = _hash_rows(buf, algos, src, ts)
        rows.sort(key=_row_sort_key)
        inserted += _insert_many(rows)
        n += k
    return inserted, n


def _region_words(path, start, count, limit=None):
    """子进程任务：读原始行区间 [start, start+count)，返回原始行（bytes）。

    分片按**原始行**切，不按变体切——一条词条的全部变体必落在同一子进程里。
    """
    out, i, taken = [], 0, 0
    with open(path, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            i += 1
            if i <= start:
                continue
            out.append(line)
            taken += 1
            if taken >= count or (limit and i >= limit):
                break
    return out


def _spawn_ready():
    r"""检查多进程 spawn 是否**真的可用**。返回 (ok, 原因)。

    Windows 只有 spawn 一种上下文，而 spawn 要求子进程能重新导入 ``__main__``。
    两种情况会直接崩在子进程里：
      ① 主模块不可导入——`python -c "..."`、管道/标准输入、交互式 REPL
         （__main__.__file__ 是 '<stdin>' / '<string>' 甚至不存在）；
         报错形如 ``OSError: [Errno 22] Invalid argument: '...\<stdin>'``。
      ② 当前进程本身就是 spawn 出来的子进程——再开池会递归爆炸
         （未加 `if __name__ == "__main__":` 保护的脚本会踩到）。
    这两种都提前判掉，退回单进程，不让用户看到栈回溯。
    """
    import multiprocessing as mp
    if mp.current_process().name != "MainProcess":
        return False, "当前进程本身是子进程（避免 spawn 递归）"
    f = getattr(sys.modules.get("__main__"), "__file__", None) or ""
    if not f or f.startswith("<") or not os.path.isfile(f):
        return False, "主模块不可被重新导入（python -c / 标准输入 / 交互模式）"
    return True, None


def _worker(args):
    """多进程子进程入口：只做 CPU（展开变体 + 算摘要），批量把 row 回传主进程。

    子进程**不写库**：SQLite 是单写入者模型，多进程同时写同一库文件只会互相锁。
    rows 已按摘要排好序，主进程直接 executemany。
    """
    path, start, count, algos, level, src, ts = args
    words = _region_words(path, start, count)
    if level is not None:
        mod = _load_rules()
        words = [v.encode("utf-8") for w in words
                 for v in mod.variants(w.decode("utf-8", errors="replace"), level)]
    rows, n = _hash_rows(words, algos, src, ts)
    rows.sort(key=_row_sort_key)
    return rows, n


def _import_parallel(path, algos, level, src, nproc, limit=None):
    """多进程分片导入：子进程并行算摘要，主进程串行批量落库。

    返回 (变更行数, 候选条数)——与 _import_single 返回结构一致，调用方无需分支。
    结果与单进程完全一致（同一套规则、同一套主键，只是任务被切了片）。
    任何环节不可用（spawn 前提不满足、建池失败、子进程执行期崩溃）→ 一律
    **自动降级单进程**并说明原因；因为 (algo, digest) 是主键且用 INSERT OR IGNORE，
    即便已写入一部分再重做整份词表，也不会产生重复行（幂等）。
    """
    import multiprocessing as mp
    ready, why = _spawn_ready()
    if not ready:
        sys.stderr.write("[import] 多进程不可用（%s），自动降级单进程。\n" % why)
        sys.stderr.flush()
        return _import_single(path, algos, level, src, limit)

    pool = None
    inserted = n = 0
    try:
        ctx = mp.get_context("spawn")     # Windows 只能用 spawn
        pool = ctx.Pool(processes=nproc)
        ts = _now()
        # _plan_tasks 返回 (start, count) 的 2 元组；在此补全 worker 需要的 7 元组
        tasks = [(path, start, count, algos, level, src, ts)
                 for (start, count) in _plan_tasks(path, level, limit)]
        for rows, k in pool.imap_unordered(_worker, tasks, chunksize=1):
            inserted += _insert_many(rows)
            n += k
    except Exception as exc:
        # 覆盖建池 **与执行阶段** 的失败（spawn 的 OSError、worker 异常等）
        sys.stderr.write("[import] 多进程失败（%s: %s），自动降级单进程重跑。\n"
                         % (type(exc).__name__, exc))
        sys.stderr.flush()
        if pool is not None:
            try:
                pool.terminate()
            except Exception:
                pass
        pool = None
        return _import_single(path, algos, level, src, limit)
    finally:
        if pool is not None:
            try:
                pool.close()
                pool.join()
            except Exception:
                pass
    return inserted, n


def import_wordlist(path, algos=DEFAULT_ALGOS, rules=None, source=None,
                    processes=None, progress=False, limit=None):
    """词表逐行导入：读一行 → 生成变体 → 算摘要 → 批量事务插入（每 BATCH 条一事务）。

    内存恒定，不随词表大小增长（对照旧方案：JSON 需全量载入再全量覆写）。
    Step 2 起 ``rules`` 走 rules.py 的流式变形引擎。

    algos     要建索引的算法，默认 MD5 + SHA-256
    rules     规则档位：None = 裸字典（原样一行）；"min"/"std"/"max" = 规则变形
    source    写入 source 字段；缺省按档位生成 'wordlist:文件' 或 'wordlist:文件#std'
    processes 多进程分片：None/1 = 单进程；N = 子进程数；"auto" = 按 CPU 核数
    progress  置 True 向 stderr 打进度心跳（大词表导入用）
    limit     只导入前 N 行（基准测试用；正式导入不要传）

    返回 {'file','rules','lines','variants','inserted','algos','source','counts',
          'elapsed','rate','processes'}。

    幂等性：(algo, digest) 主键 + INSERT OR IGNORE → 同词表重复导入不产生重复行，
    行数严格不翻倍，重跑/断点续传安全。
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    level = _normalize_level(rules)
    algos = tuple(normalize_algo(a) for a in (algos or DEFAULT_ALGOS))
    for a in algos:
        if a not in _HASHERS:
            raise ValueError("不支持的算法 %r（当前支持 %s）" % (a, "/".join(sorted(_HASHERS))))
    src = source or ("wordlist:" + os.path.basename(path)
                     + (("#" + level) if level else ""))
    lines = _count_wordlist(path, limit)
    # 并行开关看**候选变体量**，不是原始行数：1 万行 × std 档 = 210 万变体，
    # 比 2 万行裸字典重得多，按行数判断会让它悄悄跑单进程（早期实测踩过这个坑）。
    est_variants = _estimate_variants(path, level, limit=limit)
    nproc = _resolve_processes(processes)
    if nproc == 1 and est_variants > PARALLEL_MIN_VARIANTS and processes is None:
        # 默认档：量够大就自动上多进程；显式传 processes=1 仍尊重用户选择。
        nproc = _resolve_processes("auto")
    t0 = time.time()
    if progress:
        hint = ("（%s 档：单条约 ×%d，预估共 %d 个变体）"
                % (level, _load_rules().count_variants("password", level), est_variants)
                if level else "（裸字典）")
        sys.stderr.write("[import] %s  lines=%d  rules=%s%s  algos=%s  procs=%d\n"
                         % (os.path.basename(path), lines, level or "raw", hint,
                            "+".join(algos), nproc))
        sys.stderr.flush()
    with _bulk_tuning():                   # 导入期放大页缓存，退出自动恢复 8MB
        if nproc > 1 and est_variants > PARALLEL_MIN_VARIANTS:
            inserted, variants_n = _import_parallel(path, algos, level, src, nproc, limit)
        else:
            inserted, variants_n = _import_single(path, algos, level, src, limit, progress)
    if nproc > 1:
        _checkpoint(_conn())               # 收尾把 WAL 收回主库文件
    elapsed = time.time() - t0
    return {"file": os.path.abspath(path), "rules": level, "lines": lines,
            "variants": variants_n, "inserted": inserted, "algos": list(algos),
            "source": src, "counts": {a: count(a) for a in algos},
            "elapsed": round(elapsed, 3),
            "rate": int(variants_n / elapsed) if elapsed > 0 else 0,
            "processes": nproc}


def _meta_set(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))
    conn.commit()


def _meta_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def _meta_del(conn, key):
    conn.execute("DELETE FROM meta WHERE key = ?", (key,))
    conn.commit()


def migration_status(conn=None):
    """迁移健康状态（供 stats()/agent 的程序化检测使用）。

    返回 {'ok', 'skipped_count', 'error', 'skipped', 'from', 'at'}：
      ok            —— 无跳过也无失败时为 True
      skipped_count —— 被隔离的坏条目数
      error         —— 整批放弃时的原因字符串（无则 None）
      skipped       —— 坏条目明细列表（algo / digest / plaintext / index / reason）
    """
    conn = conn or _conn()
    skipped_raw = _meta_get(conn, "migrate_skipped")
    try:
        skipped = json.loads(skipped_raw) if skipped_raw else []
    except (ValueError, TypeError):
        skipped = []
    error = _meta_get(conn, "migrate_error") or None
    # 明细可能被 MIGRATE_SKIP_DETAIL_MAX 截断；总数以 migrate_skipped_total 为准
    total_skipped = _meta_get(conn, "migrate_skipped_total")
    truncated = _meta_get(conn, "migrate_skipped_truncated") == "1"
    if total_skipped is not None:
        try:
            skipped_count = int(total_skipped)
        except (TypeError, ValueError):
            skipped_count = len(skipped)
    else:
        skipped_count = len(skipped)
    return {"ok": not skipped_count and not error,
            "skipped_count": skipped_count,
            "error": error,
            "skipped": skipped,
            "from": _meta_get(conn, "migrated_from_json") or None,
            "at": _meta_get(conn, "migrated_at") or None,
            "detail_truncated": truncated}


def stats():
    """返回各算法条数、磁盘占用，以及**迁移健康状态**。

    关键字段（用于程序化检测，不必靠人盯 stderr）：
      migrate_error   —— 整批放弃的原因（None 表示无）
      migrate_skipped —— 被隔离的坏条目条数（0 表示无）
    """
    conn = _conn()
    out = {a: 0 for a in DEFAULT_ALGOS}
    for algo, n in conn.execute("SELECT algo, COUNT(*) FROM hash_index GROUP BY algo"):
        out[algo] = n
    total = sum(out.values())
    size = 0
    for suffix in ("", "-wal", "-shm"):   # WAL 里可能还压着未 checkpoint 的数据
        p = db_path() + suffix
        if os.path.isfile(p):
            size += os.path.getsize(p)
    out["rows"] = total
    out["size_mb"] = round(size / 1048576.0, 3)
    out["path"] = db_path()
    st = migration_status(conn)
    out["migrate_error"] = st["error"]
    out["migrate_skipped"] = st["skipped_count"]
    out["migrate_skipped_truncated"] = st["detail_truncated"]
    out["migrate_ok"] = st["ok"]
    return out


# ---------------------------------------------------------------- 旧表迁移
def _json_candidates():
    """旧 hash_table.json 的候选位置：数据库目录 → 项目目录（去重）。

    两个位置都查，是为了照顾 HFA_DB_PATH 指向别处（如 D:\\HashForensicsDB\\）时，
    项目目录里遗留的旧表仍能被自动发现。
    """
    cands = []
    for d in (os.path.dirname(db_path()), _HERE):
        p = os.path.join(d, JSON_NAME)
        if p not in cands:
            cands.append(p)
    return cands


def _scan_json(raw):
    """把旧表解析成可写入的行 + 坏条目明细。

    返回 (rows, expected, bad)：
      rows     —— 可直接入库的 (algo, blob, plaintext, source, ts) 元组
      expected —— 各算法合法条目数
      bad      —— 坏条目明细（algo / digest 原样 / plaintext 原样 / index / reason）
    坏条目连同原 hex 与原文一起记下来，便于用户从 meta 取回，不丢信息。
    """
    ts = _now()
    rows, expected, bad = [], {}, []
    for algo, store in raw.items():
        if not isinstance(store, dict):
            continue
        a = normalize_algo(algo)
        expected.setdefault(a, 0)
        for idx, (digest_hex, plaintext) in enumerate(store.items()):
            reason = None
            blob = _to_blob(digest_hex)
            if blob is None:
                reason = "摘要不是合法十六进制"
            elif not isinstance(plaintext, str):
                reason = "明文不是字符串"
            else:
                try:
                    _check(a, blob)
                except ValueError as exc:
                    reason = str(exc)
            if reason:
                bad.append({"algo": a, "digest": str(digest_hex),
                            "plaintext": plaintext if isinstance(plaintext, str) else repr(plaintext),
                            "index": idx, "reason": reason})
                continue
            rows.append((a, blob, plaintext, "import:json", ts))
            expected[a] += 1
    return rows, expected, bad


def migrate_from_json(json_path, backup_suffix=".migrated.bak"):
    """迁移旧 JSON 对照表 → hash_index。返回成功入库的行数。

    分档处理坏条目（MIGRATE_SKIP_RATIO = 5%）：
      * 无坏条目      → 全部入库，原文件改名 <原名>.migrated.bak（保持原行为）
      * 坏占比 ≤ 5%   → 好数据入库，坏条目隔离到 meta.migrate_skipped，
                        **原文件保留原地**——它同时是好数据的来源凭据和坏条目的备份
      * 坏占比 > 5%   → 整批放弃（一条不写），原文件保留，原因写 meta.migrate_error，
                        避免"大面积残缺的迁移被误认为成功"
    无论哪种结果都会写 meta，`stats()` 与 `migration_status()` 均可程序化检测。
    """
    if not json_path or not os.path.isfile(json_path):
        return 0
    with open(json_path, encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("旧对照表格式异常（顶层应为 dict）：%s" % json_path)

    rows, expected, bad = _scan_json(raw)
    total = len(rows) + len(bad)
    ratio = (len(bad) / float(total)) if total else 0.0
    conn = _conn()
    ts = _now()

    # --- 分档 3：坏条目过多 → 整批放弃（不写任何数据行） ---
    if total and ratio > MIGRATE_SKIP_RATIO:
        detail = "、".join("%s:%s(%s)" % (b["algo"], b["digest"][:32], b["reason"]) for b in bad[:5])
        msg = ("旧对照表坏条目占比 %.1f%%（%d/%d）超过阈值 %.0f%%，"
               "为免残缺迁移被误认为成功，已整批放弃；原文件保留未改名：%s"
               % (ratio * 100, len(bad), total, MIGRATE_SKIP_RATIO * 100, json_path))
        _meta_set(conn, "migrate_error", "%s：%s" % (msg, detail))
        _meta_set(conn, "migrate_skipped", "[]")
        _meta_del(conn, "migrate_skipped_truncated")
        _meta_set(conn, "migrate_attempted_at", ts)
        raise ValueError(msg)

    # --- 分档 1/2：入库合法数据 ---
    n = _insert_many(rows, _SQL_UPSERT)
    conn.commit()

    after = {a: count(a) for a in expected}
    # 校验口径：JSON 对象的键在同一 algo 内天然唯一，故 expected[a] 是旧表该算法的合法唯一条目数。
    # 迁移要做到"合法条目一条不少地进库" → after[a] >= expected[a]。
    mismatch = {a: (expected[a], after[a]) for a in expected if after[a] < expected[a]}
    if mismatch:
        msg = "迁移条数校验失败（算法: 旧表合法条目/库中条数）：%s" % mismatch
        _meta_set(conn, "migrate_error", msg)
        raise RuntimeError(msg)

    _meta_del(conn, "migrate_error")
    _meta_set(conn, "migrated_from_json", os.path.abspath(json_path))
    _meta_set(conn, "migrated_at", ts)
    _meta_set(conn, "migrate_attempted_at", ts)

    if bad:                                   # 分档 2：隔离坏条目，原文件保留
        payload = bad[:MIGRATE_SKIP_DETAIL_MAX]
        _meta_set(conn, "migrate_skipped", json.dumps(payload, ensure_ascii=False))
        _meta_set(conn, "migrate_skipped_truncated",
                  "1" if len(bad) > MIGRATE_SKIP_DETAIL_MAX else "0")
        _meta_set(conn, "migrate_skipped_total", str(len(bad)))
    else:                                     # 分档 1：干净迁移 → 原文件改名备份
        _meta_del(conn, "migrate_skipped")
        _meta_del(conn, "migrate_skipped_truncated")
        _meta_del(conn, "migrate_skipped_total")
        os.replace(json_path, json_path + backup_suffix)
    conn.commit()
    return n


def _warn_migration(outcome):
    """迁移有跳过/失败时，向 stderr 发醒目提示（含取回办法）。"""
    path = outcome.get("from") or outcome.get("path") or "?"
    line = "!" * 70
    out = [line]
    if outcome.get("error"):
        out.append("!! [HashForensics] 旧对照表迁移失败，本次未导入任何数据")
        out.append("!! 原因：%s" % outcome["error"])
        out.append("!! 数据库当前为空表，查表将全部落空。原始文件完好保留：%s" % path)
        out.append("!! 处理：修正上述坏条目后重启即可自动重试；或用 db.migrate_from_json() 手工迁移。")
    else:
        out.append("!! [HashForensics] 旧对照表迁移完成，但有条目被跳过")
        out.append("!! 旧表共 %d 条：成功 %d 条，跳过 %d 条（坏数据未丢弃）"
                   % (outcome.get("total", 0), outcome.get("migrated", 0),
                      outcome.get("skipped_count", 0)))
        out.append("!! 原始文件保留未改名：%s" % path)
        out.append("!! 跳过的条目已存入 meta.migrate_skipped（含 algo/原摘要/原文/原因），")
        out.append("!! 可取回：python -c \"import db,json; print(json.dumps(db.migration_status()['skipped'],"
                   " ensure_ascii=False, indent=1))\"")
    out.append(line)
    sys.stderr.write("\n".join(out) + "\n")
    sys.stderr.flush()


def _auto_migrate(conn):
    """启动时自动迁移：hash_index 为空且存在旧 hash_table.json → 迁移。

    返回结果摘要 dict（无迁移发生则返回 None）；异常不抛出——已写入 meta.migrate_error
    供 stats() 检测，并保留原文件等待用户修正后重启重试。
    """
    if conn.execute("SELECT 1 FROM hash_index LIMIT 1").fetchone():
        return _existing_issue(conn)
    if _meta_get(conn, "migrated_from_json"):
        return _existing_issue(conn)
    for cand in _json_candidates():
        if not os.path.isfile(cand):
            continue
        try:
            n = migrate_from_json(cand)
        except Exception as exc:      # 迁移失败不拖垮启动；保留原文件，改用空表继续
            msg = "%s: %s" % (cand, exc)
            if not _meta_get(conn, "migrate_error"):   # migrate_from_json 已写过就不覆盖
                _meta_set(conn, "migrate_error", msg)
            return {"from": cand, "path": cand, "migrated": count(None), "total": 0,
                    "skipped_count": 0, "error": msg}
        st = migration_status(conn)
        if st["skipped_count"] or st["error"]:
            with open(cand, encoding="utf-8") as f:
                try:
                    total = sum(len(v) for v in json.load(f).values() if isinstance(v, dict))
                except Exception:
                    total = 0
            return {"from": st["from"] or cand, "path": cand, "migrated": n, "total": total,
                    "skipped_count": st["skipped_count"], "error": st["error"]}
        return None
    return None


def _existing_issue(conn):
    """库里已有数据时，仍把历史遗留的迁移异常带回给 connect()，保证每次启动都可见。"""
    st = migration_status(conn)
    if st["skipped_count"] or st["error"]:
        rows = count(None)
        return {"from": st["from"], "path": st["from"], "migrated": rows,
                "total": rows + st["skipped_count"],
                "skipped_count": st["skipped_count"], "error": st["error"]}
    return None


# ---------------------------------------------------------------- 旧 dict 语义视图
class AlgoView(object):
    """单算法视角的惰性视图：`view[hex]` 查、`view[hex] = 明文` 写、`hex in view`、`len(view)`。

    接口与旧 agent.py 里的 dict（table["MD5"]）一致，但底层就是 hash_index 表，
    所以内存占用不随表规模增长。写入先入缓冲，批量落盘（FLUSH_EVERY 条一次），
    任何读操作前先刷缓冲，保证 len/命中结果实时准确。
    """

    __slots__ = ("algo", "source", "_pending")

    def __init__(self, algo, source="compute"):
        self.algo = normalize_algo(algo)
        self.source = source
        self._pending = []          # 写入缓冲，批量落盘

    # -- 写 --
    def __setitem__(self, digest_hex, plaintext):
        # 不在此处校验摘要长度：旧行为是「宽容写入」，宁可存进去也不抛异常打断调用方。
        blob = _to_blob(digest_hex)
        if blob is None:
            raise ValueError("摘要必须是十六进制字符串：%r" % (digest_hex,))
        if not isinstance(plaintext, str):
            plaintext = str(plaintext)
        self._pending.append((self.algo, blob, plaintext, self.source))
        if len(self._pending) >= FLUSH_EVERY:
            self.flush()

    def flush(self):
        """把缓冲写入数据库（按摘要长度分桶，规避异常长度条目），返回新增行数。"""
        if not self._pending:
            return 0
        ts = _now()
        buckets = {}
        for (a, d, p, s) in self._pending:
            buckets.setdefault(len(d), []).append((a, d, p, s, ts))
        self._pending = []
        n = 0
        for rows in buckets.values():
            n += _insert_many(rows)
        return n

    # -- 读 --
    def get(self, digest_hex, default=None):
        self.flush()
        blob = _to_blob(digest_hex)
        if blob is None:
            return default
        row = _conn().execute(
            "SELECT plaintext FROM hash_index WHERE algo = ? AND digest = ?",
            (self.algo, blob)).fetchone()
        return row[0] if row else default

    def __getitem__(self, digest_hex):
        sentinel = _MISS
        val = self.get(digest_hex, sentinel)
        if val is sentinel:
            raise KeyError(digest_hex)
        return val

    def __contains__(self, digest_hex):
        return self.get(digest_hex, _MISS) is not _MISS

    def __len__(self):
        self.flush()
        return count(self.algo)

    def __bool__(self):
        self.flush()
        return _conn().execute("SELECT 1 FROM hash_index WHERE algo = ? LIMIT 1",
                               (self.algo,)).fetchone() is not None

    def __repr__(self):
        return "<AlgoView %s (%d 条，SQLite 惰性视图)>" % (self.algo, len(self))


_MISS = object()


def load_view(source=None):
    """返回 {"MD5": AlgoView, "SHA-256": AlgoView}——结构与旧 load_table() 的 dict 一致，
    但读写都落在 SQLite 上，不再把全表载入内存。"""
    connect()
    return {a: AlgoView(a, source or "compute") for a in DEFAULT_ALGOS}


if __name__ == "__main__":
    # 自检：python db.py
    connect()
    print("数据库路径：%s" % db_path())
    print("统计：%s" % json.dumps(stats(), ensure_ascii=False))
    _md5, _sha = hashlib.md5("062481".encode()).hexdigest(), hashlib.sha256("062481".encode()).hexdigest()
    remember("062481")
    print("lookup('MD5', %s) = %r" % (_md5, lookup("MD5", _md5)))
    print("lookup('SHA-256', %s) = %r" % (_sha[:16] + "…", lookup("SHA-256", _sha)))
    print("未命中的错误输入：%r" % lookup("MD5", "$2b$12$not-a-hex"))
