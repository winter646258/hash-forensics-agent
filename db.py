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
import time

_HERE = os.path.dirname(os.path.abspath(__file__))

# 数据库路径：环境变量 HFA_DB_PATH 优先，默认项目目录下 hash_index.db
DB_PATH = os.environ.get("HFA_DB_PATH") or os.path.join(_HERE, "hash_index.db")

# 旧 JSON 表的文件名与默认位置（仅迁移时使用；迁移成功后改名 .migrated.bak）
JSON_NAME = "hash_table.json"
JSON_TABLE_PATH = os.path.join(_HERE, JSON_NAME)

DEFAULT_ALGOS = ("MD5", "SHA-256")   # 正向计算默认双索引
BATCH = 10000                        # 批量事务条数：内存恒定，不随词表大小增长
FLUSH_EVERY = 2000                   # 视图写入缓冲阈值（防止调用方一边写一边撑内存）

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
def connect(path=None):
    """建立（并缓存）数据库连接：建表 + 设 PRAGMA。重复调用返回同一连接。"""
    global _CONN, _CONN_PATH
    target = os.path.abspath(path or DB_PATH)
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
    _auto_migrate(conn)              # 启动时：旧 JSON 存在且表为空 → 自动迁移
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
    return _CONN_PATH or os.path.abspath(DB_PATH)


def flush():
    """提交未落盘的事务（WAL 下为轻量操作）。"""
    if _CONN is not None:
        _CONN.commit()


def _insert_many(rows, sql=_SQL_INSERT):
    """批量写入：显式事务包裹。返回实际变更的行数。

    两个坑都在这一个函数里躲掉：
    ① 连接是 autocommit（isolation_level=None），不显式开事务的话 executemany 会退化成
       「逐条 INSERT 各自提交」——每条一次 fsync，导入 20 万行要三十秒。
    ② `cursor.rowcount` 在 executemany 走 array binding 时返回 0，不能拿来校验条数。
       改用 `conn.total_changes` 前后差值——SQLite 自维护的累计变更行数，可靠。
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


def import_wordlist(path, algos=DEFAULT_ALGOS, rules=None, source=None):
    """词表逐行导入：读一行 → 算摘要 → 批量事务插入（每 BATCH 条一事务）。

    内存恒定，不随词表大小增长（对照旧方案：JSON 需全量载入再全量覆写）。
    rules 参数为 Step 2 的规则档位预留；本步骤仅支持 rules=None。
    返回 {'file','lines','inserted','algos','source','counts'}。
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if rules:
        try:
            import rules as _rules  # noqa: F401  Step 2 才落地
        except ImportError:
            raise NotImplementedError(
                "规则档位 rules=%r 需要 Step 2 的 rules.py；本步骤（Step 1）仅支持 rules=None。" % (rules,))
    algos = tuple(normalize_algo(a) for a in (algos or DEFAULT_ALGOS))
    for a in algos:
        if a not in _HASHERS:
            raise ValueError("不支持的算法 %r（当前支持 %s）" % (a, "/".join(sorted(_HASHERS))))
    src = source or ("wordlist:" + os.path.basename(path))
    ts = _now()
    lines = inserted = 0
    buf = []
    with open(path, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            lines += 1
            text = line.decode("utf-8", errors="replace")
            for a in algos:
                buf.append((a, _HASHERS[a](line).digest(), text, src, ts))
            if len(buf) >= BATCH:
                inserted += _insert_many(buf)
                buf = []
    if buf:
        inserted += _insert_many(buf)
    return {"file": os.path.abspath(path), "lines": lines, "inserted": inserted,
            "algos": list(algos), "source": src,
            "counts": {a: count(a) for a in algos}}


def stats():
    """返回 {'MD5': n, 'SHA-256': n, ..., 'rows': 总数, 'size_mb': x, 'path': 数据库路径}。"""
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


def migrate_from_json(json_path, backup_suffix=".migrated.bak"):
    """迁移旧 JSON 对照表 → hash_index。

    成功后原文件改名为 <原名>.migrated.bak；条数校验不通过则整体回滚且不改名。
    返回迁移的行数（每个算法各算一行）。
    """
    if not json_path or not os.path.isfile(json_path):
        return 0
    with open(json_path, encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("旧对照表格式异常（顶层应为 dict）：%s" % json_path)

    ts = _now()
    rows, expected, bad = [], {}, []
    for algo, store in raw.items():
        if not isinstance(store, dict):
            continue
        a = normalize_algo(algo)
        expected[a] = 0
        for digest_hex, plaintext in store.items():
            blob = _to_blob(digest_hex)
            if blob is None or not isinstance(plaintext, str):
                bad.append("%s:%s" % (a, str(digest_hex)[:32]))
                continue
            try:
                _check(a, blob)
            except ValueError:
                bad.append("%s:%s" % (a, str(digest_hex)[:32]))
                continue
            rows.append((a, blob, plaintext, "import:json", ts))
            expected[a] += 1
    if bad:
        raise ValueError("旧对照表含 %d 条无法解析的条目，为免丢数据已中止迁移：%s"
                         % (len(bad), "、".join(bad[:5])))

    conn = _conn()
    n = _insert_many(rows, _SQL_UPSERT)   # 显式事务 + total_changes 口径（见 _insert_many）
    conn.commit()

    after = {a: count(a) for a in expected}
    # 校验口径：JSON 对象的键在同一 algo 内天然唯一，故 expected[a] 就是旧表的唯一条目数。
    # 迁移要做到"旧条目一条不少地存在于库中" → after[a] >= expected[a]。
    # 自动迁移时表必为空（before 全 0），此时退化为严格相等：after[a] == expected[a]。
    mismatch = {a: (expected[a], after[a]) for a in expected if after[a] < expected[a]}
    if mismatch:
        raise RuntimeError("迁移条数校验失败（算法: 旧表唯一条目/库中条数）：%s" % mismatch)

    os.replace(json_path, json_path + backup_suffix)     # 校验通过 → 原文件改名备份
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                 ("migrated_from_json", os.path.abspath(json_path)))
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", ("migrated_at", ts))
    conn.commit()
    return n


def _auto_migrate(conn):
    """启动时自动迁移：hash_index 为空且存在旧 hash_table.json → 迁移并备份。"""
    if conn.execute("SELECT 1 FROM hash_index LIMIT 1").fetchone():
        return 0
    if conn.execute("SELECT 1 FROM meta WHERE key = 'migrated_from_json'").fetchone():
        return 0
    for cand in _json_candidates():
        if os.path.isfile(cand):
            try:
                return migrate_from_json(cand)
            except Exception as exc:      # 迁移失败不能拖垮启动：保留原文件，改用空表继续
                conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                             ("migrate_error", "%s: %s" % (cand, exc)))
                conn.commit()
                return 0
    return 0


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
