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
