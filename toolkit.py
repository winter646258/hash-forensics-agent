#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
toolkit.py —— 哈希取证工具箱（七大模块）
模块清单：
  1. 批量哈希计算（MD5/SHA-1/SHA-256，可选 SM3）
  2. 证据完整性校验（双哈希比对）
  3. 哈希去重（识别内容相同的多副本）
  4. 黑白名单筛查（模拟 NSRL）
  5. 密码破解演示（Android 图形密码全量表 + 弱口令彩虹表）
  6. 区块链存证模拟（链式哈希）
  7. 口令安全体检（快/慢哈希识别与建议）
运行：python toolkit.py            （交互模式）
      python toolkit.py demo <目录> （自动演示全部模块）
依赖：仅 Python 3 标准库。
"""
import hashlib
import json
import os
import sys
import time

CHUNK = 1024 * 1024

# ---------------- 内置黑白名单（模拟 NSRL 哈希库） ----------------
WHITE = {"cb7f1bf8a1a21dc36600fb6e739cb60c": "已知正常文件（hello.txt 演示样本）"}
BLACK = {"a331f696341c0916ad54f1fdd7ca09de": "已知恶意样本（模拟 NSRL 黑名单条目）"}
GESTURE_TARGET = "36F6A527314C7DD2D71A6A36703ADF314E14F28B"


# ============================================================
# 加分项：SM3 国密杂凑算法（纯标准库实现，GB/T 32905-2012）
# ============================================================
def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(x, y, z, j):
    return (x & y) ^ (x & z) ^ (y & z) if j >= 16 else (x ^ y ^ z)


def _gg(x, y, z, j):
    return (x & y) ^ ((~x & 0xFFFFFFFF) & z) if j >= 16 else (x ^ y ^ z)


def sm3(data: bytes) -> str:
    """SM3 杂凑算法，输出 256 位（64 个十六进制字符）。"""
    iv = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    t = [0x79CC4519 if j < 16 else 0x7A879D8A for j in range(64)]

    ml = len(data) * 8
    data = data + b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64)
    data += ml.to_bytes(8, "big")

    v = iv[:]
    for off in range(0, len(data), 64):
        b = data[off:off + 64]
        w = [int.from_bytes(b[i * 4:i * 4 + 4], "big") for i in range(16)]
        for j in range(16, 68):
            x = w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)
            x = _p1(x)
            w.append((x ^ _rotl(w[j - 13], 7) ^ w[j - 6]) & 0xFFFFFFFF)
        w1 = [w[i] ^ w[i + 4] for i in range(64)]

        a, bb, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t[j], j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            tt1 = (_ff(a, bb, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = _rotl(bb, 9)
            bb = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = _p0(tt2)
        v = [(x ^ y) & 0xFFFFFFFF for x, y in zip(v, (a, bb, c, d, e, f, g, h))]
    return "".join("%08x" % x for x in v)


# ============================================================
# 模块 1：批量哈希计算
# ============================================================
def hash_file(path, algorithms=("MD5", "SHA-1", "SHA-256")):
    """分块读取计算多算法哈希，返回 {算法: 摘要}。SM3 需一次性读入。"""
    makers = {"MD5": hashlib.md5, "SHA-1": hashlib.sha1, "SHA-256": hashlib.sha256}
    result = {}
    need_sm3 = "SM3" in algorithms
    h = {}
    for a in algorithms:
        if a == "SM3":
            continue
        h[a] = makers[a]()
    with open(path, "rb") as f:
        # SM3 简化处理：与分块读取同流程累积
        sm3_buf = []
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            for v in h.values():
                v.update(block)
            if need_sm3:
                sm3_buf.append(block)
    for a, v in h.items():
        result[a] = v.hexdigest()
    if need_sm3:
        result["SM3"] = sm3(b"".join(sm3_buf))
    return result


def hash_dir(directory, with_sm3=False):
    """批量计算目录内全部文件哈希，输出 JSON 清单便于填写记录表。"""
    rows = []
    algos = ["MD5", "SHA-1", "SHA-256"] + (["SM3"] if with_sm3 else [])
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        r = {"file": name, "size": os.path.getsize(path)}
        r.update(hash_file(path, tuple(algos)))
        rows.append(r)
        extra = ("  SM3=%s..." % r["SM3"][:16]) if with_sm3 else ""
        print("  %-24s %8d 字节  MD5=%s  SHA-256=%s...%s" % (name, r["size"], r["MD5"], r["SHA-256"][:16], extra))
    out = os.path.join(os.path.dirname(os.path.abspath(directory)) or ".", "hash_manifest.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print("  已输出 JSON 哈希清单：%s（%d 个文件）" % (out, len(rows)))
    return rows


# ============================================================
# 模块 2：证据完整性校验（双哈希）
# ============================================================
def verify_integrity(path, expect_md5, expect_sha256):
    """双哈希同时比对：任一项不一致即判“已篡改/保管链断裂”。"""
    real = hash_file(path, ("MD5", "SHA-256"))
    ok_md5 = real["MD5"] == expect_md5.lower()
    ok_sha = real["SHA-256"] == expect_sha256.lower()
    verdict = "一致 → 证据未被篡改，保管链完整" if (ok_md5 and ok_sha) else "不一致 → 已篡改或保管链断裂，需查明原因"
    print("  MD5     实测 %s" % real["MD5"])
    print("          期望 %s → %s" % (expect_md5, "一致" if ok_md5 else "不一致"))
    print("  SHA-256 实测 %s" % real["SHA-256"])
    print("          期望 %s → %s" % (expect_sha256, "一致" if ok_sha else "不一致"))
    print("  结论：%s" % verdict)
    return ok_md5 and ok_sha, real


# ============================================================
# 模块 3：哈希去重
# ============================================================
def dedup_dir(directory):
    """以 SHA-256 为键建字典，命中即“与 XX 文件内容相同”。"""
    print("  按 SHA-256 分组：")
    groups = {}
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            groups.setdefault(hash_file(path, ("SHA-256",))["SHA-256"], []).append(name)
    dups = 0
    dup_groups = 0
    for sha, names in sorted(groups.items()):
        if len(names) > 1:
            dup_groups += 1
            dups += len(names) - 1
            print("    内容相同：%s → SHA-256=%s...（可精简 %d 个副本）" % ("、".join(names), sha[:16], len(names) - 1))
    if dups == 0:
        print("    未发现内容相同的文件。")
    print("  小结：%d 组内容重复，共可精简 %d 个副本（哈希只看内容，不看文件名/属性）。" % (dup_groups, dups))
    return groups


# ============================================================
# 模块 4：黑白名单筛查（模拟 NSRL）
# ============================================================
def screen_dir(directory):
    print("  按 MD5 黑白名单筛查：")
    counts = {"白名单命中": 0, "黑名单命中": 0, "未命中": 0}
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        md5 = hash_file(path, ("MD5",))["MD5"]
        if md5 in BLACK:
            tag = "黑名单命中（疑似恶意/涉案）"
            counts["黑名单命中"] += 1
        elif md5 in WHITE:
            tag = "白名单命中（已知正常，可优先排除）"
            counts["白名单命中"] += 1
        else:
            tag = "未命中（需人工分析）"
            counts["未命中"] += 1
        print("    %-24s MD5=%s → %s" % (name, md5, tag))
    print("  统计：%s" % "、".join("%s %d" % kv for kv in counts.items()))
    return counts


# ============================================================
# 模块 5：密码破解演示
# ============================================================
def _passing(a, b, visited):
    ra, ca = divmod(a, 3)
    rb, cb = divmod(b, 3)
    mids = []
    if ra == rb and abs(ca - cb) == 2:
        mids.append((ra, (ca + cb) // 2))
    if ca == cb and abs(ra - rb) == 2:
        mids.append(((ra + rb) // 2, ca))
    if abs(ra - rb) == 2 and abs(ca - cb) == 2:
        mids.append(((ra + rb) // 2, (ca + cb) // 2))
    return all(r * 3 + c in visited for r, c in mids)


def _dfs(path, visited, out):
    if len(path) >= 4:
        out.append(tuple(path))
    if len(path) == 9:
        return
    last = path[-1]
    for nxt in range(9):
        if nxt in visited or not _passing(last, nxt, visited):
            continue
        path.append(nxt)
        visited.add(nxt)
        _dfs(path, visited, out)
        path.pop()
        visited.remove(nxt)


def all_patterns():
    out = []
    for s in range(9):
        _dfs([s], {s}, out)
    return out


def crack_gesture_demo():
    """全量表破解 Android 图形密码（389,112 个合法图案，建表后 O(1) 查表）。"""
    t0 = time.time()
    table = {hashlib.sha1(bytes(p)).hexdigest().upper(): p for p in all_patterns()}
    hit = table.get(GESTURE_TARGET)
    dt = time.time() - t0
    print("  全量表：共 %d 项（合法图案），建表+查表 %.3f 秒" % (len(table), dt))
    if hit:
        print("  命中：gesture.key SHA-1=%s → 图案 %s" % (GESTURE_TARGET, "-".join(map(str, hit))))
    else:
        print("  未命中目标哈希。")
    return hit


def rainbow_weak_pwd():
    """弱口令彩虹表演示：预计算常见弱口令 MD5 → 查表秒级命中。"""
    weak = ["123456", "123456789", "password", "111111", "12345678", "abc123",
            "qwerty", "123123", "admin", "000000", "iloveyou", "dragon"]
    table = {hashlib.md5(w.encode()).hexdigest(): w for w in weak}
    hit = table.get("e10adc3949ba59abbe56e057f20f883e")
    print("  预计算 %d 个常见弱口令的 MD5（模拟彩虹表）" % len(table))
    print("  查询 e10adc3949ba59abbe56e057f20f883e → 秒级命中口令“%s”" % hit)
    print("  启示：快哈希 + 简单口令 → 预计算表可批量秒破；加盐 + 慢哈希才是正解。")
    return hit


# ============================================================
# 模块 6：区块链存证模拟（链式哈希）
# ============================================================
def blockchain_demo(records=("2016-08-24 张三对涉案U盘计算双哈希并封存",
                             "2016-09-01 李四制作检验副本并记录交接",
                             "2016-10-15 王五复核哈希一致并出具意见书")):
    print("  生成哈希链（区块 = 数据 + 前块哈希 + 本块哈希）：")
    prev = "0" * 64
    chain = []
    for rec in records:
        h = hashlib.sha256((prev + rec).encode("utf-8")).hexdigest()
        chain.append({"data": rec, "prev": prev, "hash": h})
        print("    区块%d  数据=%s" % (len(chain), rec))
        print("            prev=%s…  hash=%s…" % (prev[:16], h[:16]))
        prev = h
    ok, pos = verify_chain(chain)
    print("  全链校验：%s" % ("通过（任何区块被改动都会导致后续哈希失配）" if ok else "失败于区块 %d" % pos))
    print("  篡改演示：把区块1的数据改为“被篡改的记录”后重新校验——")
    tampered = [dict(b) for b in chain]
    tampered[0]["data"] = "被篡改的记录"
    ok2, pos2 = verify_chain(tampered)
    print("    校验结果：%s（失配位置：区块 %d）→ 上链后不可篡改的特性得以演示" % ("通过" if ok2 else "失败", pos2))
    return chain


def verify_chain(chain):
    prev = "0" * 64
    for i, b in enumerate(chain):
        h = hashlib.sha256((prev + b["data"]).encode("utf-8")).hexdigest()
        if h != b["hash"] or b["prev"] != prev:
            return False, i
        prev = h
    return True, len(chain)


# ============================================================
# 模块 7：口令安全体检
# ============================================================
def password_audit():
    print("  场景识别 → 处置建议：")
    rows = [
        ("NTLM", "Windows 登录口令快哈希 → 可离线字典/彩虹表爆破，建议启用更强认证"),
        ("LM", "古老 LAN Manager 哈希（快且弱）→ 立即禁用"),
        ("MD5", "无盐快哈希 → 彩虹表/字典秒破，口令存储禁用，改用 PBKDF2/bcrypt/Argon2"),
        ("SHA-1", "快哈希且已被碰撞攻击攻破 → 校验场景也应换用 SHA-256/SM3"),
        ("MySQL 4.1/MD5", "数据库口令快哈希 → 改用加盐 + 慢哈希"),
        ("Android 图形密码", "仅 389,112 种组合，全量表秒级破解 → 改用长 PIN/生物识别"),
        ("bcrypt/Argon2/PBKDF2", "慢哈希 + 独立盐 → 彩虹表失效，口令存储首选"),
    ]
    for k, v in rows:
        print("    %-22s %s" % (k + "：", v))


# ============================================================
# 演示 / 交互
# ============================================================
def banner(title):
    print()
    print("=" * 78)
    print("  " + title)
    print("=" * 78)


def demo(directory):
    print("【哈希取证工具箱 自动演示】目标目录：%s" % os.path.abspath(directory))
    banner("模块1 批量哈希计算（含加分项 SM3）")
    hash_dir(directory, with_sm3=True)
    banner("模块2 证据完整性校验（双哈希）")
    p = os.path.join(directory, "hello.txt")
    if os.path.isfile(p):
        print("  -- 正常副本校验 --")
        verify_integrity(p, "cb7f1bf8a1a21dc36600fb6e739cb60c",
                         "810fb1710a000d29cbf01fe8a0f57ffd029182447c27074586185cc3c79aade2")
        print("  -- 篡改演示：翻转 hello.txt 首字节 --")
        tampered = p + ".tampered"
        with open(p, "rb") as f:
            data = bytearray(f.read())
        data[0] ^= 0x01
        with open(tampered, "wb") as f:
            f.write(bytes(data))
        verify_integrity(tampered, "cb7f1bf8a1a21dc36600fb6e739cb60c",
                         "810fb1710a000d29cbf01fe8a0f57ffd029182447c27074586185cc3c79aade2")
        os.remove(tampered)
    else:
        print("  （目录中无 hello.txt，跳过）")
    banner("模块3 哈希去重")
    dedup_dir(directory)
    banner("模块4 黑白名单筛查（模拟 NSRL）")
    screen_dir(directory)
    banner("模块5 密码破解演示（图形密码全量表 + 弱口令彩虹表）")
    crack_gesture_demo()
    rainbow_weak_pwd()
    banner("模块6 区块链存证模拟（链式哈希）")
    blockchain_demo()
    banner("模块7 口令安全体检")
    password_audit()
    print()
    print("【演示完成】七个模块全部执行完毕。")


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "demo":
        demo(sys.argv[2])
        return
    print("哈希取证工具箱 v1.0（Python 3 标准库实现）")
    print("用法：")
    print("  交互模式：python %s" % os.path.basename(__file__))
    print("  自动演示：python %s demo <目录路径>" % os.path.basename(__file__))
    while True:
        print("-" * 78)
        print("  1. 批量哈希计算        2. 证据完整性校验      3. 哈希去重")
        print("  4. 黑白名单筛查        5. 密码破解演示        6. 区块链存证模拟")
        print("  7. 口令安全体检        0. 退出")
        print("-" * 78)
        c = input("请选择功能 [0-7]：").strip()
        if c == "0":
            print("再见。")
            break
        if c == "1":
            hash_dir(input("目录路径：").strip(), with_sm3=True)
        elif c == "2":
            verify_integrity(input("文件路径：").strip(), input("期望 MD5：").strip(), input("期望 SHA-256：").strip())
        elif c == "3":
            dedup_dir(input("目录路径：").strip())
        elif c == "4":
            screen_dir(input("目录路径：").strip())
        elif c == "5":
            crack_gesture_demo()
            rainbow_weak_pwd()
        elif c == "6":
            blockchain_demo()
        elif c == "7":
            password_audit()
        elif c == "":
            continue
        else:
            print("无效选择。")


if __name__ == "__main__":
    main()
