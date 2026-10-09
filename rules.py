#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rules.py —— 字典规则引擎（v2.3 · Step 2）
================================================================================
把「明文原样匹配」升级为「明文 + 常见变形」：词表里一行 `password`，
std 档额外产出 `password123`、`password2026`、`Password!` 等，命中率因此显著提高。

三档（LEVELS）：

  min  原名、小写、大写、首字母大写                               ×4
  std  默认：min + 数字后缀(0-9 / 00-99 / 年份 1980-2030) + 常见符号/数字后缀
  max  std + leet 替换 + 反转 + 前缀数字 + 双词拼接               ×500 以上

设计要点
  * ``variants()`` 是**生成器**：逐条 yield，不构造完整列表。单条词条的中间状态
    （去重集合）上限是个常数，故整表导入的内存恒定，与词表规模无关。
  * 产出**两两不重复**（``dedup=True``，默认）：全小写词、纯数字词这类"基底互相
    重合"的情况会被去重，避免对同一个候选口令重复算哈希（CPU 是这里的瓶颈）。
  * leet 用 ``itertools.product`` 惰性展开；只有"可替换字符数 ≤ LEET_FULL_MAX"时
    才做全组合，其余退化为「逐字符单位替换 + 全主替换」，避免组合爆炸。

与升级书的偏差（已在交付说明中报告）
  ① 文档写「std ≈ ×60」，但文档同时列出的规则集是
     4 条基底 + 10(0-9) + 100(00-99) + 51(年份) + 符号/常见后缀 ≈ ×200；
     两者互相矛盾。本实现以**规则集**为准（漏掉 00-99 / 年份会直接丢掉
     `password123`、`password2026` 这两条验收用例）。要压回 ×60 只需删减
     下方 STD_SUFFIX_* 常量中的条目，无需改动算法。
  ② 文档写 min 档 ×4，本实现按"产出不重复"去重后，全小写/纯数字词会少于 4 条
     （`password` → 3 条，`123456` → 1 条）。这是**刻意**的：那几条本来就是同一个
     口令，重复产出只会白算哈希。文档口径可用 ``variants(w, "min", dedup=False)`` 复现。

依赖：仅 Python 标准库。
"""
from itertools import chain, product

__all__ = ["LEVELS", "DEFAULT_LEVEL", "variants", "count_variants", "describe",
           "LEVEL_DESC"]

LEVELS = ("min", "std", "max")
DEFAULT_LEVEL = "std"

LEVEL_DESC = {
    "min": "原名/小写/大写/首字母大写（×4）",
    "std": "min + 数字后缀(0-9、00-99、年份 1980-2030) + 常见符号后缀",
    "max": "std + leet 替换 + 反转 + 前缀数字 + 双词拼接（×500 以上）",
}

# ---------------------------------------------------------------- 规则素材
# std：数字后缀
DIGIT_SUFFIXES = tuple(str(i) for i in range(10))                  # 0-9
TWO_DIGIT_SUFFIXES = tuple("%02d" % i for i in range(100))         # 00-99
YEAR_SUFFIXES = tuple(str(y) for y in range(1980, 2031))           # 1980-2030
# std：常见符号后缀
SYMBOL_SUFFIXES = ("!", "@", "#", "$", "%", "^", "&", "*", ".", "_", "-",
                   "!!", "@@", "##", "$$", "!!!", "!@#", "..", "?", "~")
# std：常见"数字+符号"后缀（覆盖 password123 这类经典弱口令）
COMMON_SUFFIXES = ("123", "1234", "12345", "123456", "123456789", "12345678",
                   "321", "520", "1314", "111", "000", "666", "888", "007",
                   "110", "119", "120", "250", "abc", "qwe", "qwerty",
                   "123!", "1234!", "@123", "#123", "1!", "2023", "2024", "2025")

# max：leet 替换表（第一个为该字符的主替换）
LEET_MAP = {
    "a": ("@", "4"),
    "b": ("8",),
    "e": ("3",),
    "g": ("9",),
    "i": ("1", "!"),
    "l": ("1",),
    "o": ("0",),
    "s": ("5", "$"),
    "t": ("7",),
    "z": ("2",),
}
LEET_FULL_MAX = 6      # 可替换字符 ≤ 6 时做全组合（≤3^6），否则退化，避免组合爆炸

# max：前缀数字/符号
PREFIXES = ("1", "12", "123", "1234", "12345", "0", "00", "007", "000", "666",
            "888", "!", "@", "#", "1!", "!!", "2023", "2024", "2025", "2026")

# max：双词拼接用的内置常见口令词表（无需读第二份词表 → 内存恒定）
COMMON_WORDS = tuple(dict.fromkeys((
    "password", "admin", "root", "user", "guest", "test", "qwerty", "abc", "love",
    "iloveyou", "hello", "welcome", "master", "monkey", "dragon", "sunshine",
    "princess", "football", "baseball", "superman", "shadow", "michael", "jennifer",
    "computer", "internet", "security", "windows", "secret", "freedom", "whatever",
    "trustno1", "letmein", "starwars", "pokemon", "soccer", "batman", "charlie",
    "donald", "flower", "hunter", "jordan", "killer", "liverpool", "mustang",
    "nicole", "orange", "pepper", "purple", "ranger", "samsung", "silver", "summer",
    "thomas", "tigger", "victoria", "yellow", "zxcvbnm", "ginger", "banana",
    "cookie", "diamond", "eagle", "falcon", "google", "hockey", "jackson", "kitty",
    "lemon", "matrix", "naruto", "oliver", "phoenix", "robert", "taylor", "unicorn",
    "vampire", "william", "xavier", "yamaha", "zombie", "angel", "baby", "chicken",
    "daniel", "elephant", "friend", "guitar", "italia", "joshua", "knight",
    "london", "marine", "nathan", "october", "patricia", "quality", "rachel",
    "samuel", "thunder", "ultimate", "vincent", "winter", "xtreme", "yankees",
    "zeppelin", "forever", "sophie", "turtle", "walter", "cookie", "butterfly",
    "asdfgh", "1qaz2wsx", "qazwsx", "zxcasd", "asdf1234", "password1",
    "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
)))


# ---------------------------------------------------------------- 基与派生
def _bases(word):
    """min 档的 4 条形态：原名、小写、大写、首字母大写（顺序固定，与文档口径一致）。

    注意：这 4 条在**全小写词**（password）、**纯数字词**（123456）、**单字符词**（a）
    下会互相重合——词本身小写时「原名」==「小写」，纯数字时四种变换全相等。
    去重统一由 variants() 负责（见 dedup 参数），这里保持文档口径的原始顺序。
    """
    return (word, word.lower(), word.upper(), word.capitalize())


def _ordered_unique(items):
    """保序去重（Python 3.7+ dict 保序）——只用于常数级的小集合。"""
    return tuple(dict.fromkeys(items))


def _std_suffixes():
    """std 档后缀流（惰性拼装，不物化整张表）。"""
    return chain(DIGIT_SUFFIXES, TWO_DIGIT_SUFFIXES, YEAR_SUFFIXES,
                 SYMBOL_SUFFIXES, COMMON_SUFFIXES)


def _std_stream(word):
    """std 增量：后缀接在「原名」「小写」两个词形之后。

    后缀不挂到全部 4 个词形上：4×200 会把单条扩充倍数推到 ×800，
    而大小写 + 后缀的组合（`PASSWORD123`）在 max 档与实测命中率上收益很低。
    纯小写词条下「原名」与「小写」重合，去重后仍是同一份。
    """
    for b in _ordered_unique((word, word.lower())):
        for s in _std_suffixes():
            yield b + s


def _leet_stream(word):
    """leet 替换（惰性 product，内存与组合数无关）。"""
    opts = []
    for ch in word:
        reps = LEET_MAP.get(ch.lower())
        opts.append((ch,) + reps if reps else (ch,))
    flexible = [o for o in opts if len(o) > 1]
    if not flexible:
        return
    if len(flexible) <= LEET_FULL_MAX:
        for combo in product(*opts):     # 惰性展开，不建列表
            yield "".join(combo)
    else:                                # 组合爆炸：逐字符单位替换 + 全主替换
        for i, o in enumerate(opts):
            if len(o) > 1:
                for r in o[1:]:
                    yield word[:i] + r + word[i + 1:]
        yield "".join(o[1] if len(o) > 1 else o[0] for o in opts)


def _max_stream(word, bases):
    """max 增量：leet + 反转 + 前缀数字 + 双词拼接。"""
    leet_bases = _ordered_unique((word, word.lower(), word.capitalize()))
    for b in leet_bases:                 # leet（p@ssw0rd 即 a→@、o→0 这一支）
        for v in _leet_stream(b):
            yield v
    for b in bases:                      # 反转
        yield b[::-1]
    for b in _ordered_unique((word, word.lower(), word.capitalize())):
        for p in PREFIXES:               # 前缀数字/符号
            yield p + b
    for b in _ordered_unique((word, word.capitalize())):   # 双词拼接（含自拼接）
        yield b + b
        for w2 in COMMON_WORDS:
            yield b + w2
            yield w2 + b


# ---------------------------------------------------------------- 对外接口
def variants(word, level=DEFAULT_LEVEL, dedup=True):
    """流式生成 ``word`` 在 ``level`` 档下的全部变体（**生成器**，绝不返回 list）。

    每次只持有一条词条的中间状态（去重集合 ≤ 常数），因此整表导入时
    内存与词表规模无关。参数非法直接抛 ValueError（不静默降级）。

    dedup=True（默认）：三档产出**两两不重复**。基底里的重复项（全小写词的
    「原名」==「小写」、纯数字词四种形态全等）会被跳过，省下一次白算的哈希。
    去重记忆是「一条词条的全部产出」这个常数级集合，不破坏内存恒定性。

    dedup=False：按文档口径原样输出 min 档的 4 条形态（×4），即使它们重合。
    这是给"基线对照/教学演示"用的；生产导入请用默认值。

    顺序保证（dedup=True 时）：原名 → 小写 → 大写 → 首字母大写 → 后缀/前缀等派生。
    """
    if level not in LEVELS:
        raise ValueError("未知规则档位 %r（可选：%s）" % (level, " / ".join(LEVELS)))
    w = "" if word is None else str(word)
    if not w:
        return
    bases = _bases(w)
    seen = set() if dedup else None
    for b in bases:                      # min：4 条形态，保序、按需去重
        if seen is not None:
            if b in seen:
                continue
            seen.add(b)
        yield b
    if level == "min":
        return
    if seen is None:
        seen = set(bases)
    stream = (_std_stream(w) if level == "std"
              else chain(_std_stream(w), _max_stream(w, bases)))
    for v in stream:
        if v and v not in seen:
            seen.add(v)
            yield v


def count_variants(word, level=DEFAULT_LEVEL):
    """数一数某条词条在指定档位下会产出多少个变体（O(n) 时间、O(1) 额外内存）。

    用于导入前预估规模（升级书第 7 节风险项：max 档需先看预估条数）。
    """
    return sum(1 for _ in variants(word, level))


def describe(level=DEFAULT_LEVEL):
    """返回档位的一句话说明（供 agent 反馈层直接引用）。"""
    if level not in LEVELS:
        raise ValueError("未知规则档位 %r（可选：%s）" % (level, " / ".join(LEVELS)))
    return LEVEL_DESC[level]


if __name__ == "__main__":
    # 自检：python rules.py
    import inspect
    for lv in LEVELS:
        vs = variants("password", lv)
        print("%-4s 是生成器=%s  去重后 %d 条" % (lv, inspect.isgenerator(vs),
                                                count_variants("password", lv)))
    print("min(去重)  →", list(variants("password", "min")))
    print("min(文档口径 dedup=False) →", list(variants("password", "min", dedup=False)))
    std = set(variants("password", "std"))
    print("std 含 password123=%s  含 password2026=%s  总 %d 条"
          % ("password123" in std, "password2026" in std, len(std)))
    print("max 含 p@ssw0rd=%s  总 %d 条" % ("p@ssw0rd" in set(variants("password", "max")),
                                          count_variants("password", "max")))
    print()
    print("边界词去重自检（每档 len(list) == len(set)）：")
    for w in ("password", "123456", "admin", "P@ssw0rd", "aaa", "AAA", "1"):
        row = []
        for lv in LEVELS:
            vs = list(variants(w, lv))
            row.append("%s:%d/%s" % (lv, len(vs), "OK" if len(vs) == len(set(vs)) else "重复!"))
        print("  %-10s %s" % (w, "  ".join(row)))
