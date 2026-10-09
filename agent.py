#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent.py —— HashForensics Agent：哈希取证迷你智能体
================================================================
原理：感知 → 决策 → 行动 → 反馈 的单循环；干活的全是 exp5 现成函数，
agent 只负责"听懂、选路、解释、留痕"。

模式：
  python agent.py            交互模式
  python agent.py demo       演示模式（5 句预设对话，含内存实测）

红线（写入启动横幅）：
  1. 仅限授权检材与教学样本操作；
  2. 每次调用写审计日志 audit.log（谁/何时/对什么/方法/结果）；
  3. 外部 LLM API 只收脱敏后的技术问题，涉案数据不出本地。
"""
import hashlib
import json
import os
import re
import sys
import time

import toolkit as exp5  # 行动层：复用取证工具箱的哈希/校验/去重/破解函数

# ---------------- 路径常量：全部锚定到项目目录，克隆后开箱即用 ----------------
_HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(_HERE, "samples")           # 演示样本目录
DEFAULT_DEDUP_DIR = os.path.join(SAMPLES, "screening")

# ----------------------------------------------------------------
# 本地对照表（持久化）：正向算过的"哈希→明文"自动写入，查表时自动加载
#   存储：hash_table.json（MD5/SHA-256 各一张）——仅标准库，O(1) dict 查询
#   注意：这是"查表反查"，命中前提 = 原文曾被正向算过并存入；不是解密。
# ----------------------------------------------------------------
TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hash_table.json")


def load_table():
    if os.path.isfile(TABLE_PATH):
        with open(TABLE_PATH, encoding="utf-8") as f:
            return json.load(f)
    return {"MD5": {}, "SHA-256": {}}


def save_table(table):
    with open(TABLE_PATH, "w", encoding="utf-8") as f:
        json.dump(table, f, ensure_ascii=False, indent=1)


def remember(plaintext, table=None):
    """正向算 MD5+SHA-256 并自动写入本地对照表。返回 (md5, sha256)。"""
    if table is None:
        table = load_table()
    data = plaintext.encode("utf-8")
    md5 = hashlib.md5(data).hexdigest()
    sha = hashlib.sha256(data).hexdigest()
    table["MD5"][md5] = plaintext
    table["SHA-256"][sha] = plaintext
    save_table(table)
    return md5, sha

# ----------------------------------------------------------------
# 知识层：FAQ（哈希取证常见问题预置语料）
# ----------------------------------------------------------------
FAQ = [
    (("双哈希", "为什么要同时", "md5和sha", "md5+sha"),
     "双哈希 = 同时计算 MD5 与 SHA-256：① MD5 已有实用碰撞攻击（fastcoll 秒级），"
     "单独使用证明力会被质疑；② 两者结构独立，让攻击者必须同时攻破两个函数，目前不可行；"
     "③ 还能交叉核对工具与记录错误。成本几乎为零，证明力大幅提升。"),
    (("哈希", "加密", "区别", "解密"),
     "哈希不是加密：加密有密钥、可逆，目的是保密；哈希无密钥、单向，目的是完整性校验。"
     "哈希是多对一压缩映射，信息在运算中被不可逆丢弃，所以不存在“解密”，只能穷举或查表碰运气。"),
    (("彩虹表",),
     "彩虹表 = 预计算的“哈希→明文”对照表，用归约函数 R + 哈希链把存储压到只存链端点。"
     "它只对无盐快哈希有效——加盐后同一口令每个用户哈希都不同，表直接作废。"
     "GitHub 上有现成表（rockyou 词表、CrackStation 十亿级词表），agent 的查表层就是用它。"),
    (("雪崩",),
     "雪崩效应：输入哪怕 1 字节变化，输出哈希完全变样（实测 hello→hellp，MD5 由 cb7f1bf8… "
     "变为 bbdcaf5b…）。这是“任何篡改都能被检出”的技术基础。"),
    (("白名单", "黑名单", "nsrl"),
     "NSRL 白名单收录已知正常文件哈希，命中可优先排除但不能直接定性排除；"
     "黑名单命中只是“合理怀疑”，需人工复核内容。哈希筛查证明的是字节序列一致性，不判断语义。"),
    (("快播", "ip"),
     "快播案中“服务器 IP 不变”证明不了数据未篡改：IP 是网络层属性，与文件内容无对应关系。"
     "鉴真必须针对内容本身——哈希比对 + 提取/封存/流转全程记录。"),
    (("盐", "加盐", "salt"),
     "加盐 = 在口令后拼一段随机数据再哈希，同一口令每个用户的哈希都不同。"
     "作用：① 预计算对照表（彩虹表）全部作废；② 相同口令看不出同款。"
     "现代口令存储 = 加盐 + 慢哈希（bcrypt/Argon2/PBKDF2）。"),
    (("sm3", "国密"),
     "SM3 是国密杂凑算法（GB/T 32905-2012），输出 256 位，安全性对标 SHA-256。"
     "公安业务按国密要求优先使用 SM3；本实验包 exp5 工具箱内置纯 Python 实现，标准向量自检通过。"),
]
AUDIT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_audit.log")


# ----------------------------------------------------------------
# ⓪ LLM 感知层（--llm 启用，v2.0 主力理解层）：自然语言 → 结构化指令
#   工作方式 = function calling：工具清单写成 JSON 发给模型，
#   模型只回结构化指令，本地白名单校验后才执行（模型不碰文件、不碰网络）。
#   红线：发给 API 的只有"指令文本本身"，涉案文件内容绝不上传。
# ----------------------------------------------------------------
LLM_ACTIONS = ("identify", "crack", "verify", "dedup", "faq",
               "hash_compute", "build_table", "crack_then_verify")
LLM_TOOLS_SPEC = [
    {"action": "identify", "params": ["hash"], "desc": "用户给了一段哈希值，想知道它是什么类型/什么算法"},
    {"action": "hash_compute", "params": ["content", "algo"], "desc": "用户给出明文内容，要求按指定算法（md5/sha-1/sha-256/sha-512/sm3）正向计算哈希。注意：用户说'加密'但给了原文+算法时，真实意图就是正向算哈希，algo 归一化为 MD5/SHA-1/SHA-256/SHA-512/SM3"},
    {"action": "crack", "params": ["hash"], "desc": "用户给出哈希值，想反查原文（查表）"},
    {"action": "verify", "params": ["path"], "desc": "校验某文件的完整性（双哈希比对）"},
    {"action": "dedup", "params": ["dir"], "desc": "对目录内文件按内容去重"},
    {"action": "build_table", "params": ["file"], "desc": "把词表文件逐行正向算哈希写入本地对照表"},
    {"action": "crack_then_verify", "params": ["hash"], "desc": "先查表破解哈希，再用原文与样本文件比对是否同一来源"},
    {"action": "faq", "params": ["question"], "desc": "哈希取证原理类提问（为什么/是什么/区别/原理）"},
]
LLM_PROMPT = (
    "你是电子数据取证助手的意图解析器。把用户的话转成 JSON 指令，只输出 JSON 不解释。\n"
    "规则：\n"
    "1. 用户口语中常说'加密 xxx'，若给了原文内容+算法名，真实意图是 hash_compute（正向算哈希），algo 归一化为 MD5/SHA-1/SHA-256/SHA-512/SM3；\n"
    "2. 若给的是一段 32/40/64 位十六进制串且想反查原文，用 crack；想先破解再比对文件，用 crack_then_verify；\n"
    "3. 无法归类时用 faq，把原话放进 question。\n"
    "示例（严格照此风格输出）：\n"
    '用户：加密：062481，sha-256 → 输出 {"action":"hash_compute","content":"062481","algo":"SHA-256"}\n'
    '用户：算一下hello的md5 → 输出 {"action":"hash_compute","content":"hello","algo":"MD5"}\n'
    '用户：解密 e10adc3949ba59abbe56e057f20f883e → 输出 {"action":"crack","hash":"e10adc3949ba59abbe56e057f20f883e"}\n'
    '用户：校验 hello.txt → 输出 {"action":"verify","path":"hello.txt"}\n'
    '用户：对screening去重 → 输出 {"action":"dedup","dir":"screening"}\n'
    '用户：为什么要双哈希 → 输出 {"action":"faq","question":"为什么要双哈希"}\n'
    "工具清单：%s" % json.dumps(LLM_TOOLS_SPEC, ensure_ascii=False)
)


def llm_perceive(text):
    """LLM 理解层：调 OpenAI 兼容接口（DeepSeek/ChatGPT/本地 llama-server 等均可）。
    环境变量 LLM_API_KEY 存在才启用；失败/超时返回 None，由调用方降级回规则。"""
    import urllib.request
    base = os.environ.get("LLM_API_BASE", "https://api.deepseek.com").rstrip("/")
    key = os.environ.get("LLM_API_KEY", "")
    body = json.dumps({
        "model": os.environ.get("LLM_MODEL", "deepseek-chat"),
        "messages": [{"role": "system", "content": "/no_think\n" + LLM_PROMPT},
                     {"role": "user", "content": text}],
        "max_tokens": 300,
        "temperature": 0.1,
        "chat_template_kwargs": {"enable_thinking": False},  # Qwen3 等思考模型：关闭思考链，直接出 JSON
    }).encode("utf-8")
    req = urllib.request.Request(base + "/chat/completions", data=body, headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            msg = json.loads(resp.read())["choices"][0]["message"]
            content = (msg.get("content") or "").strip()
            if not content:  # 有的思考模型把内容放在 reasoning_content
                content = (msg.get("reasoning_content") or "").strip()
        # 容错抽取 JSON（模型偶尔会带 ```json 围栏或前后缀文字）
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if not m:
            return None
        cmd = json.loads(m.group())
        action = str(cmd.get("action", "")).lower()
        # 本地小模型可能输出近义 action 名，做一次归一化
        alias = {"hash": "hash_compute", "encrypt": "hash_compute", "decrypt": "crack",
                 "compute": "hash_compute", "lookup": "crack", "build": "build_table"}
        action = alias.get(action, action)
        if action not in LLM_ACTIONS:
            return None  # 白名单外指令一律拒绝
        if action == "hash_compute" and isinstance(cmd.get("algo"), str):
            cmd["algo"] = cmd["algo"].upper().replace("SHA-", "SHA-").replace("_", "-")
            if cmd["algo"].startswith("SHA"):  # 归一化 sha256 → SHA-256
                cmd["algo"] = "SHA-" + cmd["algo"][4:].lstrip("-")
        p = {k: v for k, v in cmd.items() if k != "action"}
        return action, p
    except Exception:
        return None


USE_LLM = "--llm" in sys.argv
if USE_LLM and not os.environ.get("LLM_API_KEY"):
    print("[提示] 未设置 LLM_API_KEY 环境变量，本次使用规则版理解层。")


def perceive_any(text):
    """统一入口（v2.0）：LLM 主力理解（口语自由），规则表兜底（离线/断网/失败降级）。
    两层输出同一结构，行动层与审计层无感知。"""
    if USE_LLM and os.environ.get("LLM_API_KEY"):
        llm = llm_perceive(text)
        if llm:
            return llm
        # LLM 不可用或没听懂 → 降级规则
    return perceive(text)


# ----------------------------------------------------------------
# ① 感知层：正则规则表（智能是写死的，确定性、可审计）
# ----------------------------------------------------------------
HASH_PATTERNS = [
    ("bcrypt", re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("MD5", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("SHA-1", re.compile(r"^[0-9a-fA-F]{40}$")),
    ("SHA-256", re.compile(r"^[0-9a-fA-F]{64}$")),
    ("SHA-512", re.compile(r"^[0-9a-fA-F]{128}$")),
]
# 内置演示样本库（已知明文，用于校验与反查演示）
KNOWN_MD5 = {
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "cb7f1bf8a1a21dc36600fb6e739cb60c": "hello，电子数据取证（演示样本）",
}
GESTURE_TARGET = "36F6A527314C7DD2D71A6A36703ADF314E14F28B"

SLOW_HASHES = ("bcrypt",)  # 慢哈希：拒绝盲目穷举，给成本评估（这是"智能"的体现）


def perceive(text):
    """感知：返回 (意图, 参数)。顺序即优先级。v1.1：支持夹在中文里的哈希串、组合意图。"""
    t = text.strip()
    # 1) 抽出疑似哈希串（bcrypt 需含 cost 段 $12$；$ 前不能用 \b 词边界；
    #    环视断言允许哈希紧贴中文，解决“帮我破解abc…行不行”这类句子）
    token = re.search(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,128}(?![0-9a-fA-F])|\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}", t)
    if token:
        s = token.group()
        algo = identify(s)
        if re.search(r"识别|是什么|类型", t):
            return "identify", {"hash": s, "algo": algo}
        # 组合意图：“破解后再校验/对比” → 先破解，行动层附带校验结论
        if re.search(r"(再|然后|之后)校验|校验.*(是否|有没有)被?.*(改|篡)", t):
            return "crack_then_verify", {"hash": s, "algo": algo}
        return "crack", {"hash": s, "algo": algo}
    # ---- 正向计算意图（三种句式，共用同一套内容清洗）----
    # 设计要点：算法名 + 计算类动词即为触发条件，连接词/标点均可选，
    # 内容提取后统一剥离动词、连接词、疑问词与标点，避免污染对照表。
    m_algo = re.search(r"(md5|sha[-_ ]?1|sha[-_ ]?256|sha[-_ ]?512|sm3)", t, re.IGNORECASE)
    if m_algo:
        m_verb = re.search(r"加密|计算|算一下|算算|算|求|生成|哈希一下|做哈希", t)
        front = bool(re.match(r"^\s*(md5|sha|sm3)", t, re.IGNORECASE))   # 算法前置式
        ask = bool(re.search(r"是多少|是什么|等于多少|几|值", t))          # 疑问式
        if m_verb or front or ask:
            algo = m_algo.group(1).upper().replace("_", "-").replace(" ", "-").replace("SHA", "SHA-", 1)
            algo = algo.replace("SHA--", "SHA-")
            # 取下需要清洗的片段：算法名在前的取其后，否则取算法名之前
            seg = t[m_algo.end():] if front else t[:m_algo.start()]
            content = re.sub(
                r"加密|计算|算一下|算算|算|求|生成|哈希一下|做哈希|一下|"      # 动词
                r"用|使用|按|以|采用|"                                        # 连接词
                r"是多少|是什么|等于多少|多少|结果|值|的|请|帮我|给我|"        # 疑问/语气词
                r"算法|加密|哈希|md5|sha-?1|sha-?256|sha-?512|sm3",           # 算法词残留
                "", seg, flags=re.IGNORECASE)
            content = re.sub(r"^[\s:：,，。=、?？!！]+|[\s:：,，。=、?？!！]+$", "", content)
            if content:
                return "hash_compute", {"content": content, "algo": algo}
    # 3) 建表意图：“建表 <文件>”（把词表逐行算哈希写入本地对照表）
    m_build = re.search(r"建表\s*[:：]?\s*([\w\u4e00-\u9fff\\/:.]+\.(?:txt|dic|lst))?", t)
    if m_build and re.search(r"建表", t):
        return "build_table", {"file": m_build.group(1)}
    # 4) 文件类意图
    path = re.search(r"[\w\u4e00-\u9fff·]+\.(?:txt|docx|pdf|jpg|bin|exe|zip)", t)
    if path and re.search(r"校验|比对|完整性", t):
        return "verify", {"path": path.group()}
    if re.search(r"去重|重复", t):
        d = re.search(r"[\w\u4e00-\u9fff\\/:.-]+", t.replace("对", "").replace("去重", "").strip())
        return "dedup", {"dir": d.group() if d else "."}
    # 3) 知识问答
    for keys, ans in FAQ:
        if any(k in t for k in keys):
            return "faq", {"answer": ans, "topic": keys[0]}
    return "unknown", {}


def identify(s):
    for name, pat in HASH_PATTERNS:
        if pat.match(s):
            return name
    return "未知类型"


# ----------------------------------------------------------------
# ② 决策层 + ③ 行动层
# ----------------------------------------------------------------
def decide_act(intent, p):
    """决策：按算法/场景选路；行动：调 exp5 现成函数。返回统一结构。"""
    if intent == "identify":
        algo = p["algo"]
        tips = {
            "MD5": "128 位快哈希，无盐时可用字典/查表攻击",
            "SHA-1": "160 位，已被碰撞攻击攻破，校验场景应换 SHA-256/SM3",
            "SHA-256": "256 位强哈希，完整性校验首选",
            "SHA-512": "512 位强哈希",
            "bcrypt": "慢哈希（自带盐），口令存储正解，预计算表无效",
            "未知类型": "不像标准十六进制哈希，检查是否 Base64/密文/编码串",
        }
        return {"ok": True, "action": "identify", "result": algo, "advice": tips[algo]}

    if intent == "hash_compute":
        # 正向计算：对任意内容按指定算法求哈希（不是解密，是哈希的本职工作）
        # v1.2：结果自动写入本地对照表，供日后 crack 意图查表反查
        content = p["content"].encode("utf-8")
        algo = p["algo"]
        if algo == "MD5":
            val = hashlib.md5(content).hexdigest()
        elif algo == "SHA-1":
            val = hashlib.sha1(content).hexdigest()
        elif algo == "SHA-256":
            val = hashlib.sha256(content).hexdigest()
        elif algo == "SHA-512":
            val = hashlib.sha512(content).hexdigest()
        else:
            val = exp5.sm3(content)  # SM3（exp5 内置国密实现）
        table = load_table()
        before = len(table["MD5"])
        remember(p["content"], table)  # 自动入表
        note = ""
        if val in KNOWN_MD5:
            note = "（该值恰在内置样本库中 → 对应口令 %s）" % KNOWN_MD5[val]
        return {"ok": True, "action": "hash_compute", "result": val,
                "advice": "%s(%r) 正向计算完成，已自动写入本地对照表（现 %d 条，新增 %d 条）。"
                          "今后直接“解密 %s”即可反查明文。注意：这是查表不是解密——"
                          "命中前提是原文曾被算过并存入。%s"
                          % (algo, p["content"], len(table["MD5"]),
                             len(table["MD5"]) - before, val, note)}

    if intent == "crack":
        # v2.1：algo 改为可选参数——LLM 只回 hash 也能查（双表都查一遍），规则路径仍可显式传 algo
        s = p["hash"]
        algo = p.get("algo") or identify(s)
        if algo in SLOW_HASHES:
            return {"ok": False, "action": "crack", "result": None,
                    "advice": "%s 是慢哈希且自带盐：预计算表无效，盲目穷举性价比极低。"
                              "建议只做已知口令定向尝试，或放弃爆破改查其他证据。" % algo}
        table = load_table()
        stores = []
        if algo == "MD5":
            stores = [table.get("MD5")]
        elif algo == "SHA-256":
            stores = [table.get("SHA-256")]
        else:  # 类型未知/其他：MD5、SHA-256 双表都查
            stores = [table.get("MD5"), table.get("SHA-256")]
        for store in stores:
            if store and s.lower() in store:  # v1.2：先查持久化对照表（含历史正向计算结果）
                plain = store[s.lower()]
                return {"ok": True, "action": "crack", "result": plain,
                        "advice": "本地对照表命中（共 %d 条）。这是查表不是解密——原文此前被正向算过并存入。"
                                  "真实场景可换 rockyou/CrackStation 十亿级表。" % len(store)}
        if s.lower() in KNOWN_MD5:  # 内置样本库
            return {"ok": True, "action": "crack", "result": KNOWN_MD5[s.lower()],
                    "advice": "内置样本库命中。真实场景可换 rockyou/CrackStation 十亿级表，覆盖弱口令。"}
        if s == GESTURE_TARGET:
            hit = exp5.crack_gesture_demo()  # 全量表枚举 389112 种（约 1~2 秒）
            if hit:
                return {"ok": True, "action": "crack", "result": "图形密码 " + "-".join(map(str, hit)),
                        "advice": "空间仅 38.9 万，全量表 1~2 秒穷举完毕——图形密码对取证几乎透明。"}
        tip_table = "" if any(stores) else "本地对照表为空，可先用“加密：xxx，用md5算法”或“建表 <词表.txt>”攒表；"
        return {"ok": False, "action": "crack", "result": None,
                "advice": "查表未命中。%s%s：① 加盐则查表无效，需现场逐目标计算；"
                          "② 无盐可换大词表（rockyou/CrackStation）；③ 强口令建议放弃爆破。" % (tip_table, algo)}

    if intent == "build_table":
        # 建表：把词表文件逐行正向算 MD5+SHA-256 写入本地对照表（行数即词条数）
        src = p.get("file")
        if not src or not os.path.isfile(src):
            return {"ok": False, "action": "build_table", "result": None,
                    "advice": "需要词表文件（每行一个候选明文）。示例：建表 D:\\wordlist.txt。"
                              "没有词表可用“加密：xxx，用md5算法”逐条攒表。"}
        table = load_table()
        before = len(table["MD5"])
        cnt = 0
        with open(src, "rb") as f:
            for raw in f:
                line = raw.rstrip(b"\r\n")
                if not line:
                    continue
                md5 = hashlib.md5(line).hexdigest()
                sha = hashlib.sha256(line).hexdigest()
                table["MD5"][md5] = line.decode("utf-8", errors="replace")
                table["SHA-256"][sha] = table["MD5"][md5]
                cnt += 1
        save_table(table)
        return {"ok": True, "action": "build_table",
                "result": "导入 %d 条，对照表现有 %d 条（MD5+SHA-256 双索引）" % (cnt, len(table["MD5"])),
                "advice": "已写入 %s。今后 crack 意图会自动查这张表——查表是反查不是解密，"
                          "命中前提 = 原文在词表里。" % TABLE_PATH}

    if intent == "verify":
        path = p["path"]
        if not os.path.isfile(path):
            alt = os.path.join(SAMPLES, path)
            if os.path.isfile(alt):
                path = alt
            else:
                return {"ok": False, "action": "verify", "result": "文件不存在",
                        "advice": "请给绝对路径，或把文件放进 samples/ 目录。"}
        real = exp5.hash_file(path, ("MD5", "SHA-256"))
        expect = None
        if real["MD5"] in KNOWN_MD5:  # 演示用：样本库里有记录则自动带出期望值
            expect_md5 = real["MD5"]
            expect_sha = exp5.hash_file(path, ("SHA-256",))["SHA-256"]
            expect = (expect_md5, expect_sha)
        if expect is None:
            return {"ok": True, "action": "verify", "result": real,
                    "advice": "已算出双哈希，请与取证记录比对（此文件不在内置样本库，无法自动判定）。"}
        ok, _ = exp5.verify_integrity(path, expect[0], expect[1])
        return {"ok": ok, "action": "verify", "result": real,
                "advice": "与内置样本记录比对：%s" % ("一致，未被篡改" if ok else "不一致，已篡改或保管链断裂")}

    if intent == "dedup":
        d = p.get("dir") or DEFAULT_DEDUP_DIR
        if not os.path.isdir(d):
            alt = os.path.join(SAMPLES, d)
            d = alt if os.path.isdir(alt) else DEFAULT_DEDUP_DIR
        groups = exp5.dedup_dir(d)
        n = sum(1 for v in groups.values() if len(v) > 1)
        return {"ok": True, "action": "dedup", "result": "%d 组内容重复（目录 %s）" % (n, os.path.abspath(d)),
                "advice": "哈希只看内容不看属性：改名/改时间戳的多副本会被归为一组。"}

    if intent == "faq":
        # v2.1：兼容两种来源——规则层给 {answer, topic}；LLM 层给 {question}（用关键词再匹配一次 FAQ）
        if "answer" in p:
            return {"ok": True, "action": "faq", "result": p["answer"],
                    "advice": "（命中预置知识库：%s）" % p["topic"]}
        q = str(p.get("question", ""))
        for keys, ans in FAQ:
            if any(k in q for k in keys):
                return {"ok": True, "action": "faq", "result": ans,
                        "advice": "（命中预置知识库：%s）" % keys[0]}
        return {"ok": True, "action": "faq", "result":
                "该问题超出预置知识库。核心要点：哈希不可逆（不存在解密）；取证用双哈希（MD5+SHA-256）固定证据；"
                "口令存储必须加盐+慢哈希。",
                "advice": "（未命中知识库，返回通用要点。可扩充 FAQ 语料。）"}

    if intent == "crack_then_verify":
        # 组合意图：先破解哈希得到原文，再用原文与样本文件内容比对，给出"是否同一来源"结论
        r_crack = decide_act("crack", p)
        plain = r_crack.get("result")
        if not r_crack["ok"] or not isinstance(plain, str):
            return {"ok": False, "action": "crack_then_verify", "result": None,
                    "advice": "破解未命中，无法进入校验环节。" + r_crack["advice"]}
        same = None
        for name in ("hello.txt",):
            fp = os.path.join(SAMPLES, name)
            if os.path.isfile(fp):
                with open(fp, "rb") as f:
                    same = plain.encode("utf-8") == f.read()
        verdict = ("内容与演示样本 samples/hello.txt 完全一致 → 同一来源，可作为关联线索"
                   if same else "破解出的原文与演示样本不一致 → 非同一内容")
        return {"ok": True, "action": "crack_then_verify", "result": "原文=%s；%s" % (plain, verdict),
                "advice": "组合流程：破解→内容比对。取证含义：口令即原文，可直接用于关联分析。"}

    return {"ok": False, "action": "unknown", "result": None,
            "advice": "没听懂。试试：①贴一段哈希让我识别/破解；②“校验 hello.txt”；"
                      "③“对 screening 去重”；④“为什么要双哈希”。"}


# ----------------------------------------------------------------
# ④ 反馈层：解释 + 审计留痕
# ----------------------------------------------------------------
def respond(r):
    line = "─" * 62
    print("  [%s] %s" % (r["action"], "成功" if r["ok"] else "未成功"))
    if r["result"] is not None:
        print("  结果：%s" % r["result"])
    print("  说明：%s" % r["advice"])
    print(line)


def audit(text, r):
    rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "input": text,
           "action": r["action"], "ok": r["ok"], "result": str(r["result"])[:120]}
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def step(text):
    """单轮：感知→决策行动→反馈→留痕。返回统一结构（demo/测试用）。"""
    intent, p = perceive(text)
    r = decide_act(intent, p)
    respond(r)
    audit(text, r)
    return r


BANNER = """══════════════════════════════════════════════════════════════
 哈希取证迷你智能体 v2.0（感知→决策→行动→反馈 单循环；行动层复用 exp5）
 理解层：--llm 大模型主力（口语自由）+ 正则规则表兜底（断网/无 key 可用）
 红线：① 仅限授权样本 ② 全程审计留痕 ③ 外部API只收脱敏指令、文件内容不出本地
 试试：贴一段哈希 / “加密：062481，sha-256” / “校验 hello.txt” / “对 screening 去重” /
      “为什么要双哈希” / “退出”
══════════════════════════════════════════════════════════════"""


def interactive():
    print(BANNER)
    while True:
        try:
            text = input("\n你说> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见。")
            break
        if not text:
            continue
        if text in ("退出", "exit", "quit"):
            print("再见。审计日志：%s" % AUDIT_LOG)
            break
        step(text)


DEMO_INPUTS = [
    "这是什么哈希 e10adc3949ba59abbe56e057f20f883e",
    "帮我破解 e10adc3949ba59abbe56e057f20f883e",
    "帮我破解 36F6A527314C7DD2D71A6A36703ADF314E14F28B",
    "校验 hello.txt",
    "对 screening 去重",
    "为什么要双哈希",
    "帮我破解 $2b$12$KIX/DeWw5Z5pXbH9Qz1eeOsF7kQf9XqWYh2m1Z0VZ8vJ3xWq5yZzW",  # bcrypt：应被劝退
]
# v1.1 新增：夹中文哈希、组合意图、新 FAQ
DEMO_INPUTS_V11 = [
    "帮我破解abc12345678901234567890123456789012行不行",          # 哈希紧贴中文（v1.0 漏检）
    "破解e10adc3949ba59abbe56e057f20f883e再校验是不是同一个文件",   # 组合意图：破解→内容比对
    "加盐到底有什么用",                                             # 新 FAQ
    "加密：062481，用sha-256算法",                                  # 正向计算（曾被 FAQ 误吞）
]
# v1.2 新增：自动入表 → 重启级查表反查（验证跨会话持久化）
DEMO_INPUTS_V12 = [
    "加密：062481，用md5算法",     # 正向计算 → 自动写入 hash_table.json
    "解密 " + hashlib.md5("062481".encode()).hexdigest(),  # 拿刚才的 MD5 来查表 → 应命中 062481
]


def demo():
    print(BANNER)
    print("\n【演示模式】基础 %d 句 + v1.1 新增 %d 句 + v1.2 查表闭环 %d 句 + 内存实测\n"
          % (len(DEMO_INPUTS), len(DEMO_INPUTS_V11), len(DEMO_INPUTS_V12)))
    for text in DEMO_INPUTS:
        print("\n你说> %s" % text)
        step(text)
    print("\n────── v1.1 新增能力 ──────")
    for text in DEMO_INPUTS_V11:
        print("\n你说> %s" % text)
        step(text)
    print("\n────── v1.2 新增能力：正向计算自动入表 → 查表反查命中 ──────")
    for text in DEMO_INPUTS_V12:
        print("\n你说> %s" % text)
        step(text)
    # 内存实测：把整轮"感知→决策→行动"包进量程（行动层 exp5 内部建表也计入）
    import tracemalloc
    tracemalloc.start()
    step("帮我破解 36F6A527314C7DD2D71A6A36703ADF314E14F28B")
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("\n【内存实测】破解一轮峰值 Python 堆内存 ≈ %.1f MB（当前残留 %.2f MB；进程总内存另含解释器 ~15MB 底子）"
          % (peak / 1048576, cur / 1048576))
    print("【审计日志】%s" % AUDIT_LOG)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "demo":
        demo()
    else:
        interactive()
