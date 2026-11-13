"""业务层：零依赖密码强度评分（P4 密码健康审计专用）。

License 说明：全部自实现，未复制任何第三方代码。KeePassXC（GPL-2/3）、
Bitwarden clients（GPL-3 + Bitwarden License）仅做思路级借鉴：
- 等级五档分界（Bad/Poor/Weak/Good/Excellent）照 KeePassXC quality() 语义；
- 长度 ≥25 跳过重熵类规则（KeePassXC Length::Long=25 思路）、
  逐字符分析截断前 256 字符（其 ZXCVBN_ESTIMATE_THRESHOLD=256 思路）；
- 用户名 token 扣分借鉴 Bitwarden 弱口令报告的 user-input 检测
  （email 本地部分按非字母数字切分、长度 ≥3、小写）。

评分模型（对数熵基准 + 规则扣分，0-100）：
  base_bits = len(pw) * log2(字符池大小)
  字符池 = 26 小写 + 26 大写 + 10 数字 + 34 符号/空格 +（含 CJK 码点再补 40）
  扣分：纯数字 -20；字母/数字/键盘序列段每段 -10；同字符连打 ≥3 -10；
        含 19xx/20xx 年份 -10；命中内置常见口令词典 → 直接 Bad(0)；
        包含本条目用户名 token -25。
  等级：score ≤0 Bad / <40 Poor / <75 Weak / <100 Good / ≥100 Excellent。
  复用惩罚：每多复用一次 -15，且最终分封顶 74（复用口令不得评为 Good）。
  到期惩罚：30 天内到期先封顶 70 再每天 -2；已过期 = 0。

明文仅经本模块计算后立即丢弃，不做任何落盘/落日志。
"""
import hashlib
import math
import re
import threading

# ---------- 内置常见弱口令词典（精确匹配，即命中直接评 Bad） ----------
# 收录泄露口令统计中最高频的条目（含中西文常见组合与年份变体）。
# 完整 top1000 体积收益有限，按「落地规格：常见弱口令小词典」取约 500 条。
COMMON_PASSWORDS = frozenset({
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "1234567890", "1234567", "111111", "123123", "abc123", "password1",
    "1234", "12345678910", "000000", "iloveyou", "1q2w3e4r", "qwerty123",
    "zaq12wsx", "dragon", "sunshine", "princess", "letmein", "654321",
    "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop", "superman",
    "asdfghjkl", "1q2w3e4r5t", "asdfgh", "charlie", "welcome", "login",
    "master", "hello", "freedom", "whatever", "qazwsx", "trustno1",
    "batman", "baseball", "shadow", "michael", "football", "jordan23",
    "harley", "ranger", "buster", "thomas", "tigger", "robert", "soccer",
    "hockey", "killer", "george", "sexy", "andrew", "charlie1", "jordan",
    "jennifer", "hunter", "buster1", "thunder", "tigger1", "purple",
    "fuckyou", "fuckme", "secret", "diamond", "aiden",
    "corvette", "cookie", "nicholas", "mercedes", "taylor", "summer",
    "heather", "scooter", "jasmine", "chelsea", "amanda",
    "123qwe", "qwe123", "a123456", "a123456789", "aa123456", "abc123456",
    "1234qwer", "q1w2e3r4", "zxcvbnm", "zxcvbn", "poiuytrewq", "lkjhgfdsa",
    "mnbvcxz", "0987654321", "987654321", "159357", "753951", "147258369",
    "147852369", "741852963", "159753", "321654", "789456123", "13579",
    "246810", "112233", "121314", "101010", "102030", "112358", "147258",
    "15935748", "520520", "1314520", "woaini", "woaini520", "woaini1314",
    "7758521", "5211314", "nihao", "nimeia", "caonima", "cnm123", "woshishui",
    "zhangweigen", "123456a", "123456abc", "123456q", "abcd1234", "abcd123456",
    "p@ssw0rd", "p@ssword", "passw0rd", "passw0rd!", "pass1234", "pass123",
    "password!", "password12", "password123", "password1234", "Password1",
    "Password123", "Password123!", "Passw0rd", "Passw0rd!", "P@ssw0rd",
    "P@ssw0rd1", "P@ssword1", "Qwerty123", "qwerty12", "qweasdzxc",
    "admin", "admin1", "admin12", "admin123", "admin1234", "admin12345",
    "admin123456", "admin888", "admin666", "admin2023", "admin2024",
    "admin2025", "administrator", "root", "root123", "toor", "root1234",
    "test", "test123", "test1234", "guest", "guest123", "user", "user123",
    "oracle", "oracle123", "mysql", "mysql123", "postgres", "sa123456",
    "changeme", "changeme1", "changeit", "letmein1", "letmein123",
    "welcome1", "welcome123", "welcome2023", "monkey123", "dragon123",
    "sunshine1", "princess1", "superman1", "batman123", "starwars",
    "solo", "yoda", "chewbacca", "skynet", "matrix", "nebula", "nokia",
    "samsung", "xiaomi", "huawei", "huawei123", "honor", "android",
    "iphone", "apple", "apple123", "google", "google123", "baidu",
    "baidu123", "qq123456", "qq123456789", "taobao", "wechat", "weixin",
    "alipay", "12345678a", "a12345678", "asd123456", "asdasd", "asdasd123",
    "qazxsw", "qazwsxedc", "1qazxsw2", "2wsx3edc", "qweqwe", "qweqwe123",
    "aaabbb", "aaa111", "aaa123", "bbb123", "xyz123456", "iloveyou1",
    "iloveyou2", "iloveyou123", "loveyou", "loveyou520", "5201314",
    "88888888", "66666666", "99999999", "8888888", "6666666", "888888",
    "666666", "999999", "123654", "159951", "1593570", "1123581321",
    "12341234", "11223344", "121212", "1234321", "104434", "123698745",
    "10203040", "5040302010", "1234554321", "123456654321", "abcdef",
    "abcdefg", "abcdefgh", "qwerty123456", "qaz123456", "asd12345",
    "zxc123456", "1a2b3c4d", "1a2a3a4a", "aa123456789", "abcd@1234",
    "abcd1234!", "abcd12345678", "abc@123", "abc@123456", "test123456",
    "123.com", "12306", "1230612306", "123456.", "123456.com", "11111111",
    "1213123", "159753456", "a1234567890", "abcd", "abcde", "aaaaaa",
    "aaaaaaa", "aaaaaaaa", "1111111", "12121212", "88888888a", "666888",
    "168168", "521521", "13141314", "520131400", "wo520ni", "aini1314",
    "password2023", "password2024", "password2025", "password2026",
    "admin@123", "admin#123", "admin!123", "Admin123", "Admin@123",
    "root@123", "test@123", "123456789q", "qqqqqq", "qq1234567",
    "abcd1234abcd", "1122334455", "123456987", "1472583690", "2023",
    "2024", "2025", "2026", "2019", "2018", "2017", "2016", "2015",
    "1230", "12300", "password1!", "passwort", "contrasena", "motdepasse",
    "1q2w3e", "1q2w3e4r5t6y", "q1w2e3", "q1w2e3r4t5", "z1x2c3v4",
    "zaqwsx", "12qwaszx", "qwerty1", "asdf1234", "asdfjkl", "hjkl;",
    "qpalzm", "1234abcd", "4321dcba", "1234qaz", "qaz123", "wsx123",
    "edc123", "123qaz", "123wsx", "123edc", "a1b2c3d4", "a1b2c3",
    "q123456", "q123456789", "z123456", "w123456", "s123456", "x123456",
    "e123456", "d123456", "c123456", "r123456", "f123456", "v123456",
    "t123456", "g123456", "b123456", "y123456", "h123456", "n123456",
    "u123456", "j123456", "m123456", "i123456", "k123456", "o123456",
    "p123456", "l123456", "1234567890q", "987654321a", "0123456789",
    "123456789.", "1357924680", "2468135790", "1234567891", "1234567892",
    "1234567893", "1234567894", "1234567895", "1234567896", "1234567897",
    "1234567898", "1234567899", "1020304050", "152637485960", "13572468",
    "24681012", "3691215", "48121620", "1234560", "12345600", "123456000",
    "00000000", "000000000", "1212121212", "77777777", "55555555",
    "33333333", "44444444", "22222222", "112233445566", "11235813",
})

_YEAR_RE = re.compile(r"(19|20)\d{2}")
# 键盘横排序列（qwerty 行），出现 ≥3 连续子串视为键盘序列段
_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
# 分析截断：超过 256 字符只对前 256 做模式/字符池分析，熵按全长外推
_ANALYSIS_CAP = 256
# 长度达到该值跳过重熵类规则（序列/连打/年份/纯数字），仅保留词典与用户名检测
_LONG_PASSWORD = 25

_SEQ_REASONS = {
    "seq_alpha": "包含连续字母序列（如 abc/xyz）",
    "seq_digit": "包含连续数字序列（如 123/456）",
    "seq_keyboard": "包含键盘横排序列（如 qwerty）",
    "repeat": "同一字符连续出现 3 次以上",
    "year": "包含 19xx/20xx 年份数字",
    "digits_only": "纯数字口令，抗爆破能力极弱",
    "username": "包含本条目用户名片段",
    "common": "命中内置常见弱口令词典",
}

# 评分缓存：按 (口令SHA-256摘要, username) 记忆化（Bitwarden 报告 cache 思路）。
# v0.1.0 修复 S-07：键不使用明文口令本身，避免真实口令长期驻留内存。
# 上限保护：超过即整体清空（审计场景同一 run 内命中率高，缓存只增不减）。
_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 200000


def _pool_size(sample: str) -> int:
    """按口令实际出现的字符类别计算字符池大小。"""
    pool = 0
    if any(c.islower() for c in sample):
        pool += 26
    if any(c.isupper() for c in sample):
        pool += 26
    if any(c.isdigit() for c in sample):
        pool += 10
    # 非字母数字剩余字符按符号/空格池计（33 符号 + 空格 = 34）
    if any(not c.isalnum() for c in sample):
        pool += 34
    # 含超出基本拉丁的宽字符（CJK 等）：isascii() 为假即补足大码点空间
    if any(not c.isascii() for c in sample):
        pool += 40
    return max(pool, 1)


def _username_tokens(username: str) -> list[str]:
    """提取用户名检测 token：email 先取本地部分，再按非字母数字切分，
    保留长度 ≥3 的全部小写片段（Bitwarden user-input 检测思路）。

    修复：本地部分若含点号（如 ops.zhangwei@corp.cn），此前 split 拆出
    ["ops","zhangwei"] 后只保了片段列表——正确；但对无分隔符的本地部分
    （如 zhangwei@corp.cn）拆分后为 ["zhangwei"]，同样正确。真正漏检的
    场景是：本地部分本身是带点复合名时，完整本地部分（去点）也应视为
    token（用户常用全名做口令），故两种粒度都收集。
    """
    if not username:
        return []
    name = str(username).strip().lower()
    if "@" in name:
        name = name.split("@", 1)[0]
    tokens: list[str] = []
    parts = [p for p in re.split(r"[^0-9a-z\u4e00-\u9fff]+", name)
             if len(p) >= 3]
    tokens.extend(parts)
    if len(parts) > 1:
        whole = "".join(parts)
        if len(whole) >= 3:
            tokens.append(whole)
    return tokens


def _find_patterns(sample: str) -> list[str]:
    """识别可机械预测的序列/重复/年份等模式段（仅在小写化样本上做匹配）。"""
    reasons: list[str] = []
    low = sample.lower()

    # 字母序列：连续递增 ≥3（abc、xyz）
    run = 1
    has_alpha_seq = False
    for i in range(1, len(low)):
        prev, cur = low[i - 1], low[i]
        if prev.isalpha() and cur.isalpha() and ord(cur) - ord(prev) == 1:
            run += 1
            if run >= 3:
                has_alpha_seq = True
                break
        else:
            run = 1
    if has_alpha_seq:
        reasons.append("seq_alpha")

    # 数字序列：连续递增 ≥3（123、456）
    run, has_digit_seq = 1, False
    for i in range(1, len(low)):
        prev, cur = low[i - 1], low[i]
        if prev.isdigit() and cur.isdigit() and int(cur) - int(prev) == 1:
            run += 1
            if run >= 3:
                has_digit_seq = True
                break
        else:
            run = 1
    if has_digit_seq:
        reasons.append("seq_digit")

    # 键盘横排序列（qwerty/asdf/zxcv 行内 ≥3 连续）
    if any(row[i:i + 3] in low for row in _KEYBOARD_ROWS
           for i in range(len(row) - 2)):
        reasons.append("seq_keyboard")

    # 同字符连打 ≥3
    if re.search(r"(.)\1{2,}", sample):
        reasons.append("repeat")

    if _YEAR_RE.search(sample):
        reasons.append("year")

    if sample.isdigit():
        reasons.append("digits_only")
    return reasons


def base_score(password: str, username: str = "") -> tuple[int, list[str]]:
    """基础强度评分。返回 (0-100 分数, 命中原因代码列表)。

    password 为空串时返回 (0, ["common"])（空口令按最差处理）。
    """
    if not password:
        return 0, ["common"]

    cache_key = (hashlib.sha256(password.encode("utf-8")).hexdigest(),
                 username or "")
    with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    sample = password[:_ANALYSIS_CAP]  # 逐字符分析截断，熵按全长外推
    reasons = _find_patterns(sample)
    long_pw = len(password) >= _LONG_PASSWORD
    if long_pw:
        # 长口令跳过重熵类规则（KeePassXC Length::Long 思路）：这些模式
        # 段在超长口令上不扣分，也不在报告中展示（避免"有原因无扣分"的混淆）
        reasons = []

    tokens = _username_tokens(username)
    low_sample = sample.lower()
    if tokens and any(t in low_sample for t in tokens):
        reasons.append("username")

    if password.lower() in COMMON_PASSWORDS:
        score, reasons = 0, ["common"]
    else:
        bits = len(password) * math.log2(_pool_size(sample))
        penalty = 0
        if not long_pw:
            if "digits_only" in reasons:
                penalty += 20
            penalty += 10 * reasons.count("seq_alpha")
            penalty += 10 * reasons.count("seq_digit")
            penalty += 10 * reasons.count("seq_keyboard")
            if "repeat" in reasons:
                penalty += 10
            if "year" in reasons:
                penalty += 10
        if "username" in reasons:
            penalty += 25
        score = max(0, min(100, round(bits - penalty)))

    result = (score, reasons)
    # v0.1.0 修复 S-07：缓存键改为口令的 SHA-256 摘要，不再以明文为 key。
    # 明文 key 会让最多 20 万条真实口令长期驻留进程内存，与"明文只在
    # 服务端内存中短暂存活、用后即弃"的设计承诺相悖；换成摘要后缓存仍
    # 完全有效（同一口令必然得到同一评分），却不再持有明文本身。
    cache_key = (hashlib.sha256(password.encode("utf-8")).hexdigest(),
                 username or "")
    with _CACHE_LOCK:
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()
        _CACHE[cache_key] = result
    return result


def grade(score: int) -> str:
    """等级五档（分界照 KeePassXC quality() 语义）。"""
    if score <= 0:
        return "Bad"
    if score < 40:
        return "Poor"
    if score < 75:
        return "Weak"
    if score < 100:
        return "Good"
    return "Excellent"


def final_score(score: int, *, reuse_count: int = 1,
                expire_in_days: int | None = None,
                expired: bool = False) -> int:
    """应用复用与到期惩罚后的最终评分（仅用于展示/排序，不回写评分基准）。"""
    final = score
    if expired:
        return 0
    if reuse_count and reuse_count > 1:
        final = final - 15 * (reuse_count - 1)
        final = min(final, 74)  # 复用口令封顶 74（不得评为 Good）
    if expire_in_days is not None and 0 <= expire_in_days <= 30:
        final = min(final, 70) - 2 * expire_in_days
    return max(0, final)


def reason_text(code: str) -> str:
    """原因代码 -> 可读文案。"""
    return _SEQ_REASONS.get(code, code)
