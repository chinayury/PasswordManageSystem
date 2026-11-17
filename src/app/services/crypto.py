"""业务层：加解密与安全随机。

- 存量密文解不开时抛 CryptoError，由上层决定展示与处理策略，
  根治旧版"解密失败把密文当明文回显、保存时再加密一次导致数据损坏"的缺陷。
- 随机数全部使用 secrets（密码学安全），弃用旧版 random 模块。
"""
import secrets
import string

from cryptography.fernet import Fernet, InvalidToken


class CryptoError(Exception):
    """密文无法解密（通常是 ENCRYPTION_KEY 变更过）。"""


class CryptoService:
    def __init__(self, key: str):
        self._fernet = Fernet(key.encode())

    def encrypt(self, plaintext: str) -> str:
        if plaintext is None:
            plaintext = ""
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except (InvalidToken, TypeError, ValueError) as exc:
            raise CryptoError("密文无法解密：加密密钥可能已变更") from exc

    def decrypt_or_none(self, token: str):
        """解密失败返回 None（fail-soft）。空值（None/""）同样返回 None，
        与方法名语义一致；调用方无需再自行判空。"""
        if not token:
            return None
        try:
            return self.decrypt(token)
        except CryptoError:
            return None


_crypto: CryptoService | None = None


def init_crypto(key: str) -> None:
    global _crypto
    _crypto = CryptoService(key)


def crypto() -> CryptoService:
    if _crypto is None:
        raise RuntimeError("CryptoService 尚未初始化")
    return _crypto


SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# 排除易混淆字符（借鉴 Bitwarden 生成器 "avoid ambiguous characters"）：
# 大小写 iIl、字母 O/o、数字 0/1、竖线——打印或手抄口令时最易看错
SIMILAR_CHARS = set("iIlOo01|")


def _shuffle_secure(items: list) -> list:
    """密码学安全的 Fisher-Yates 洗牌（secrets 模块）。"""
    out = list(items)
    for i in range(len(out) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        out[i], out[j] = out[j], out[i]
    return out


# v0.1.0 第六轮（借鉴 GB-43 · CipherMoth）：口令生成统一走 secrets 模块
# （CSPRNG）。secrets.choice 内部对序列做"拒绝采样"，不存在 random.choice
# 那样的取模偏差；严禁为"看起来更随机"改用 random 模块。
def generate_secure_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    no_similar: bool = False,
) -> str:
    """密码学安全的随机密码生成。长度强制 8~64。

    no_similar=True 时剔除易混淆字符；保证每个被选中的字符池至少
    贡献一位（旧版不保证，存在"16 位里一个符号都没有"的抽样可能）。
    全部字符集被关闭时回退为字母+数字（与旧版行为一致）。
    """
    length = max(8, min(int(length), 64))
    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_special:
        pools.append(SPECIAL_CHARS)
    if no_similar:
        pools = ["".join(c for c in pool if c not in SIMILAR_CHARS) for pool in pools]
        pools = [p for p in pools if p]
    if not pools:
        fallback = string.ascii_letters + string.digits
        if no_similar:
            fallback = "".join(c for c in fallback if c not in SIMILAR_CHARS)
        pools = [fallback]

    if length < len(pools):
        length = len(pools)
    picks = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    picks.extend(secrets.choice(all_chars) for _ in range(length - len(picks)))
    return "".join(_shuffle_secure(picks))


PASSPHRASE_SEPARATORS = ("-", "_", ".", " ")


def generate_passphrase(
    words: int = 5,
    separator: str = "-",
    capitalize: bool = True,
    append_digit: bool = True,
) -> str:
    """易记口令短语模式（借鉴 Bitwarden/KeePassXC 生成器）。

    内置词表见 wordlist.WORDLIST（每词约 8.8 bit 熵），默认
    5 词 + 两位数字 ≈ 50 bit；参数异常时钳制到安全范围而不是报错，
    分隔符只允许 -/_/. 与空格，其余一律回退为 "-"。
    """
    words = max(3, min(int(words), 10))
    if separator not in PASSPHRASE_SEPARATORS:
        separator = "-"
    from .wordlist import WORDLIST

    parts = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        parts = [w.capitalize() for w in parts]
    phrase = separator.join(parts)
    if append_digit:
        phrase += separator + str(secrets.randbelow(90) + 10)
    return phrase


def generate_numeric_code(length: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_api_key() -> str:
    """生成 API 密钥明文（pmk_ 前缀，仅创建时可见一次）。"""
    import base64

    return "pmk_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def hash_api_key(plaintext: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(plaintext.encode()).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    """常数时间字符串比较。

    v0.1.0 修复 B-03：hmac.compare_digest 只接受"两侧均为 ASCII str"
    或"两侧均为 bytes"。用户输入含非 ASCII（如中文验证码框）时直接调用
    会抛 TypeError，把"验证码错误"变成 HTTP 500。此处统一转 UTF-8 字节
    后比较——字节比较同样是常数时间，语义不变。
    """
    import hmac

    if a is None or b is None:
        return False
    try:
        return hmac.compare_digest(str(a).encode("utf-8"),
                                   str(b).encode("utf-8"))
    except (TypeError, UnicodeEncodeError):
        return False
