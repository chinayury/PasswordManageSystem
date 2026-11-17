"""v0.2.3 回归：加密层与 TOTP 基线。

依赖升级（cryptography 44→50、pyotp 2.9→2.12）前后行为必须一致：
Fernet 加解密往返、非法 token fail-closed、生成器输出形态、TOTP 校验与
provisioning URI。此前加密层无直接测试，本轮补上作为升级基线。
"""
import pytest
from cryptography.fernet import Fernet

from app.services import crypto as crypto_mod
from app.services import totp as totp_mod
from app.services.crypto import (CryptoError, constant_time_equal,
                                 generate_api_key, generate_numeric_code,
                                 generate_passphrase, generate_secure_password,
                                 hash_api_key, init_crypto)


@pytest.fixture(autouse=True)
def _crypto_ready():
    init_crypto(Fernet.generate_key().decode())


def test_fernet_roundtrip():
    svc = crypto_mod.crypto()
    token = svc.encrypt("p@ss-w0rd!中文")
    assert svc.decrypt(token) == "p@ss-w0rd!中文"
    assert token != "p@ss-w0rd!中文"                      # 库里不落明文
    assert svc.encrypt("x") != svc.encrypt("x")           # 每次 IV 随机


def test_decrypt_or_none_and_invalid_token():
    svc = crypto_mod.crypto()
    assert svc.decrypt_or_none(None) is None       # 空值防护（v0.2.3 起）
    assert svc.decrypt_or_none("") is None
    assert svc.decrypt_or_none(svc.encrypt("abc")) == "abc"
    with pytest.raises(CryptoError):
        svc.decrypt("not-a-valid-fernet-token")
    assert svc.decrypt_or_none("not-a-valid-fernet-token") is None


def test_generators_basic():
    pw = generate_secure_password(length=20)
    assert len(pw) == 20
    assert any(c.isdigit() for c in pw) and any(c.isupper() for c in pw)
    assert generate_secure_password() != generate_secure_password()  # CSPRNG
    parts = generate_passphrase().split("-")
    assert len(parts) == 6 and parts[-1].isdigit()   # 5 词 + 末尾数字段
    code = generate_numeric_code()
    assert len(code) == 6 and code.isdigit()
    key = generate_api_key()
    assert len(key) >= 32 and hash_api_key(key) != key
    assert constant_time_equal("a", "a") is True
    assert constant_time_equal("a", "b") is False


def test_totp_verify_and_uri():
    import pyotp

    secret = totp_mod.generate_secret()
    assert len(secret) >= 16
    code = pyotp.TOTP(secret).now()
    assert totp_mod._verify_totp(secret, code) is True
    assert totp_mod._verify_totp(secret, "123456789") is False  # 长度非法
    uri = totp_mod.provisioning_uri(secret, "alice")
    assert uri.startswith("otpauth://totp/") and secret in uri
