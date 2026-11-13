"""业务层：服务端一次性机密传递（v0.1.0 新增）。

背景（S-02）：Flask 的 session cookie 只做签名、不做加密，客户端
Base64 解码即可读到全部内容。此前"新建 API 密钥的明文"与"管理员重置
的临时口令"都经 session/flash 传递，等于把凭据明文暴露给浏览器端。

本模块提供进程内一次性凭据仓：POST 时把明文写入仓内并只把随机
不透明 token 放进 session；下一次 GET 凭 token 换取明文后立即销毁。
token 本身不含任何信息，泄露了也无法反推出凭据。
"""
import logging
import secrets
import threading
import time

logger = logging.getLogger(__name__)

# 条目存活上限（秒）：超过即视为已消费/失效，防止长期驻留内存
_TTL_SECONDS = 300
# 条目数量上限：超出时清理最旧的，避免无界增长
_MAX_ENTRIES = 256


class OneTimeSecretStore:
    """线程安全的一次性机密仓（进程内，多 worker 部署时仅当前进程可见）。

    注意：因此类机密只在内存中存活一个请求周期，多进程/多 worker 部署
    （gunicorn 多 worker）下换取必须发生在同一进程。本项目默认单实例
    waitress 单进程部署，Docker 镜像亦为单容器单进程，故满足前提；
    若改造为多 worker，应改为共享存储（Redis 等）。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, tuple[str, float]] = {}

    def put(self, secret: str, ttl: int = _TTL_SECONDS) -> str:
        """存入机密，返回不透明 token（不含机密内容）。"""
        token = secrets.token_urlsafe(24)
        expires = time.monotonic() + max(1, ttl)
        with self._lock:
            self._gc_locked()
            self._data[token] = (secret, expires)
        return token

    def pop(self, token, ttl: int = _TTL_SECONDS) -> str | None:
        """取出并立即销毁机密；token 无效/过期/不存在返回 None。"""
        if not token or not isinstance(token, str):
            return None
        now = time.monotonic()
        with self._lock:
            item = self._data.pop(token, None)
        if item is None:
            return None
        secret, expires = item
        if expires < now or now - (expires - max(1, ttl)) > max(1, ttl) * 2:
            # 过期条目：不返回
            return None
        return secret

    def _gc_locked(self) -> None:
        now = time.monotonic()
        for tok, (_, exp) in list(self._data.items()):
            if exp < now:
                self._data.pop(tok, None)
        # 仍超限则淘汰最早过期的若干条
        while len(self._data) >= _MAX_ENTRIES:
            oldest = min(self._data.items(), key=lambda kv: kv[1][1])[0]
            self._data.pop(oldest, None)

    def clear(self) -> None:
        """清空（测试隔离用）。"""
        with self._lock:
            self._data.clear()


# 进程内单例
store = OneTimeSecretStore()
