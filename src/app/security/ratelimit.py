"""安全层：内存滑动窗口限流器。

说明：单进程部署（waitress 单实例）下完全有效；多进程部署时为
每进程独立计数，仍具备基本防护能力。键由调用方组合（IP/用户名/邮箱）。
"""
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    # 键数量上限：超过即触发一次过期清扫。任意可变输入（如随机用户名）
    # 都会成为限流键，无上限会在长期运行中缓慢吃掉进程内存（内存 DoS 面）。
    _MAX_KEYS = 20000
    # 清扫保守窗口：项目内最大限流窗口为 1 小时，取 24 小时兜底
    _PRUNE_WINDOW = 86400

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune_stale(self, now: float) -> None:
        """摘除长期无命中的键（仅在上限附近才执行，均摊开销可忽略）。"""
        stale = [k for k, dq in self._hits.items()
                 if not dq or dq[0] <= now - self._PRUNE_WINDOW]
        for k in stale:
            self._hits.pop(k, None)

    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """记录一次命中。返回 (是否放行, 建议等待秒数)。"""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) >= self._MAX_KEYS:
                self._prune_stale(now)
            bucket = self._hits[key]
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = int(window - (now - bucket[0])) + 1
                return False, max(retry_after, 1)
            bucket.append(now)
            return True, 0

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def clear(self) -> None:
        """清空全部计数（测试隔离用）。"""
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def client_ip() -> str:
    """客户端 IP。

    v0.1.0：仅在 TRUST_PROXY=true（部署于可信反向代理之后）时才采信
    X-Forwarded-For；默认使用对端直连地址，防止客户端伪造 XFF
    轮换"IP"绕过 IP 维度限流与 用户名+IP 锁定。

    v0.1.0 修复 S-05：采信 XFF 时取**最后一段**而非第一段。
    X-Forwarded-For 由每一跳代理追加（client, proxy1, proxy2…），
    最左段完全由客户端控制；取最左段等于允许攻击者每次请求换一个
    伪造 IP，把 IP 维度限流与持久化锁定全部绕过。单层可信代理场景下
    最后一段正是代理观察到的真实对端地址。
    """
    from flask import current_app, request

    try:
        trust_proxy = bool(current_app.config.get("TRUST_PROXY"))
    except RuntimeError:  # 无应用上下文（极端情况）：按不信任处理
        trust_proxy = False
    if trust_proxy:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            candidate = fwd.split(",")[-1].strip()
            if candidate:
                return candidate
    return request.remote_addr or "unknown"
