"""业务层：HIBP（Have I Been Pwned）k-匿名口令泄露查询（默认关闭）。

k-匿名协议（Bitwarden audit.service.ts 与 KeePassXC HibpDownloader 思路双印证）：
  sha1(口令) 大写十六进制 -> 仅发送前 5 位前缀请求 {HIBP_RANGE_URL}{prefix}，
  响应每行 "SUFFIX:COUNT"，与本地后缀精确等值匹配取出现次数。
口令明文与完整 SHA-1 永不出服务端；日志/临时文件一律不落。

工程约束：
- 默认 HIBP_ENABLED=false：关闭时零外联，报告页隐藏泄露页签；
- 先去重再查询（两家共同语义）；同一前缀的响应在单次批量内只请求一次；
- 请求间隔节流 HIBP_MIN_INTERVAL_MS（Bitwarden @throttle(100) 默认 100ms）；
- 失败降级：保留已得结果并标记不可用，不阻塞其它类别（KeePassXC
  fetchFailed 思路）；
- User-Agent 固定取 HIBP_USER_AGENT（HIBP 服务要求 UA；照 KeePassXC
  不带版本号，减小指纹）。

实现仅用标准库 urllib，零新增第三方依赖。
"""
import hashlib
import logging
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

DEFAULT_RANGE_URL = "https://api.pwnedpasswords.com/range/"


def count_bucket(count: int) -> str:
    """泄露次数展示分桶（照 KeePassXC countToText 分层）。"""
    if count <= 1:
        return "1 次"
    if count <= 10:
        return "≤10 次"
    if count <= 100:
        return "≤100 次"
    if count <= 1000:
        return "≤1000 次"
    if count <= 10000:
        return "≤1 万次"
    if count <= 100000:
        return "≤10 万次"
    if count <= 1000000:
        return "≤100 万次"
    return "百万次以上"


class HibpClient:
    """单次审计 run 内使用的 HIBP 查询客户端（含节流与前缀响应缓存）。"""

    # v0.1.0 第六轮修复 BU-16：前缀响应缓存原先无字节/条数上限。一个 run 内
    # 去重后的 SHA-1 前缀最多可达条目数（MAX_ITEMS=200000），每个前缀响应
    # 通常数十 KB、单前缀上限 2MB——10 万量级前缀 ≈ 数 GB 常驻，直接把审计
    # 请求推向 OOM。现加 64MB 字节预算 + FIFO 淘汰（前缀响应短期复用率
    # 高，LRU 的收益不足以抵消维护成本，FIFO 已足够）。
    _CACHE_MAX_BYTES = 64 * 1024 * 1024

    def __init__(self, range_url: str, timeout_s: float,
                 min_interval_ms: int, user_agent: str):
        self._range_url = (range_url or DEFAULT_RANGE_URL).rstrip("/") + "/"
        self._timeout = max(1.0, float(timeout_s))
        self._interval = max(0, int(min_interval_ms)) / 1000.0
        self._ua = user_agent or "PasswordManageSystem"
        self._last_request = 0.0  # monotonic，用于节流
        self._prefix_cache: dict[str, str] = {}
        self._cache_bytes = 0  # 当前缓存占用字节数（BU-16）

    def _cache_put(self, prefix: str, body: str) -> None:
        """写入前缀缓存并按字节预算 FIFO 淘汰（BU-16）。"""
        size = len(body.encode("utf-8", errors="replace"))
        # 单条就超预算：直接不缓存（宁可多查一次，不可常驻超限）
        if size > self._CACHE_MAX_BYTES:
            logger.warning("HIBP 前缀响应 %s 大小 %d 字节超过缓存预算，跳过缓存",
                           prefix, size)
            return
        self._prefix_cache[prefix] = body
        self._cache_bytes += size
        while (self._cache_bytes > self._CACHE_MAX_BYTES
               and len(self._prefix_cache) > 1):
            oldest = next(iter(self._prefix_cache))
            evicted = self._prefix_cache.pop(oldest)
            self._cache_bytes -= len(evicted.encode("utf-8", errors="replace"))

    def _throttle(self) -> None:
        now = time.monotonic()
        wait = self._interval - (now - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def _fetch_prefix(self, prefix: str) -> str:
        """请求一个 5 位前缀，返回响应正文文本。失败抛异常由上层降级。"""
        cached = self._prefix_cache.get(prefix)
        if cached is not None:
            return cached
        self._throttle()
        url = self._range_url + prefix
        req = urllib.request.Request(
            url, headers={"User-Agent": self._ua, "Accept": "text/plain"})
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            body = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
        self._cache_put(prefix, body)
        return body

    def _count_for(self, sha1_upper: str, body: str) -> int:
        """在已取回的前缀响应中精确匹配本口令后缀，返回出现次数。"""
        suffix = sha1_upper[5:]
        for line in body.splitlines():
            # 响应行形如 "SUFFIX:COUNT"（容忍行尾空白）；逐行等值匹配，
            # 避免 startswith 前缀碰撞（如 AB1 匹配 AB12）
            head, _, tail = line.partition(":")
            if head.strip() == suffix:
                try:
                    return int(tail.strip() or "0")
                except ValueError:
                    return 0
        return 0

    def query_counts(self, passwords) -> tuple[dict[str, int], bool]:
        """便捷入口：明文批量查询（内部即时哈希后丢弃明文）。

        返回 ({sha1_hex_upper: count}, available)。失败降级保留已得结果，
        available=False；调用方据此在报告页标注 "HIBP 暂不可用"。
        """
        sha1s = {
            hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
            for pw in passwords if pw
        }
        return self.query_counts_sha1(sha1s)

    def query_counts_sha1(self, sha1_set) -> tuple[dict[str, int], bool]:
        """批量查询 SHA-1 大写十六进制集合（先去重，两家实现共同语义）。

        返回 ({sha1_hex_upper: count}, available)。网络失败降级：
        保留已得结果，available=False；不阻塞其它类别分析。
        """
        uniq = {s.upper() for s in sha1_set if s}
        counts: dict[str, int] = {}
        prefixes: dict[str, list[str]] = {}
        for digest in uniq:
            prefixes.setdefault(digest[:5], []).append(digest)

        available = True
        for prefix, digests in prefixes.items():
            try:
                body = self._fetch_prefix(prefix)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                # 单个前缀失败即整体降级（继续请求大概率同样失败且徒增耗时）
                logger.warning("HIBP 查询失败（前缀 %s**）：%s", prefix, exc)
                available = False
                break
            for digest in digests:
                n = self._count_for(digest, body)
                if n > 0:
                    counts[digest] = n
        return counts, available


def client_from_config() -> HibpClient | None:
    """按应用配置构造客户端；HIBP_ENABLED=false（默认）时返回 None（零外联）。"""
    from flask import current_app

    if not current_app.config.get("HIBP_ENABLED"):
        return None
    return HibpClient(
        range_url=current_app.config.get("HIBP_RANGE_URL", DEFAULT_RANGE_URL),
        timeout_s=current_app.config.get("HIBP_TIMEOUT_S", 10),
        min_interval_ms=current_app.config.get("HIBP_MIN_INTERVAL_MS", 100),
        user_agent=current_app.config.get("HIBP_USER_AGENT",
                                          "PasswordManageSystem"),
    )
