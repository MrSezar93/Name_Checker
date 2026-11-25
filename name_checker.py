#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
name_checker.py
================
بررسی آزاد بودن یک نام (فارسی + انگلیسی) در:
  • دامنه‌های .ir / .ایران / .co.ir و ... (از طریق WHOIS ایرنیک + DNS)
  • اینستاگرام
  • توییتر (X)
  • تلگرام (+ بررسی Fragment برای یوزرنیم‌های حراجی)
  • بله

نصب پیش‌نیازها:
    pip install requests
    pip install rich idna        # اختیاری: خروجی رنگی + پشتیبانی بهتر از دامنه فارسی
    pip install "requests[socks]" # اختیاری: اگر پراکسی SOCKS دارید

نمونه اجرا:
    python name_checker.py --fa "علی رضایی" --en "ali rezaei"
    python name_checker.py --fa "دیجی کالا" --en digikala --variants --proxy socks5h://127.0.0.1:1080
    python name_checker.py --en mybrand --only instagram,telegram --json out.json --csv out.csv
    python name_checker.py            # حالت تعاملی: نام‌ها را می‌پرسد

نکته: اینستاگرام و X در ایران فیلتر هستند؛ برای نتیجه درست آن‌ها از --proxy استفاده کنید.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import json
import random
import re
import socket
import string
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover
    sys.exit("کتابخانه requests نصب نیست:  pip install requests")

try:
    import idna as _idna  # IDNA2008 (پشتیبانی از ZWNJ در دامنه فارسی)
except ImportError:
    _idna = None

try:
    from rich.console import Console
    from rich.table import Table
    _console = Console()
except ImportError:
    _console = None


# ───────────────────────────── مدل نتیجه ─────────────────────────────

class Status(str, Enum):
    AVAILABLE = "available"
    TAKEN = "taken"
    RESERVED = "reserved"   # حراجی/فروشی در Fragment یا رزرو شده
    INVALID = "invalid"     # طبق قوانین پلتفرم مجاز نیست
    UNKNOWN = "unknown"     # خطا، محدودیت نرخ یا پاسخ نامشخص


STATUS_FA = {
    Status.AVAILABLE: "✅ آزاد",
    Status.TAKEN: "❌ گرفته شده",
    Status.RESERVED: "💰 رزرو/حراجی",
    Status.INVALID: "⛔ نامعتبر",
    Status.UNKNOWN: "❓ نامشخص",
}
STATUS_COLOR = {
    Status.AVAILABLE: "green",
    Status.TAKEN: "red",
    Status.RESERVED: "yellow",
    Status.INVALID: "magenta",
    Status.UNKNOWN: "bright_black",
}


@dataclass
class Result:
    platform: str
    target: str
    status: Status
    detail: str = ""
    url: str = ""

    def as_dict(self) -> dict:
        return {
            "platform": self.platform,
            "target": self.target,
            "status": self.status.value,
            "status_fa": STATUS_FA[self.status],
            "detail": self.detail,
            "url": self.url,
        }


# ───────────────────────────── HTTP ─────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
]


class Http:
    """یک Session ساده با retry، پراکسی و تأخیر تصادفی برای جلوگیری از بلاک شدن."""

    def __init__(self, proxy: Optional[str], timeout: float, delay: float, retries: int = 2):
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self._local = threading.local()
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def _session(self) -> requests.Session:
        s = getattr(self._local, "s", None)
        if s is None:
            s = requests.Session()
            s.mount("https://", HTTPAdapter(pool_connections=10, pool_maxsize=10))
            if self.proxies:
                s.proxies.update(self.proxies)
            self._local.s = s
        return s

    def get(self, url: str, **kw) -> requests.Response:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
        }
        headers.update(kw.pop("headers", {}) or {})
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            if self.delay:
                time.sleep(random.uniform(0, self.delay))
            try:
                r = self._session().get(url, headers=headers, timeout=self.timeout,
                                        allow_redirects=kw.pop("allow_redirects", True), **kw)
                if r.status_code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    time.sleep(2 ** attempt + random.random())
                    continue
                return r
            except requests.RequestException as e:
                last_exc = e
                if attempt < self.retries:
                    time.sleep(1 + attempt)
        raise last_exc or RuntimeError("request failed")


# ───────────────────────────── نرمال‌سازی نام‌ها ─────────────────────────────

_AR_TO_FA = str.maketrans({
    "ي": "ی", "ى": "ی", "ك": "ک", "ة": "ه", "ۀ": "ه", "أ": "ا", "إ": "ا", "ٱ": "ا",
    "٠": "0", "١": "1", "٢": "2", "٣": "3", "٤": "4", "٥": "5", "٦": "6", "٧": "7", "٨": "8", "٩": "9",
    "۰": "0", "۱": "1", "۲": "2", "۳": "3", "۴": "4", "۵": "5", "۶": "6", "۷": "7", "۸": "8", "۹": "9",
})
_DIACRITICS = re.compile(r"[\u064B-\u065F\u0670\u0640]")  # اعراب و کشیده


def normalize_fa(text: str) -> str:
    text = unicodedata.normalize("NFC", text).translate(_AR_TO_FA)
    text = _DIACRITICS.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def normalize_en(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    text = text.lower()
    text = re.sub(r"[^a-z0-9._\-\s]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def to_ascii_domain(domain: str) -> str:
    """تبدیل دامنه (حتی فارسی) به Punycode."""
    domain = domain.strip(".").lower()
    if _idna is not None:
        try:
            return _idna.encode(domain, uts46=True).decode()
        except _idna.IDNAError:
            pass
    return domain.encode("idna").decode()


def fa_domain_labels(name_fa: str, variants: bool) -> list[str]:
    base = normalize_fa(name_fa)
    words = [w for w in re.split(r"[\s\u200c\-_]+", base) if w]
    if not words:
        return []
    labels = ["".join(words)]
    if len(words) > 1:
        labels.append("-".join(words))
        if variants and "\u200c" in base:
            labels.append(re.sub(r"\s+", "", base))  # با نیم‌فاصله
    return list(dict.fromkeys(labels))


def en_domain_labels(name_en: str, variants: bool) -> list[str]:
    base = normalize_en(name_en)
    words = [w for w in re.split(r"[\s._\-]+", base) if w]
    if not words:
        return []
    labels = ["".join(words)]
    if len(words) > 1:
        labels.append("-".join(words))
    if variants:
        j = "".join(words)
        labels += [f"{j}ir", f"{j}-ir", f"get{j}", f"{j}app", f"{j}online"]
    return list(dict.fromkeys(labels))


def username_candidates(name_en: str, variants: bool) -> list[str]:
    base = normalize_en(name_en)
    words = [w for w in re.split(r"[\s._\-]+", base) if w]
    if not words:
        return []
    joined = "".join(words)
    cands = [joined]
    if len(words) > 1:
        cands += ["_".join(words), ".".join(words)]
    if variants:
        cands += [
            f"{joined}_ir", f"{joined}ir", f"{joined}_official", f"{joined}official",
            f"the{joined}", f"the_{joined}", f"real{joined}", f"iam{joined}",
            f"{joined}_app", f"{joined}hq", f"{joined}_co", f"{joined}team",
        ]
    return list(dict.fromkeys(cands))


# ───────────────────────────── قوانین یوزرنیم ─────────────────────────────

RULES: dict[str, tuple[re.Pattern, str]] = {
    "instagram": (re.compile(r"^(?!\.)(?!.*\.\.)(?!.*\.$)[a-z0-9._]{1,30}$"),
                  "۱ تا ۳۰ کاراکتر؛ حروف کوچک، عدد، نقطه و _ ؛ نقطه نه در ابتدا/انتها و نه پشت‌سرهم"),
    "x": (re.compile(r"^[A-Za-z0-9_]{4,15}$"),
          "۴ تا ۱۵ کاراکتر؛ فقط حروف لاتین، عدد و _"),
    "telegram": (re.compile(r"^[A-Za-z](?!.*__)[A-Za-z0-9_]{3,30}[A-Za-z0-9]$"),
                 "۵ تا ۳۲ کاراکتر؛ شروع با حرف، بدون _ در انتها"),
    "bale": (re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$"),
             "حدود ۵ تا ۳۲ کاراکتر؛ شروع با حرف (قانون تقریبی)"),
}


def validate(platform: str, username: str) -> Optional[str]:
    pattern, msg = RULES[platform]
    if not pattern.match(username):
        return msg
    if platform == "x" and re.search(r"twitter|admin", username, re.I):
        return "نمی‌تواند شامل twitter یا admin باشد"
    return None


# ───────────────────────────── بررسی‌کننده‌ها ─────────────────────────────

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_OG_TITLE_RE = re.compile(r'<meta[^>]+property="og:title"[^>]+content="([^"]*)"', re.I)


def _page_signature(r: requests.Response) -> tuple:
    html = r.text or ""
    t = _TITLE_RE.search(html)
    og = _OG_TITLE_RE.search(html)
    return r.status_code, (t.group(1).strip() if t else ""), (og.group(1).strip() if og else "")


class Checker:
    def __init__(self, http: Http):
        self.http = http
        self._baselines: dict[str, tuple] = {}
        self._lock = threading.Lock()

    # ---------- baseline: صفحه یک یوزرنیم قطعاً ناموجود ----------
    def _baseline(self, key: str, url_tpl: str) -> Optional[tuple]:
        with self._lock:
            if key in self._baselines:
                return self._baselines[key]
        fake = "q" + "".join(random.choices(string.ascii_lowercase + string.digits, k=22))
        try:
            sig = _page_signature(self.http.get(url_tpl.format(fake)))
            sig = (sig[0], sig[1].replace(fake, "{u}"), sig[2].replace(fake, "{u}"))
        except Exception:
            sig = None
        with self._lock:
            self._baselines[key] = sig
        return sig

    def _same_as_baseline(self, key: str, url_tpl: str, username: str, r: requests.Response) -> Optional[bool]:
        base = self._baseline(key, url_tpl)
        if base is None:
            return None
        sig = _page_signature(r)
        sig = (sig[0], sig[1].replace(username, "{u}"), sig[2].replace(username, "{u}"))
        return sig == base

    # ---------- اینستاگرام ----------
    def instagram(self, u: str) -> Result:
        url = f"https://www.instagram.com/{u}/"
        if (err := validate("instagram", u)):
            return Result("Instagram", u, Status.INVALID, err, url)
        try:
            r = self.http.get(
                "https://i.instagram.com/api/v1/users/web_profile_info/",
                params={"username": u},
                headers={"x-ig-app-id": "936619743392459",
                         "Accept": "*/*", "Referer": "https://www.instagram.com/"},
            )
        except Exception as e:
            return Result("Instagram", u, Status.UNKNOWN, f"خطای اتصال: {e.__class__.__name__} (پراکسی؟)", url)

        if r.status_code == 404:
            return Result("Instagram", u, Status.AVAILABLE,
                          "پروفایلی یافت نشد (ممکن است بن/غیرفعال شده باشد)", url)
        if r.status_code == 200:
            try:
                user = (r.json().get("data") or {}).get("user")
            except ValueError:
                user = None
            if user:
                info = f"{user.get('full_name') or ''} | فالوور: " \
                       f"{(user.get('edge_followed_by') or {}).get('count', '?')}"
                return Result("Instagram", u, Status.TAKEN, info.strip(" |"), url)
            return Result("Instagram", u, Status.AVAILABLE, "کاربر در پاسخ API نبود", url)
        if r.status_code in (401, 403, 429):
            return Result("Instagram", u, Status.UNKNOWN,
                          f"محدودیت نرخ/نیاز به لاگین (HTTP {r.status_code}) — کمی بعد یا با IP دیگر", url)
        return Result("Instagram", u, Status.UNKNOWN, f"HTTP {r.status_code}", url)

    # ---------- توییتر / X ----------
    def x(self, u: str) -> Result:
        url = f"https://x.com/{u}"
        if (err := validate("x", u)):
            return Result("X (Twitter)", u, Status.INVALID, err, url)
        for endpoint in ("https://api.x.com/i/users/username_available.json",
                         "https://api.twitter.com/i/users/username_available.json"):
            try:
                r = self.http.get(endpoint, params={"username": u},
                                  headers={"Accept": "application/json"})
            except Exception as e:
                last = f"خطای اتصال: {e.__class__.__name__} (پراکسی؟)"
                continue
            if r.status_code != 200:
                last = f"HTTP {r.status_code}"
                continue
            try:
                j = r.json()
            except ValueError:
                last = "پاسخ JSON نبود"
                continue
            reason = str(j.get("reason", "")).lower()
            msg = j.get("msg", "")
            if j.get("valid") is True:
                return Result("X (Twitter)", u, Status.AVAILABLE, msg, url)
            if reason == "taken":
                return Result("X (Twitter)", u, Status.TAKEN, msg, url)
            if reason in ("invalid_username", "is_banned_word", "too_short", "too_long"):
                return Result("X (Twitter)", u, Status.INVALID, msg or reason, url)
            return Result("X (Twitter)", u, Status.UNKNOWN, msg or reason or "پاسخ نامشخص", url)
        return Result("X (Twitter)", u, Status.UNKNOWN, last, url)

    # ---------- تلگرام ----------
    def telegram(self, u: str, use_fragment: bool = True) -> Result:
        url = f"https://t.me/{u}"
        if (err := validate("telegram", u)):
            return Result("Telegram", u, Status.INVALID, err, url)
        try:
            r = self.http.get(url)
        except Exception as e:
            return Result("Telegram", u, Status.UNKNOWN, f"خطای اتصال: {e.__class__.__name__} (پراکسی؟)", url)

        html = r.text or ""
        if 'class="tgme_page_title"' in html:
            m = re.search(r'class="tgme_page_title"[^>]*>\s*<span[^>]*>(.*?)</span>', html, re.S)
            extra = re.search(r'class="tgme_page_extra"[^>]*>(.*?)</div>', html, re.S)
            info = " | ".join(x for x in [
                re.sub(r"<[^>]+>|\s+", " ", m.group(1)).strip() if m else "",
                re.sub(r"<[^>]+>|\s+", " ", extra.group(1)).strip() if extra else "",
            ] if x)
            return Result("Telegram", u, Status.TAKEN, info or "کاربر/کانال/گروه وجود دارد", url)

        # در t.me پیدا نشد → Fragment را چک کن (یوزرنیم‌های حراجی/فروخته‌شده)
        if use_fragment:
            frag = self._fragment(u)
            if frag:
                return frag
        return Result("Telegram", u, Status.AVAILABLE,
                      "در t.me یافت نشد (ممکن است حساب خصوصی بدون یوزرنیم عمومی یا رزرو باشد)", url)

    def _fragment(self, u: str) -> Optional[Result]:
        url = f"https://fragment.com/username/{u.lower()}"
        try:
            r = self.http.get(url)
        except Exception:
            return None
        if r.status_code != 200:
            return None
        m = re.search(r'class="tm-section-header-status[^"]*"[^>]*>\s*([^<]+?)\s*<', r.text or "")
        if not m:
            return None
        st = m.group(1).strip().lower()
        if st in ("taken",):
            return Result("Telegram", u, Status.TAKEN, "Fragment: Taken", url)
        if st in ("on auction", "for sale", "sold"):
            price = re.search(r'class="table-cell-value tm-value icon-before icon-ton"[^>]*>([^<]+)<', r.text)
            p = f" — قیمت: {price.group(1).strip()} TON" if price else ""
            return Result("Telegram", u, Status.RESERVED, f"Fragment: {m.group(1).strip()}{p}", url)
        if st == "available":
            return Result("Telegram", u, Status.AVAILABLE, "Fragment: Available", f"https://t.me/{u}")
        return None

    # ---------- بله ----------
    def bale(self, u: str) -> Result:
        url = f"https://ble.ir/{u}"
        if (err := validate("bale", u)):
            return Result("Bale", u, Status.INVALID, err, url)
        try:
            r = self.http.get(url)
        except Exception as e:
            return Result("Bale", u, Status.UNKNOWN, f"خطای اتصال: {e.__class__.__name__}", url)

        if r.status_code == 404:
            return Result("Bale", u, Status.AVAILABLE, "صفحه پروفایل وجود ندارد (404)", url)
        if r.status_code >= 500 or r.status_code in (403, 429):
            return Result("Bale", u, Status.UNKNOWN, f"HTTP {r.status_code}", url)

        html = r.text or ""
        # نشانه‌های رایج صفحه پروفایل/کانال
        if re.search(r'"(nick|nickName|title|name)"\s*:\s*"[^"]+"', html) and u.lower() in html.lower():
            same = self._same_as_baseline("bale", "https://ble.ir/{}", u, r)
            if same is False or same is None:
                return Result("Bale", u, Status.TAKEN, "صفحه پروفایل/کانال یافت شد", url)

        same = self._same_as_baseline("bale", "https://ble.ir/{}", u, r)
        if same is True:
            return Result("Bale", u, Status.AVAILABLE, "پاسخ مشابه یک یوزرنیم ناموجود است", url)
        if same is False:
            t = _page_signature(r)
            return Result("Bale", u, Status.TAKEN, (t[2] or t[1])[:60] or "صفحه متفاوت از یوزر ناموجود", url)
        return Result("Bale", u, Status.UNKNOWN, "امکان مقایسه نبود", url)

    # ---------- دامنه ----------
    def domain(self, domain: str) -> Result:
        try:
            ascii_d = to_ascii_domain(domain)
        except Exception as e:
            return Result("Domain", domain, Status.INVALID, f"دامنه نامعتبر: {e}")
        label = ascii_d.split(".")[0]
        if len(label) > 63 or label.startswith("-") or label.endswith("-") or "--" in label[2:4] and not label.startswith("xn--"):
            return Result("Domain", domain, Status.INVALID, "برچسب دامنه نامعتبر است")
        url = f"https://whois.nic.ir/WHOIS?name={ascii_d}"
        shown = domain if domain == ascii_d else f"{domain}  ({ascii_d})"

        try:
            resp = whois_query("whois.nic.ir", ascii_d, timeout=self.http.timeout)
        except Exception as e:
            resp = None
            whois_err = e.__class__.__name__
        if resp is not None:
            low = resp.lower()
            if "no entries found" in low or "%error:101" in low:
                return Result("Domain", shown, Status.AVAILABLE, "WHOIS ایرنیک: ثبت نشده", url)
            if re.search(r"^domain:\s*\S+", resp, re.M | re.I):
                exp = re.search(r"^expire-date:\s*(.+)$", resp, re.M | re.I)
                holder = re.search(r"^(?:holder-c|person|org):\s*(.+)$", resp, re.M | re.I)
                info = "ثبت شده"
                if exp:
                    info += f" | انقضا: {exp.group(1).strip()}"
                if holder:
                    info += f" | {holder.group(1).strip()[:30]}"
                return Result("Domain", shown, Status.TAKEN, info, url)
            if "%error" in low:
                msg = re.search(r"%error:\d+:\s*(.+)", resp, re.I)
                whois_err = msg.group(1).strip() if msg else "خطای WHOIS"
            else:
                whois_err = "پاسخ WHOIS نامشخص"

        # پشتیبان: DNS
        try:
            socket.getaddrinfo(ascii_d, None)
            return Result("Domain", shown, Status.TAKEN, f"رکورد DNS دارد (WHOIS: {whois_err})", url)
        except socket.gaierror:
            return Result("Domain", shown, Status.UNKNOWN,
                          f"WHOIS ناموفق ({whois_err})؛ DNS ندارد → احتمالاً آزاد", url)


def whois_query(server: str, query: str, timeout: float = 10, port: int = 43) -> str:
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


# ───────────────────────────── اجرا ─────────────────────────────

PLATFORM_ALIASES = {
    "domain": "domain", "domains": "domain", "ir": "domain",
    "instagram": "instagram", "ig": "instagram", "insta": "instagram",
    "x": "x", "twitter": "x", "tw": "x",
    "telegram": "telegram", "tg": "telegram",
    "bale": "bale", "bale.ir": "bale", "ble": "bale",
}


def build_tasks(args, checker: Checker) -> list[tuple[Callable[[], Result], str, str]]:
    platforms = {PLATFORM_ALIASES[p.strip().lower()] for p in args.only.split(",") if p.strip()}
    tlds = [t.strip().strip(".") for t in args.tlds.split(",") if t.strip()]
    tasks: list[tuple[Callable[[], Result], str, str]] = []

    if "domain" in platforms:
        labels: list[str] = []
        if args.fa:
            labels += fa_domain_labels(args.fa, args.variants)
        if args.en:
            labels += en_domain_labels(args.en, args.variants)
        for lab in dict.fromkeys(labels):
            for tld in tlds:
                d = f"{lab}.{tld}"
                tasks.append((lambda d=d: checker.domain(d), "Domain", d))

    users = username_candidates(args.en, args.variants) if args.en else []
    base_users = set(username_candidates(args.en, False)) if args.en else set()
    for p in ("instagram", "x", "telegram", "bale"):
        if p not in platforms:
            continue
        for u in users:
            # واریانت‌های نامعتبر را بی‌صدا رد کن؛ فقط شکل اصلی را حتی اگر نامعتبر است نشان بده
            if validate(p, u) and u not in base_users:
                continue
            if p == "telegram":
                fn = (lambda u=u: checker.telegram(u, not args.no_fragment))
            else:
                fn = (lambda u=u, p=p: getattr(checker, p)(u))
            tasks.append((fn, p, u))
    return tasks


def safe_call(fn: Callable[[], Result], platform: str, target: str) -> Result:
    try:
        return fn()
    except Exception as e:  # هرگز کل اجرا به خاطر یک خطا متوقف نشود
        return Result(platform, target, Status.UNKNOWN, f"خطای داخلی: {e!r}")


ORDER = ["Domain", "Instagram", "X (Twitter)", "Telegram", "Bale"]


def print_results(results: list[Result]) -> None:
    results.sort(key=lambda r: (ORDER.index(r.platform) if r.platform in ORDER else 99, r.target))
    if _console:
        table = Table(title="نتیجه بررسی نام", show_lines=False, header_style="bold cyan")
        table.add_column("پلتفرم", no_wrap=True)
        table.add_column("نام / یوزرنیم", no_wrap=True)
        table.add_column("وضعیت", no_wrap=True)
        table.add_column("توضیح")
        for r in results:
            c = STATUS_COLOR[r.status]
            table.add_row(r.platform, r.target, f"[{c}]{STATUS_FA[r.status]}[/{c}]", r.detail)
        _console.print(table)
    else:
        w1 = max([len(r.platform) for r in results] + [8])
        w2 = max([len(r.target) for r in results] + [10])
        print(f"\n{'PLATFORM':<{w1}}  {'TARGET':<{w2}}  STATUS            DETAIL")
        print("-" * (w1 + w2 + 40))
        for r in results:
            print(f"{r.platform:<{w1}}  {r.target:<{w2}}  {STATUS_FA[r.status]:<16}  {r.detail}")

    summary = {s: sum(1 for r in results if r.status == s) for s in Status}
    line = "  ".join(f"{STATUS_FA[s]}: {n}" for s, n in summary.items() if n)
    (_console.print if _console else print)(f"\nخلاصه → {line}")

    free = [r for r in results if r.status == Status.AVAILABLE]
    if free:
        (_console.print if _console else print)("\nموارد آزاد:")
        for r in free:
            (_console.print if _console else print)(f"  • {r.platform}: {r.target}")


def save_outputs(results: list[Result], json_path: Optional[str], csv_path: Optional[str]) -> None:
    rows = [r.as_dict() for r in results]
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        print(f"JSON ذخیره شد: {json_path}")
    if csv_path:
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:  # utf-8-sig برای نمایش درست فارسی در اکسل
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["platform"])
            w.writeheader()
            w.writerows(rows)
        print(f"CSV ذخیره شد: {csv_path}")


def save_markdown(results: list[Result], path: str, args) -> None:
    """گزارش Markdown (برای GitHub Actions Job Summary)."""
    icon = {Status.AVAILABLE: "✅", Status.TAKEN: "❌", Status.RESERVED: "💰",
            Status.INVALID: "⛔", Status.UNKNOWN: "❓"}
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    lines = ["## 🔎 نتیجه بررسی نام", ""]
    if args.fa:
        lines.append(f"- **نام فارسی:** {esc(args.fa)}")
    if args.en:
        lines.append(f"- **نام انگلیسی:** `{esc(args.en)}`")
    summary = {s: sum(1 for r in results if r.status == s) for s in Status}
    lines += ["- **خلاصه:** " + " · ".join(f"{STATUS_FA[s]}: {n}" for s, n in summary.items() if n), ""]
    lines += ["| پلتفرم | نام / یوزرنیم | وضعیت | توضیح |", "|---|---|---|---|"]
    for r in sorted(results, key=lambda r: (ORDER.index(r.platform) if r.platform in ORDER else 99, r.target)):
        target = f"[{esc(r.target)}]({r.url})" if r.url else esc(r.target)
        lines.append(f"| {r.platform} | {target} | {icon[r.status]} {STATUS_FA[r.status][2:]} | {esc(r.detail)} |")
    free = [r for r in results if r.status == Status.AVAILABLE]
    if free:
        lines += ["", "### ✅ موارد آزاد", ""] + [f"- **{r.platform}:** `{esc(r.target)}`" for r in free]
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="بررسی آزاد بودن نام در دامنه‌های .ir و اینستاگرام، X، تلگرام و بله",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--fa", help='نام فارسی (برای دامنه فارسی)، مثل "علی رضایی"')
    p.add_argument("--en", help='نام انگلیسی (برای دامنه و یوزرنیم‌ها)، مثل "ali rezaei"')
    p.add_argument("--tlds", default="ir,ایران",
                   help="پسوندهای دامنه، جداشده با کاما (پیش‌فرض: ir,ایران)\nمثال: ir,co.ir,ایران,net.ir")
    p.add_argument("--only", default="domain,instagram,x,telegram,bale",
                   help="فقط این پلتفرم‌ها: domain,instagram,x,telegram,bale")
    p.add_argument("--variants", action="store_true",
                   help="ساخت و بررسی حالت‌های جایگزین (name_ir, thename, nameofficial, ...)")
    p.add_argument("--proxy", help="پراکسی برای HTTP، مثل http://127.0.0.1:8080 یا socks5h://127.0.0.1:1080")
    p.add_argument("--timeout", type=float, default=12, help="مهلت هر درخواست به ثانیه (پیش‌فرض ۱۲)")
    p.add_argument("--workers", type=int, default=6, help="تعداد درخواست هم‌زمان (پیش‌فرض ۶)")
    p.add_argument("--delay", type=float, default=0.8,
                   help="حداکثر تأخیر تصادفی قبل از هر درخواست، برای جلوگیری از بلاک (پیش‌فرض ۰.۸)")
    p.add_argument("--no-fragment", action="store_true", help="عدم بررسی Fragment برای تلگرام")
    p.add_argument("--json", help="ذخیره خروجی در فایل JSON")
    p.add_argument("--csv", help="ذخیره خروجی در فایل CSV")
    p.add_argument("--markdown", help="افزودن گزارش Markdown به این فایل (مثلاً $GITHUB_STEP_SUMMARY)")
    p.add_argument("--no-input", action="store_true", help="هیچ‌وقت نام را تعاملی نپرس (برای CI)")
    args = p.parse_args(argv)
    args.fa = (args.fa or "").strip() or None
    args.en = (args.en or "").strip() or None

    if not args.fa and not args.en and not args.no_input and sys.stdin.isatty():
        try:
            args.fa = input("نام فارسی (اختیاری، Enter برای رد شدن): ").strip() or None
            args.en = input("نام انگلیسی (اختیاری، Enter برای رد شدن): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
    if not args.fa and not args.en:
        p.error("حداقل یکی از --fa یا --en لازم است")

    bad = [x for x in args.only.split(",") if x.strip() and x.strip().lower() not in PLATFORM_ALIASES]
    if bad:
        p.error(f"پلتفرم ناشناخته: {', '.join(bad)}")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    http = Http(args.proxy, args.timeout, args.delay)
    checker = Checker(http)
    tasks = build_tasks(args, checker)
    if not tasks:
        print("چیزی برای بررسی ساخته نشد (یوزرنیم‌ها فقط از نام انگلیسی ساخته می‌شوند).")
        return 1

    print(f"در حال بررسی {len(tasks)} مورد ...")
    results: list[Result] = []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(safe_call, fn, plat, tgt): (plat, tgt) for fn, plat, tgt in tasks}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            results.append(fut.result())
            print(f"\r  {i}/{len(tasks)}", end="", flush=True)
    print()

    print_results(results)
    save_outputs(results, args.json, args.csv)
    if args.markdown:
        save_markdown(results, args.markdown, args)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nلغو شد.")
        sys.exit(130)
