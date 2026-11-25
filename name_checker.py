#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
name_checker.py — بررسی آزاد بودن یک نام در دامنه‌ها و ده‌ها شبکه‌ی اجتماعی ایرانی و خارجی

    pip install -r requirements.txt
    python name_checker.py --fa "علی رضایی" --en "ali rezaei"
    python name_checker.py --en mybrand --categories social,iran --variants
    python name_checker.py --en mybrand --sites instagram,telegram,github
    python name_checker.py --list-sites

اینستاگرام (به ترتیب، تا یکی جواب بدهد):
  1) API پروفایل با کوکی sessionid  ← اگر متغیر محیطی IG_SESSIONID تنظیم شده باشد (مطمئن‌ترین)
  2) بررسی «پیش‌نمایش ثبت‌نام» (همان چیزی که فرم ثبت‌نام اینستاگرام چک می‌کند)
  3) API عمومی web_profile_info (موبایل و وب)
  4) خواندن HTML صفحه‌ی پروفایل
  و اگر Tor فعال باشد (--tor-control)، در صورت 429 مدار Tor عوض می‌شود و دوباره تلاش می‌کند.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import json
import os
import random
import re
import socket
import string
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover
    sys.exit("کتابخانه requests نصب نیست:  pip install -r requirements.txt")

try:
    import idna as _idna
except ImportError:
    _idna = None

try:
    from rich.console import Console
    from rich.table import Table
    _console = Console()
except ImportError:
    _console = None

from sites import CATEGORIES, SITES, SITES_BY_KEY, Site


# ═════════════════════════════ مدل نتیجه ═════════════════════════════

class Status(str, Enum):
    AVAILABLE = "available"
    TAKEN = "taken"
    RESERVED = "reserved"
    INVALID = "invalid"
    UNKNOWN = "unknown"


STATUS_FA = {
    Status.AVAILABLE: "✅ آزاد",
    Status.TAKEN: "❌ گرفته شده",
    Status.RESERVED: "💰 رزرو/حراجی",
    Status.INVALID: "⛔ نامعتبر",
    Status.UNKNOWN: "❓ نامشخص",
}
STATUS_COLOR = {
    Status.AVAILABLE: "green", Status.TAKEN: "red", Status.RESERVED: "yellow",
    Status.INVALID: "magenta", Status.UNKNOWN: "bright_black",
}


@dataclass
class Result:
    category: str
    platform: str
    target: str
    status: Status
    detail: str = ""
    url: str = ""

    def as_dict(self) -> dict:
        return {
            "category": self.category, "platform": self.platform, "target": self.target,
            "status": self.status.value, "status_fa": STATUS_FA[self.status],
            "detail": self.detail, "url": self.url,
        }


Verdict = tuple[Optional[Status], str]   # (وضعیت یا None برای نامشخص, توضیح)


# ═════════════════════════════ HTTP ═════════════════════════════

DESKTOP_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]
IG_MOBILE_UA = ("Instagram 309.1.0.41.113 Android (33/13; 420dpi; 1080x2340; samsung; SM-S911B; dm1q; qcom; "
                "en_US; 541635890)")
IG_APP_ID = "936619743392459"
BLOCK_CODES = {401, 403, 429, 503, 999}


class Http:
    def __init__(self, proxy: Optional[str], proxy_sites: Optional[set[str]], timeout: float,
                 delay: float, retries: int = 2, tor_control: Optional[int] = None):
        self.proxy = proxy
        self.proxy_sites = proxy_sites
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.tor_control = tor_control
        self._local = threading.local()
        self._meta_lock = threading.Lock()
        self._site_locks: dict[str, threading.Lock] = {}
        self._last: dict[str, float] = {}
        self._tor_lock = threading.Lock()
        self._tor_last = 0.0

    def uses_proxy(self, site: str) -> bool:
        return bool(self.proxy) and (self.proxy_sites is None or site in self.proxy_sites)

    def _configure(self, s: requests.Session, site: str) -> requests.Session:
        s.mount("https://", HTTPAdapter(pool_connections=20, pool_maxsize=20))
        s.headers.update({"User-Agent": random.choice(DESKTOP_UAS),
                          "Accept-Language": "en-US,en;q=0.9,fa;q=0.8"})
        if self.uses_proxy(site):
            s.proxies.update({"http": self.proxy, "https": self.proxy})
        return s

    def session(self, site: str) -> requests.Session:
        store = self._local.__dict__.setdefault("sessions", {})
        key = self.uses_proxy(site)
        if key not in store:
            store[key] = self._configure(requests.Session(), site)
        return store[key]

    def new_session(self, site: str) -> requests.Session:
        return self._configure(requests.Session(), site)

    def _throttle(self, site: str, min_interval: float) -> None:
        if self.delay:
            time.sleep(random.uniform(0, self.delay))
        if min_interval <= 0:
            return
        with self._meta_lock:
            lock = self._site_locks.setdefault(site, threading.Lock())
        with lock:
            wait = self._last.get(site, 0) + min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last[site] = time.monotonic()

    def request(self, method: str, url: str, site: str = "", min_interval: float = 0.0,
                session: Optional[requests.Session] = None, **kw) -> requests.Response:
        kw.setdefault("timeout", self.timeout)
        s = session or self.session(site)
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            self._throttle(site, min_interval)
            try:
                r = s.request(method, url, **kw)
                if r.status_code in (500, 502, 504) and attempt < self.retries:
                    time.sleep(2 ** attempt + random.random())
                    continue
                return r
            except requests.RequestException as e:
                last_exc = e
                if attempt < self.retries:
                    time.sleep(1 + attempt)
        raise last_exc or RuntimeError("request failed")

    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> requests.Response:
        return self.request("POST", url, **kw)

    def renew_tor(self) -> bool:
        """درخواست مدار جدید از Tor (IP خروجی جدید)."""
        if not self.tor_control:
            return False
        with self._tor_lock:
            wait = self._tor_last + 10 - time.monotonic()   # Tor هر ۱۰ ثانیه یک NEWNYM قبول می‌کند
            if wait > 0:
                time.sleep(wait)
            try:
                with socket.create_connection(("127.0.0.1", self.tor_control), timeout=5) as s:
                    s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
                    resp = s.recv(1024)
            except OSError:
                return False
            self._tor_last = time.monotonic()
            for store in [self._local.__dict__.get("sessions", {})]:
                store.clear()   # اتصال‌های قدیمی روی مدار قبلی هستند
            time.sleep(3)
            return b"250" in resp


def err_name(e: Exception) -> str:
    return e.__class__.__name__


# ═════════════════════════════ نرمال‌سازی نام ═════════════════════════════

_AR_TO_FA = str.maketrans({
    "ي": "ی", "ى": "ی", "ك": "ک", "ة": "ه", "ۀ": "ه", "أ": "ا", "إ": "ا", "ٱ": "ا",
    **{a: str(i) for i, a in enumerate("٠١٢٣٤٥٦٧٨٩")}, **{a: str(i) for i, a in enumerate("۰۱۲۳۴۵۶۷۸۹")},
})
_DIACRITICS = re.compile(r"[\u064B-\u065F\u0670\u0640]")


def normalize_fa(text: str) -> str:
    text = _DIACRITICS.sub("", unicodedata.normalize("NFC", text).translate(_AR_TO_FA))
    return re.sub(r"\s+", " ", text).strip()


def normalize_en(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9._\-\s]", "", text)).strip()


def to_ascii_domain(domain: str) -> str:
    domain = domain.strip(".").lower()
    if _idna is not None:
        try:
            return _idna.encode(domain, uts46=True).decode()
        except _idna.IDNAError:
            pass
    return domain.encode("idna").decode()


def _words(text: str) -> list[str]:
    return [w for w in re.split(r"[\s._\-\u200c]+", text) if w]


def fa_domain_labels(name_fa: str, variants: bool) -> list[str]:
    base = normalize_fa(name_fa)
    words = _words(base)
    if not words:
        return []
    labels = ["".join(words)]
    if len(words) > 1:
        labels.append("-".join(words))
        if variants and "\u200c" in base:
            labels.append(re.sub(r"\s+", "", base))
    return list(dict.fromkeys(labels))


def en_domain_labels(name_en: str, variants: bool) -> list[str]:
    words = _words(normalize_en(name_en))
    if not words:
        return []
    j = "".join(words)
    labels = [j] + (["-".join(words)] if len(words) > 1 else [])
    if variants:
        labels += [f"{j}ir", f"{j}-ir", f"get{j}", f"{j}app", f"{j}online"]
    return list(dict.fromkeys(labels))


def username_candidates(name_en: str, variants: bool) -> list[str]:
    words = _words(normalize_en(name_en))
    if not words:
        return []
    j = "".join(words)
    cands = [j] + (["_".join(words), ".".join(words), "-".join(words)] if len(words) > 1 else [])
    if variants:
        cands += [f"{j}_ir", f"{j}ir", f"{j}_official", f"{j}official", f"the{j}", f"the_{j}",
                  f"real{j}", f"iam{j}", f"{j}_app", f"{j}hq", f"{j}_co", f"{j}team"]
    return list(dict.fromkeys(cands))


def random_username(n: int = 12) -> str:
    return "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ═════════════════════════════ بررسی‌کننده ═════════════════════════════

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_OG_TITLE_RE = re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']*)', re.I)


def page_signature(r: requests.Response, u: str, replace: bool = True) -> tuple:
    """امضای صفحه: (کد، عنوان، og:title، مسیر) — یوزرنیم با {u} جایگزین می‌شود."""
    html = r.text or ""
    t = _TITLE_RE.search(html)
    og = _OG_TITLE_RE.search(html)
    norm = (lambda s: re.sub(re.escape(u), "{u}", (s or "").strip(), flags=re.I)) if replace \
        else (lambda s: (s or "").strip())
    path = norm(requests.utils.urlparse(r.url).path)
    return r.status_code, norm(t.group(1) if t else ""), norm(og.group(1) if og else ""), path


@dataclass
class Calibration:
    ok: bool
    reason: str = ""
    baseline: Optional[tuple] = None      # (امضای نرمال‌شده، امضای خام)


def same_page(r: requests.Response, u: str, baseline: tuple) -> bool:
    return page_signature(r, u) == baseline[0] or page_signature(r, u, False)[1:3] == baseline[1][1:3] \
        and r.status_code == baseline[1][0]


class Checker:
    def __init__(self, http: Http, use_fragment: bool = True, calibrate: bool = True):
        self.http = http
        self.use_fragment = use_fragment
        self.do_calibrate = calibrate
        self._cal: dict[str, Calibration] = {}
        self._cal_locks: dict[str, threading.Lock] = {}
        self._lock = threading.Lock()
        self.ig_sessionid = os.environ.get("IG_SESSIONID", "").strip() or None
        self.gh_token = os.environ.get("GITHUB_TOKEN", "").strip() or None

    # ───────── ورودی اصلی برای یک سایت ─────────
    def check(self, site: Site, u: str) -> Result:
        cat = CATEGORIES.get(site.category, site.category)
        url = site.profile(u)
        if not re.match(site.rule, u):
            return Result(cat, site.name, u, Status.INVALID, site.rule_fa, url)

        cal = self.calibration(site)
        if not cal.ok:
            return Result(cat, site.name, u, Status.UNKNOWN, f"سایت کالیبره نشد: {cal.reason}", url)

        try:
            st, detail = self.probe(site, u, cal)
        except Exception as e:
            st, detail = None, f"خطای اتصال: {err_name(e)}"
        if site.note and st in (Status.AVAILABLE, Status.TAKEN):
            detail = f"{detail} — {site.note}" if detail else site.note
        return Result(cat, site.name, u, st or Status.UNKNOWN, detail, url)

    # ───────── کالیبراسیون ─────────
    def calibration(self, site: Site) -> Calibration:
        if not (self.do_calibrate and site.calibrate) and site.method != "baseline":
            return Calibration(True)
        with self._lock:
            if site.key in self._cal:
                return self._cal[site.key]
            lock = self._cal_locks.setdefault(site.key, threading.Lock())
        with lock:
            if site.key not in self._cal:
                self._cal[site.key] = self._run_calibration(site)
            return self._cal[site.key]

    def _run_calibration(self, site: Site) -> Calibration:
        fake = random_username()
        try:
            if site.method == "baseline":
                r = self.http.get(site.target(fake), site=site.key, min_interval=site.min_interval,
                                  headers=site.headers, allow_redirects=site.redirects)
                if r.status_code in BLOCK_CODES:
                    return Calibration(False, f"سایت دسترسی را بست (HTTP {r.status_code})")
                base = (page_signature(r, fake), page_signature(r, fake, False))
                if not site.known:
                    return Calibration(False, "یوزرنیم مرجع (known) تعریف نشده")
                rk = self.http.get(site.target(site.known), site=site.key, min_interval=site.min_interval,
                                   headers=site.headers, allow_redirects=site.redirects)
                if same_page(rk, site.known, base):
                    return Calibration(False, "صفحه‌ی حساب موجود و ناموجود یکسان است (SPA/بلاک جغرافیایی)")
                return Calibration(True, baseline=base)

            st, d = self.probe(site, fake, Calibration(True))
            if st != Status.AVAILABLE:
                return Calibration(False, d if st is None else "یوزر تصادفی «گرفته» تشخیص داده شد")
            if site.known:
                st, d = self.probe(site, site.known, Calibration(True))
                if st is None:
                    return Calibration(False, d)
                if st == Status.AVAILABLE:
                    return Calibration(False, f"حساب مرجع «{site.known}» آزاد تشخیص داده شد")
            return Calibration(True)
        except Exception as e:
            return Calibration(False, f"خطای اتصال: {err_name(e)}")

    # ───────── تشخیص عمومی ─────────
    def probe(self, site: Site, u: str, cal: Calibration) -> Verdict:
        if site.custom:
            return getattr(self, f"_c_{site.custom}")(site, u)

        headers = dict(site.headers)
        if site.key == "github" and self.gh_token:
            headers["Authorization"] = f"Bearer {self.gh_token}"
        r = self.http.get(site.target(u), site=site.key, min_interval=site.min_interval,
                          headers=headers, allow_redirects=site.redirects)
        code = r.status_code

        if site.method == "baseline":
            if code in BLOCK_CODES:
                return None, f"بلاک/محدودیت (HTTP {code})"
            same = same_page(r, u, cal.baseline)
            return (Status.AVAILABLE, "پاسخ مشابه یوزر ناموجود") if same else \
                   (Status.TAKEN, (page_signature(r, u)[2] or page_signature(r, u)[1])[:60].replace("{u}", u))

        if code in site.free_status:
            return Status.AVAILABLE, f"HTTP {code}"
        if code in BLOCK_CODES and code not in site.taken_status:
            return None, f"بلاک/محدودیت نرخ (HTTP {code})"

        if site.method == "json":
            try:
                v = site.json_free(r.json()) if site.json_free else None
            except ValueError:
                v = None
            if v is True:
                return Status.AVAILABLE, ""
            if v is False:
                return Status.TAKEN, ""
            return None, f"پاسخ نامشخص (HTTP {code})"

        if site.method == "marker":
            html = r.text or ""
            if any(m.replace("{u}", u) in html for m in site.taken_markers):
                return Status.TAKEN, ""
            if any(m.replace("{u}", u) in html for m in site.free_markers):
                return Status.AVAILABLE, ""

        if code in site.taken_status:
            return Status.TAKEN, ""
        return None, f"پاسخ نامشخص (HTTP {code})"

    # ═════════ اینستاگرام ═════════
    def _c_instagram(self, site: Site, u: str) -> Verdict:
        methods: list[Callable[[str], Verdict]] = []
        if self.ig_sessionid:
            methods.append(lambda x: self._ig_profile_api(x, auth=True))
        methods += [self._ig_signup_check, lambda x: self._ig_profile_api(x, auth=False), self._ig_html]

        rounds = 1 + (3 if self.http.tor_control else 0)
        errors: list[str] = []
        for rnd in range(rounds):
            rate_limited = False
            for m in methods:
                try:
                    st, d = m(u)
                except Exception as e:
                    st, d = None, f"خطای اتصال: {err_name(e)}"
                if st is not None:
                    return st, d
                errors.append(d)
                rate_limited |= "429" in d or "محدودیت" in d
            if rnd < rounds - 1 and rate_limited:
                self.http.renew_tor()
            elif not rate_limited:
                break
        uniq = " | ".join(dict.fromkeys(errors))
        hint = "" if self.ig_sessionid else " — راه‌حل: Secret به نام IG_SESSIONID یا گزینه‌ی Tor/پراکسی"
        return None, f"همه روش‌ها ناموفق ({uniq}){hint}"

    def _ig_profile_api(self, u: str, auth: bool) -> Verdict:
        tag = "API(لاگین)" if auth else "API"
        cookies = {"sessionid": self.ig_sessionid} if auth else None
        last = ""
        for host, ua in (("i.instagram.com", IG_MOBILE_UA), ("www.instagram.com", DESKTOP_UAS[0])):
            r = self.http.get(f"https://{host}/api/v1/users/web_profile_info/", site="instagram",
                              min_interval=3.0, params={"username": u}, cookies=cookies,
                              headers={"User-Agent": ua, "X-IG-App-ID": IG_APP_ID, "Accept": "*/*",
                                       "Referer": "https://www.instagram.com/"},
                              allow_redirects=False)
            if r.status_code == 404:
                return Status.AVAILABLE, f"{tag}: پروفایلی وجود ندارد (ممکن است بن/غیرفعال باشد)"
            if r.status_code == 200:
                try:
                    user = (r.json().get("data") or {}).get("user")
                except ValueError:
                    user = None
                if user:
                    followers = (user.get("edge_followed_by") or {}).get("count", "?")
                    return Status.TAKEN, f"{user.get('full_name') or ''} | فالوور: {followers}".strip(" |")
                if auth:
                    return Status.AVAILABLE, f"{tag}: کاربر یافت نشد"
            last = f"{tag} HTTP {r.status_code}"
            if r.status_code == 429:
                last = f"{tag}: محدودیت نرخ 429"
        return None, last

    @staticmethod
    def parse_ig_signup(j: dict) -> Verdict:
        """تحلیل پاسخ web_create_ajax/attempt (جدا شده برای تست)."""
        errors = j.get("errors") or {}
        uerr = errors.get("username") or []
        codes = []
        for e in uerr:
            codes.append((e.get("code") if isinstance(e, dict) else str(e)) or "")
        msgs = " ".join(str(e.get("message", "")) if isinstance(e, dict) else str(e) for e in uerr)
        if any("taken" in c for c in codes) or "isn't available" in msgs:
            return Status.TAKEN, "ثبت‌نام: نام کاربری گرفته شده"
        if any("held" in c or "reserved" in c for c in codes):
            return Status.RESERVED, "ثبت‌نام: رزرو/نگه‌داشته شده توسط اینستاگرام"
        if any(c.startswith("username_") for c in codes):
            return Status.INVALID, f"ثبت‌نام: {codes[0]}"
        if j.get("spam") or "wait" in str(j.get("message", "")).lower():
            return None, "ثبت‌نام: محدودیت نرخ"
        if uerr:
            return None, f"ثبت‌نام: {msgs[:80]}"
        if j.get("dryrun_passed") is True or (j.get("status") == "ok" and "errors" in j) or \
                (j.get("status") == "ok" and j.get("username_suggestions") is not None):
            return Status.AVAILABLE, "ثبت‌نام: نام کاربری قابل ثبت است"
        return None, "ثبت‌نام: پاسخ نامشخص"

    def _ig_signup_check(self, u: str) -> Verdict:
        s = self.http.new_session("instagram")
        r0 = self.http.get("https://www.instagram.com/accounts/emailsignup/", site="instagram",
                           min_interval=3.0, session=s)
        if r0.status_code == 429:
            return None, "ثبت‌نام: محدودیت نرخ 429"
        csrf = s.cookies.get("csrftoken")
        if not csrf:
            m = re.search(r'"csrf_token":"([^"]+)"', r0.text or "")
            csrf = m.group(1) if m else None
        if not csrf:
            return None, f"ثبت‌نام: توکن CSRF دریافت نشد (HTTP {r0.status_code})"
        r = self.http.post(
            "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
            site="instagram", min_interval=3.0, session=s,
            data={"email": f"{random_username(10)}@gmail.com", "first_name": "", "username": u,
                  "opt_into_one_tap": "false"},
            headers={"X-CSRFToken": csrf, "X-IG-App-ID": IG_APP_ID, "X-Requested-With": "XMLHttpRequest",
                     "Referer": "https://www.instagram.com/accounts/emailsignup/",
                     "Origin": "https://www.instagram.com"},
        )
        if r.status_code == 429:
            return None, "ثبت‌نام: محدودیت نرخ 429"
        try:
            return self.parse_ig_signup(r.json())
        except ValueError:
            return None, f"ثبت‌نام: HTTP {r.status_code}"

    def _ig_html(self, u: str) -> Verdict:
        r = self.http.get(f"https://www.instagram.com/{u}/", site="instagram", min_interval=3.0,
                          allow_redirects=False)
        if r.status_code in (301, 302) and "login" in r.headers.get("Location", ""):
            return None, "HTML: انتقال به صفحه‌ی لاگین"
        if r.status_code == 404:
            return Status.AVAILABLE, "HTML: صفحه وجود ندارد"
        if r.status_code == 200:
            html = r.text or ""
            if f'"username":"{u}"' in html or f"(@{u})" in html:
                return Status.TAKEN, "HTML: پروفایل یافت شد"
            if "Page Not Found" in html or "isn't available" in html:
                return Status.AVAILABLE, "HTML: صفحه وجود ندارد"
        return None, f"HTML: HTTP {r.status_code}"

    # ═════════ X / Twitter ═════════
    def _c_x(self, site: Site, u: str) -> Verdict:
        last = ""
        for endpoint in ("https://api.x.com/i/users/username_available.json",
                         "https://api.twitter.com/i/users/username_available.json"):
            try:
                r = self.http.get(endpoint, site="x", min_interval=site.min_interval,
                                  params={"username": u}, headers={"Accept": "application/json"})
            except Exception as e:
                last = f"خطای اتصال: {err_name(e)}"
                continue
            if r.status_code != 200:
                last = f"HTTP {r.status_code}"
                continue
            try:
                j = r.json()
            except ValueError:
                last = "پاسخ JSON نبود"
                continue
            reason, msg = str(j.get("reason", "")).lower(), j.get("msg", "")
            if j.get("valid") is True:
                return Status.AVAILABLE, msg
            if reason == "taken":
                return Status.TAKEN, msg
            if reason in ("invalid_username", "is_banned_word", "too_short", "too_long"):
                return Status.INVALID, msg or reason
            last = msg or reason or "پاسخ نامشخص"
        return None, last

    # ═════════ تلگرام ═════════
    def _c_telegram(self, site: Site, u: str) -> Verdict:
        r = self.http.get(f"https://t.me/{u}", site="telegram")
        html = r.text or ""
        if 'class="tgme_page_title"' in html:
            m = re.search(r'class="tgme_page_title"[^>]*>\s*<span[^>]*>(.*?)</span>', html, re.S)
            extra = re.search(r'class="tgme_page_extra"[^>]*>(.*?)</div>', html, re.S)
            clean = lambda s: re.sub(r"<[^>]+>|\s+", " ", s).strip()
            info = " | ".join(x for x in [clean(m.group(1)) if m else "", clean(extra.group(1)) if extra else ""] if x)
            return Status.TAKEN, info
        if r.status_code in BLOCK_CODES:
            return None, f"HTTP {r.status_code}"
        if self.use_fragment:
            frag = self._fragment(u)
            if frag:
                return frag
        return Status.AVAILABLE, "در t.me یافت نشد"

    def _fragment(self, u: str) -> Optional[Verdict]:
        try:
            r = self.http.get(f"https://fragment.com/username/{u.lower()}", site="fragment")
        except Exception:
            return None
        m = re.search(r'class="tm-section-header-status[^"]*"[^>]*>\s*([^<]+?)\s*<', r.text or "")
        if r.status_code != 200 or not m:
            return None
        st = m.group(1).strip().lower()
        if st == "taken":
            return Status.TAKEN, "Fragment: Taken"
        if st in ("on auction", "for sale", "sold"):
            price = re.search(r'icon-ton"[^>]*>([^<]+)<', r.text)
            return Status.RESERVED, f"Fragment: {m.group(1).strip()}" + (f" — {price.group(1).strip()} TON" if price else "")
        if st == "available":
            return Status.AVAILABLE, "Fragment: Available"
        return None

    # ═════════ Twitch ═════════
    def _c_twitch(self, site: Site, u: str) -> Verdict:
        r = self.http.post("https://gql.twitch.tv/gql", site="twitch",
                           headers={"Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko"},
                           json={"query": 'query($l:String!){user(login:$l,lookupType:ALL){id}}',
                                 "variables": {"l": u}})
        try:
            data = r.json().get("data")
        except (ValueError, AttributeError):
            return None, f"HTTP {r.status_code}"
        if not isinstance(data, dict):
            return None, f"HTTP {r.status_code}"
        return (Status.TAKEN, "") if data.get("user") else (Status.AVAILABLE, "")

    # ═════════ دامنه ═════════
    def domain(self, domain: str) -> Result:
        cat = CATEGORIES["domain"]
        try:
            ascii_d = to_ascii_domain(domain)
        except Exception as e:
            return Result(cat, "Domain", domain, Status.INVALID, f"دامنه نامعتبر: {e}")
        label = ascii_d.split(".")[0]
        if len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return Result(cat, "Domain", domain, Status.INVALID, "برچسب دامنه نامعتبر است")
        shown = domain if domain == ascii_d else f"{domain} ({ascii_d})"
        tld = ascii_d.rsplit(".", 1)[-1]

        if tld in ("ir", "xn--mgba3a4f16a"):      # .ir و .ایران → WHOIS ایرنیک
            url = f"https://whois.nic.ir/WHOIS?name={ascii_d}"
            st, d = self._whois_ir(ascii_d)
        else:                                       # بقیه → RDAP
            url = f"https://rdap.org/domain/{ascii_d}"
            st, d = self._rdap(ascii_d)
        if st is None:
            try:
                socket.getaddrinfo(ascii_d, None)
                st, d = Status.TAKEN, f"رکورد DNS دارد ({d})"
            except socket.gaierror:
                d = f"{d}؛ DNS ندارد → احتمالاً آزاد"
        return Result(cat, "Domain", shown, st or Status.UNKNOWN, d, url)

    def _whois_ir(self, ascii_d: str) -> Verdict:
        try:
            resp = whois_query("whois.nic.ir", ascii_d, timeout=self.http.timeout)
        except Exception as e:
            return None, f"WHOIS ناموفق: {err_name(e)}"
        low = resp.lower()
        if "no entries found" in low or "%error:101" in low:
            return Status.AVAILABLE, "WHOIS ایرنیک: ثبت نشده"
        if re.search(r"^domain:\s*\S+", resp, re.M | re.I):
            exp = re.search(r"^expire-date:\s*(.+)$", resp, re.M | re.I)
            return Status.TAKEN, "ثبت شده" + (f" | انقضا: {exp.group(1).strip()}" if exp else "")
        m = re.search(r"%error:\d+:\s*(.+)", resp, re.I)
        return None, f"WHOIS: {m.group(1).strip() if m else 'پاسخ نامشخص'}"

    def _rdap(self, ascii_d: str) -> Verdict:
        try:
            r = self.http.get(f"https://rdap.org/domain/{ascii_d}", site="rdap",
                              headers={"Accept": "application/rdap+json"})
        except Exception as e:
            return None, f"RDAP ناموفق: {err_name(e)}"
        if r.status_code == 404:
            return Status.AVAILABLE, "RDAP: ثبت نشده"
        if r.status_code == 200:
            exp = ""
            try:
                for ev in r.json().get("events", []):
                    if ev.get("eventAction") == "expiration":
                        exp = f" | انقضا: {ev.get('eventDate', '')[:10]}"
            except ValueError:
                pass
            return Status.TAKEN, "ثبت شده" + exp
        return None, f"RDAP: HTTP {r.status_code}"


def whois_query(server: str, query: str, timeout: float = 10, port: int = 43) -> str:
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode())
        chunks = []
        while data := s.recv(4096):
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


# ═════════════════════════════ ساخت کارها ═════════════════════════════

def select_sites(args) -> list[Site]:
    if args.sites:
        keys = [k.strip().lower() for k in args.sites.split(",") if k.strip()]
        unknown = [k for k in keys if k not in SITES_BY_KEY and k != "domain"]
        if unknown:
            sys.exit(f"سایت ناشناخته: {', '.join(unknown)}  (لیست: --list-sites)")
        chosen = [SITES_BY_KEY[k] for k in keys if k in SITES_BY_KEY]
    else:
        cats = {c.strip() for c in args.categories.split(",") if c.strip()}
        chosen = [s for s in SITES if s.category in cats]
    excl = {k.strip().lower() for k in (args.exclude or "").split(",") if k.strip()}
    return [s for s in chosen if s.key not in excl]


def domains_enabled(args) -> bool:
    if args.sites:
        return "domain" in [k.strip().lower() for k in args.sites.split(",")]
    return "domain" in args.categories.split(",")


def build_tasks(args, checker: Checker) -> list[tuple[Callable[[], Result], str, str, str]]:
    tasks = []
    if domains_enabled(args):
        tlds = [t.strip().strip(".") for t in args.tlds.split(",") if t.strip()]
        labels = (fa_domain_labels(args.fa, args.variants) if args.fa else []) + \
                 (en_domain_labels(args.en, args.variants) if args.en else [])
        for lab in dict.fromkeys(labels):
            for tld in tlds:
                d = f"{lab}.{tld}"
                tasks.append((lambda d=d: checker.domain(d), CATEGORIES["domain"], "Domain", d))

    users = username_candidates(args.en, args.variants) if args.en else []
    main = users[0] if users else None   # شکل اصلی (چسبیده)؛ فقط اگر همین نامعتبر بود، «نامعتبر» نشان داده می‌شود
    for site in select_sites(args):
        for u in users:
            if not re.match(site.rule, u) and u != main:
                continue
            tasks.append((lambda s=site, u=u: checker.check(s, u),
                          CATEGORIES.get(site.category, site.category), site.name, u))
    return tasks


def safe_call(fn, category, platform, target) -> Result:
    try:
        return fn()
    except Exception as e:
        return Result(category, platform, target, Status.UNKNOWN, f"خطای داخلی: {e!r}")


# ═════════════════════════════ خروجی ═════════════════════════════

CAT_ORDER = list(CATEGORIES.values())


def sort_key(r: Result):
    return (CAT_ORDER.index(r.category) if r.category in CAT_ORDER else 99, r.platform, r.target)


def ranking(results: list[Result]) -> list[tuple[str, int, int]]:
    """رتبه‌بندی یوزرنیم‌ها بر اساس تعداد پلتفرم‌هایی که آزادند."""
    stats: dict[str, list[int]] = {}
    for r in results:
        if r.platform == "Domain" or r.status in (Status.UNKNOWN, Status.INVALID):
            continue
        s = stats.setdefault(r.target, [0, 0])
        s[1] += 1
        s[0] += r.status == Status.AVAILABLE
    return sorted(((u, f, t) for u, (f, t) in stats.items()), key=lambda x: (-x[1] / max(x[2], 1), -x[2]))


def print_results(results: list[Result]) -> None:
    results.sort(key=sort_key)
    out = _console.print if _console else print
    if _console:
        table = Table(title="نتیجه بررسی نام", header_style="bold cyan")
        for col in ("دسته", "پلتفرم", "نام / یوزرنیم", "وضعیت", "توضیح"):
            table.add_column(col)
        for r in results:
            c = STATUS_COLOR[r.status]
            table.add_row(r.category, r.platform, r.target, f"[{c}]{STATUS_FA[r.status]}[/{c}]", r.detail)
        _console.print(table)
    else:
        for cat in dict.fromkeys(r.category for r in results):
            print(f"\n=== {cat} ===")
            for r in (x for x in results if x.category == cat):
                print(f"  {r.platform:<24} {r.target:<28} {STATUS_FA[r.status]:<14} {r.detail}")

    summary = {s: sum(1 for r in results if r.status == s) for s in Status}
    out("\nخلاصه → " + "  ".join(f"{STATUS_FA[s]}: {n}" for s, n in summary.items() if n))
    rank = ranking(results)
    if rank:
        out("\nبهترین یوزرنیم‌ها (آزاد / بررسی‌شده):")
        for u, f, t in rank[:10]:
            out(f"  • {u}: {f}/{t}")


def save_outputs(results: list[Result], json_path, csv_path) -> None:
    rows = [r.as_dict() for r in sorted(results, key=sort_key)]
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
    if csv_path:
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["platform"])
            w.writeheader()
            w.writerows(rows)


def save_markdown(results: list[Result], path: str, args) -> None:
    icon = {Status.AVAILABLE: "✅", Status.TAKEN: "❌", Status.RESERVED: "💰",
            Status.INVALID: "⛔", Status.UNKNOWN: "❓"}
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    results = sorted(results, key=sort_key)
    L = ["# 🔎 گزارش بررسی نام", ""]
    if args.fa:
        L.append(f"- **نام فارسی:** {esc(args.fa)}")
    if args.en:
        L.append(f"- **نام انگلیسی:** `{esc(args.en)}`")
    summary = {s: sum(1 for r in results if r.status == s) for s in Status}
    L += ["- **خلاصه:** " + " · ".join(f"{STATUS_FA[s]}: {n}" for s, n in summary.items() if n), ""]

    rank = ranking(results)
    if rank:
        L += ["## 🏆 بهترین یوزرنیم‌ها", "", "| یوزرنیم | آزاد در | از |", "|---|---|---|"]
        L += [f"| `{u}` | {f} | {t} |" for u, f, t in rank[:10]] + [""]

    for cat in dict.fromkeys(r.category for r in results):
        rows = [r for r in results if r.category == cat]
        free = sum(r.status == Status.AVAILABLE for r in rows)
        L += [f"## {cat}  ({free} آزاد از {len(rows)})", "",
              "| پلتفرم | نام / یوزرنیم | وضعیت | توضیح |", "|---|---|---|---|"]
        for r in rows:
            target = f"[{esc(r.target)}]({r.url})" if r.url else esc(r.target)
            L.append(f"| {r.platform} | {target} | {icon[r.status]} {STATUS_FA[r.status][2:]} | {esc(r.detail)[:150]} |")
        L.append("")

    unk = [r for r in results if r.status == Status.UNKNOWN]
    if unk:
        L += ["<details><summary>❓ چرا بعضی موارد نامشخص ماندند؟</summary>", "",
              "- «کالیبره نشد» یعنی سایت IP را بلاک کرده یا ساختار صفحه عوض شده؛ اسکریپت به‌جای حدس غلط، نامشخص گزارش می‌کند.",
              "- پلتفرم‌های ایرانی معمولاً IP خارجی (مثل سرورهای GitHub) را بلاک می‌کنند → از runner خودمیزبان در ایران استفاده کنید.",
              "- برای اینستاگرام Secret به نام `IG_SESSIONID` بسازید یا گزینه‌ی Tor را فعال کنید.", "", "</details>", ""]
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


def list_sites() -> None:
    for key, title in CATEGORIES.items():
        print(f"\n{title}  [{key}]")
        if key == "domain":
            print("  domain                 دامنه (.ir/.ایران با WHOIS ایرنیک، بقیه با RDAP)")
        for s in (x for x in SITES if x.category == key):
            print(f"  {s.key:<22} {s.name}")


# ═════════════════════════════ CLI ═════════════════════════════

def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="بررسی آزاد بودن نام در دامنه‌ها و شبکه‌های اجتماعی",
                                formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--fa", help='نام فارسی (برای دامنه فارسی)، مثل "علی رضایی"')
    p.add_argument("--en", help='نام انگلیسی (برای دامنه و یوزرنیم‌ها)، مثل "ali rezaei"')
    p.add_argument("--categories", default="domain,social,iran,dev",
                   help="دسته‌ها: domain,social,iran,dev (پیش‌فرض: همه)")
    p.add_argument("--sites", help="فقط این سایت‌ها (کلیدها، با کاما). مثال: instagram,telegram,domain")
    p.add_argument("--exclude", help="حذف این سایت‌ها. مثال: facebook,kick")
    p.add_argument("--tlds", default="ir,ایران,com", help="پسوندهای دامنه (پیش‌فرض: ir,ایران,com)")
    p.add_argument("--variants", action="store_true", help="بررسی حالت‌های جایگزین (name_ir, thename, ...)")
    p.add_argument("--proxy", help="پراکسی: http://host:port یا socks5h://127.0.0.1:9050")
    p.add_argument("--proxy-sites", help="پراکسی فقط برای این سایت‌ها (پیش‌فرض: همه). مثال: instagram,x")
    p.add_argument("--tor-control", type=int, help="پورت کنترل Tor (مثلاً 9051) برای عوض کردن IP هنگام 429")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--delay", type=float, default=0.6, help="حداکثر تأخیر تصادفی قبل از هر درخواست")
    p.add_argument("--no-calibrate", action="store_true", help="رد کردن کالیبراسیون (سریع‌تر، کم‌دقت‌تر)")
    p.add_argument("--no-fragment", action="store_true", help="عدم بررسی Fragment برای تلگرام")
    p.add_argument("--json"), p.add_argument("--csv")
    p.add_argument("--markdown", help="افزودن گزارش Markdown به این فایل (مثلاً $GITHUB_STEP_SUMMARY)")
    p.add_argument("--no-input", action="store_true", help="هیچ‌وقت نام را تعاملی نپرس (برای CI)")
    p.add_argument("--list-sites", action="store_true", help="نمایش همه‌ی سایت‌های پشتیبانی‌شده")
    args = p.parse_args(argv)

    if args.list_sites:
        list_sites()
        sys.exit(0)
    args.fa = (args.fa or "").strip() or None
    args.en = (args.en or "").strip() or None
    if not args.fa and not args.en and not args.no_input and sys.stdin.isatty():
        try:
            args.fa = input("نام فارسی (اختیاری): ").strip() or None
            args.en = input("نام انگلیسی (اختیاری): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
    if not args.fa and not args.en:
        p.error("حداقل یکی از --fa یا --en لازم است")
    bad = [c for c in args.categories.split(",") if c.strip() and c.strip() not in CATEGORIES]
    if bad:
        p.error(f"دسته‌ی ناشناخته: {', '.join(bad)}")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    proxy_sites = {s.strip() for s in args.proxy_sites.split(",") if s.strip()} if args.proxy_sites else None
    http = Http(args.proxy, proxy_sites, args.timeout, args.delay, tor_control=args.tor_control)
    checker = Checker(http, use_fragment=not args.no_fragment, calibrate=not args.no_calibrate)
    tasks = build_tasks(args, checker)
    if not tasks:
        print("چیزی برای بررسی ساخته نشد (یوزرنیم‌ها فقط از نام انگلیسی ساخته می‌شوند).")
        return 1

    print(f"در حال بررسی {len(tasks)} مورد ...", flush=True)
    results: list[Result] = []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = [ex.submit(safe_call, *t) for t in tasks]
        for i, fut in enumerate(cf.as_completed(futs), 1):
            results.append(fut.result())
            if sys.stdout.isatty():
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
