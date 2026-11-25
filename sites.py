# -*- coding: utf-8 -*-
"""
تعریف پلتفرم‌هایی که name_checker.py بررسی می‌کند.

برای اضافه کردن یک سایت جدید کافی است یک Site به لیست SITES اضافه کنید.

روش‌های تشخیص (method):
  status   → کد HTTP: free_status یعنی آزاد، taken_status یعنی گرفته شده
  json     → پاسخ JSON به تابع json_free داده می‌شود: True=آزاد، False=گرفته، None=نامشخص
  marker   → وجود متن‌های taken_markers / free_markers در HTML ({u} = یوزرنیم)
  baseline → مقایسه صفحه با صفحه‌ی یک یوزرنیم تصادفی ناموجود (برای سایت‌هایی که 404 نمی‌دهند)
  custom   → تابع اختصاصی در name_checker.py (اینستاگرام، X، تلگرام، Twitch)

known: یک یوزرنیم که مطمئنیم وجود دارد. پیش از بررسی، اسکریپت سایت را «کالیبره» می‌کند:
  یک یوزرنیم تصادفی باید «آزاد» و known باید «گرفته» تشخیص داده شود؛ وگرنه آن سایت
  به‌جای نتیجه‌ی غلط، «نامشخص» گزارش می‌شود (مثلاً وقتی سایت IP را بلاک کرده یا ساختارش عوض شده).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

CATEGORIES = {
    "domain": "🌐 دامنه",
    "social": "🌍 شبکه‌های اجتماعی خارجی",
    "iran": "🇮🇷 پلتفرم‌های ایرانی",
    "dev": "💻 برنامه‌نویسی و تخصصی",
}


@dataclass
class Site:
    key: str
    name: str
    category: str
    url: str                                  # آدرس پروفایل برای نمایش، با {u}
    method: str = "status"
    check_url: Optional[str] = None           # آدرسی که واقعاً بررسی می‌شود (پیش‌فرض: url)
    free_status: tuple = (404,)
    taken_status: tuple = (200,)
    free_markers: tuple = ()
    taken_markers: tuple = ()
    json_free: Optional[Callable[[Any], Optional[bool]]] = None
    rule: str = r"^[A-Za-z0-9_]{3,30}$"
    rule_fa: str = "۳ تا ۳۰ کاراکتر؛ حروف لاتین، عدد و _"
    known: Optional[str] = None
    headers: dict = field(default_factory=dict)
    redirects: bool = True
    min_interval: float = 0.0                 # حداقل فاصله‌ی بین دو درخواست به این سایت (ثانیه)
    calibrate: bool = True
    custom: Optional[str] = None
    note: str = ""

    def profile(self, u: str) -> str:
        return self.url.replace("{u}", u)

    def target(self, u: str) -> str:
        return (self.check_url or self.url).replace("{u}", u)


def _keybase(d):
    code = (d.get("status") or {}).get("code")
    if code == 205:
        return True
    them = d.get("them") or []
    return False if them and them[0] else None


def _bsky(d):
    if d.get("did"):
        return False
    return True if "unable to resolve" in str(d.get("message", "")).lower() else None


SITES: list[Site] = [
    # ───────────── شبکه‌های اجتماعی خارجی ─────────────
    Site("instagram", "Instagram", "social", "https://www.instagram.com/{u}/", method="custom",
         custom="instagram", calibrate=False, min_interval=3.0,
         rule=r"^(?!\.)(?!.*\.\.)(?!.*\.$)[a-z0-9._]{1,30}$",
         rule_fa="۱ تا ۳۰ کاراکتر؛ حروف کوچک، عدد، . و _ (نقطه نه در ابتدا/انتها/پشت‌سرهم)",
         note="Threads هم از همین یوزرنیم استفاده می‌کند"),
    Site("x", "X (Twitter)", "social", "https://x.com/{u}", method="custom", custom="x",
         known="elonmusk", min_interval=1.0,
         rule=r"^(?!.*(?i:twitter|admin))[A-Za-z0-9_]{4,15}$",
         rule_fa="۴ تا ۱۵ کاراکتر؛ حروف لاتین، عدد و _ ؛ بدون twitter/admin"),
    Site("telegram", "Telegram", "social", "https://t.me/{u}", method="custom", custom="telegram",
         known="durov", rule=r"^[A-Za-z](?!.*__)[A-Za-z0-9_]{3,30}[A-Za-z0-9]$",
         rule_fa="۵ تا ۳۲ کاراکتر؛ شروع با حرف، بدون _ در انتها"),
    Site("youtube", "YouTube", "social", "https://www.youtube.com/@{u}", known="YouTube",
         rule=r"^[A-Za-z0-9._-]{3,30}$", rule_fa="۳ تا ۳۰ کاراکتر؛ حروف، عدد، . - _"),
    Site("tiktok", "TikTok", "social", "https://www.tiktok.com/@{u}", method="marker",
         taken_markers=('"uniqueId":"{u}"',), free_markers=('"statusCode":10221', '"statusCode":10202'),
         known="tiktok", rule=r"^[a-z0-9._]{2,24}$", rule_fa="۲ تا ۲۴ کاراکتر؛ حروف کوچک، عدد، . و _"),
    Site("twitch", "Twitch", "social", "https://www.twitch.tv/{u}", method="custom", custom="twitch",
         known="twitch", rule=r"^[A-Za-z0-9][A-Za-z0-9_]{3,24}$", rule_fa="۴ تا ۲۵ کاراکتر"),
    Site("reddit", "Reddit", "social", "https://www.reddit.com/user/{u}", method="json",
         check_url="https://www.reddit.com/api/username_available.json?user={u}", free_status=(),
         json_free=lambda d: d if isinstance(d, bool) else None, known="spez",
         rule=r"^[A-Za-z0-9_-]{3,20}$", rule_fa="۳ تا ۲۰ کاراکتر؛ حروف، عدد، - و _"),
    Site("bluesky", "Bluesky", "social", "https://bsky.app/profile/{u}.bsky.social", method="json",
         check_url="https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={u}.bsky.social",
         free_status=(), json_free=_bsky,
         rule=r"^[a-z0-9][a-z0-9-]{1,16}[a-z0-9]$", rule_fa="۳ تا ۱۸ کاراکتر؛ حروف کوچک، عدد و -"),
    Site("mastodon", "Mastodon (mastodon.social)", "social", "https://mastodon.social/@{u}",
         check_url="https://mastodon.social/api/v1/accounts/lookup?acct={u}", known="Gargron",
         rule=r"^[A-Za-z0-9_]{1,30}$", rule_fa="۱ تا ۳۰ کاراکتر؛ حروف، عدد و _"),
    Site("pinterest", "Pinterest", "social", "https://www.pinterest.com/{u}/", method="baseline",
         known="pinterest", rule=r"^[A-Za-z0-9_]{3,30}$"),
    Site("snapchat", "Snapchat", "social", "https://www.snapchat.com/add/{u}", method="baseline",
         known="teamsnapchat", rule=r"^[A-Za-z][A-Za-z0-9._-]{1,13}[A-Za-z0-9]$",
         rule_fa="۳ تا ۱۵ کاراکتر؛ شروع با حرف"),
    Site("facebook", "Facebook", "social", "https://www.facebook.com/{u}", method="baseline",
         known="zuck", rule=r"^[A-Za-z0-9.]{5,50}$", rule_fa="حداقل ۵ کاراکتر؛ حروف، عدد و نقطه",
         note="فیسبوک معمولاً صفحه‌ی لاگین نشان می‌دهد؛ اگر کالیبره نشود «نامشخص» می‌ماند"),
    Site("medium", "Medium", "social", "https://medium.com/@{u}", known="ev",
         rule=r"^[A-Za-z0-9_.]{2,30}$"),
    Site("tumblr", "Tumblr", "social", "https://{u}.tumblr.com/", known="staff",
         rule=r"^[A-Za-z0-9-]{1,32}$", rule_fa="۱ تا ۳۲ کاراکتر؛ حروف، عدد و -"),
    Site("vimeo", "Vimeo", "social", "https://vimeo.com/{u}", known="staff",
         rule=r"^[A-Za-z][A-Za-z0-9_]{2,29}$"),
    Site("soundcloud", "SoundCloud", "social", "https://soundcloud.com/{u}", known="forss",
         rule=r"^[a-z0-9_-]{3,25}$"),
    Site("kick", "Kick", "social", "https://kick.com/{u}",
         check_url="https://kick.com/api/v2/channels/{u}", known="xqc",
         rule=r"^[A-Za-z0-9_]{4,25}$"),
    Site("steam", "Steam", "social", "https://steamcommunity.com/id/{u}", method="marker",
         free_markers=("The specified profile could not be found",),
         taken_markers=("profile_header_bg",), known="gabelogannewell",
         rule=r"^[A-Za-z0-9_-]{3,32}$"),
    Site("linktree", "Linktree", "social", "https://linktr.ee/{u}", known="linktree",
         rule=r"^[A-Za-z0-9_.]{3,30}$"),
    Site("patreon", "Patreon", "social", "https://www.patreon.com/{u}", known="patreon",
         rule=r"^[A-Za-z0-9_]{3,64}$"),
    Site("dribbble", "Dribbble", "social", "https://dribbble.com/{u}", known="dribbble",
         rule=r"^[A-Za-z0-9_-]{2,20}$"),
    Site("behance", "Behance", "social", "https://www.behance.net/{u}", method="baseline",
         known="behance", rule=r"^[A-Za-z0-9_-]{3,30}$"),
    Site("aboutme", "about.me", "social", "https://about.me/{u}", known="tony",
         rule=r"^[A-Za-z0-9_-]{3,30}$"),

    # ───────────── پلتفرم‌های ایرانی ─────────────
    Site("bale", "بله", "iran", "https://ble.ir/{u}", method="baseline", known="bale",
         rule=r"^[A-Za-z][A-Za-z0-9_]{4,31}$", rule_fa="حدود ۵ تا ۳۲ کاراکتر؛ شروع با حرف"),
    Site("eitaa", "ایتا", "iran", "https://eitaa.com/{u}", method="baseline", known="eitaa",
         rule=r"^[A-Za-z][A-Za-z0-9_]{4,31}$", rule_fa="حدود ۵ تا ۳۲ کاراکتر؛ شروع با حرف"),
    Site("rubika", "روبیکا", "iran", "https://rubika.ir/{u}", method="baseline", known="rubika",
         rule=r"^[A-Za-z][A-Za-z0-9_]{4,31}$", rule_fa="حدود ۵ تا ۳۲ کاراکتر؛ شروع با حرف"),
    Site("splus", "سروش پلاس", "iran", "https://splus.ir/{u}", method="baseline", known="splus",
         rule=r"^[A-Za-z][A-Za-z0-9_]{4,31}$", rule_fa="حدود ۵ تا ۳۲ کاراکتر؛ شروع با حرف"),
    Site("aparat", "آپارات", "iran", "https://www.aparat.com/{u}", method="baseline", known="aparat",
         rule=r"^[A-Za-z0-9_]{3,30}$"),
    Site("virgool", "ویرگول", "iran", "https://virgool.io/@{u}", method="baseline", known="virgool",
         rule=r"^[A-Za-z0-9_]{3,30}$"),
    Site("namasha", "نماشا", "iran", "https://www.namasha.com/{u}", method="baseline", known="namasha",
         rule=r"^[A-Za-z0-9_]{3,30}$"),
    Site("virasty", "ویراستی", "iran", "https://virasty.com/{u}", method="baseline", known="virasty",
         rule=r"^[A-Za-z0-9_]{3,30}$"),

    # ───────────── برنامه‌نویسی و تخصصی ─────────────
    Site("github", "GitHub", "dev", "https://github.com/{u}",
         check_url="https://api.github.com/users/{u}", known="torvalds",
         rule=r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$",
         rule_fa="۱ تا ۳۹ کاراکتر؛ حروف، عدد و - (نه در ابتدا/انتها)"),
    Site("gitlab", "GitLab", "dev", "https://gitlab.com/{u}", method="json",
         check_url="https://gitlab.com/api/v4/users?username={u}", free_status=(),
         json_free=lambda d: (len(d) == 0) if isinstance(d, list) else None, known="dzaporozhets",
         rule=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{1,254}$"),
    Site("codeberg", "Codeberg", "dev", "https://codeberg.org/{u}",
         check_url="https://codeberg.org/api/v1/users/{u}", known="fnetx",
         rule=r"^[A-Za-z0-9_.-]{1,40}$"),
    Site("dockerhub", "Docker Hub", "dev", "https://hub.docker.com/u/{u}",
         check_url="https://hub.docker.com/v2/users/{u}/", known="bitnami",
         rule=r"^[a-z0-9]{4,30}$", rule_fa="۴ تا ۳۰ کاراکتر؛ فقط حروف کوچک و عدد"),
    Site("npm", "npm", "dev", "https://www.npmjs.com/~{u}",
         check_url="https://registry.npmjs.org/-/user/org.couchdb.user:{u}", known="isaacs",
         rule=r"^[a-z0-9][a-z0-9._-]{0,213}$"),
    Site("pypi", "PyPI", "dev", "https://pypi.org/user/{u}/", known="dstufft",
         rule=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$"),
    Site("huggingface", "Hugging Face", "dev", "https://huggingface.co/{u}", known="julien-c",
         rule=r"^[A-Za-z0-9][A-Za-z0-9-]{1,41}$"),
    Site("devto", "DEV.to", "dev", "https://dev.to/{u}",
         check_url="https://dev.to/api/users/by_username?url={u}", known="ben",
         rule=r"^[A-Za-z0-9_]{2,30}$"),
    Site("keybase", "Keybase", "dev", "https://keybase.io/{u}", method="json",
         check_url="https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", free_status=(),
         json_free=_keybase, known="chris", rule=r"^[a-z0-9_]{2,16}$"),
    Site("replit", "Replit", "dev", "https://replit.com/@{u}", method="baseline", known="amasad",
         rule=r"^[A-Za-z0-9_-]{2,30}$"),
]

SITES_BY_KEY = {s.key: s for s in SITES}
