#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
site_audit.py v2 — أداة فحص أمني خارجي عامة وغير مُتلِفة لمواقع الويب ونطاقاتها.

الفحوصات:
  • TLS: الإصدارات القديمة، TLS 1.3، التشفير الضعيف، الشهادة وتاريخ انتهائها
  • HTTPS: التحويل من HTTP، سلسلة التحويلات، HSTS
  • الهيدرات: CSP، nosniff، Clickjacking، Referrer/Permissions-Policy، تسريب الإصدارات
  • المحتوى: السكربتات الخارجية و SRI، الاستيراد الديناميكي، eval، المحتوى المختلط، النماذج
  • التقنيات: CDN/الخادم/CMS، المكتبات القديمة (jQuery, Bootstrap, AngularJS …)
  • WordPress: كشف المستخدمين، xmlrpc، سجلات التصحيح، فهرسة المجلدات
  • الكوكيز، CORS، طرق HTTP الخطرة (TRACE)، فهرسة المجلدات، الملفات الحساسة المكشوفة
  • security.txt
  • DNS والبريد: SPF، DMARC، DKIM، CAA، DNSSEC، MTA-STS، TLS-RPT
  • العنوان والشبكة: عناوين IPv4/IPv6، المزوّد (ASN)، الدولة، الاسم العكسي
  • WAF: كشف نوع جدار الحماية (~18 نظاماً)، اختبار هل يحجب الهجمات، وكشف عنوان الخادم الأصلي
  • اختياري: المنافذ المكشوفة (--ports)، النطاقات الفرعية وخطر الاستيلاء (--subdomains)
  • --passive: وضع سلبي بالكامل لمواقع لا تملكها

بدون أي مكتبة خارجية (Python 3.8+). DNS عبر DNS-over-HTTPS.
⚠ استخدمها فقط على مواقع تملكها أو لديك إذن مكتوب بفحصها.

أمثلة:
  python3 site_audit.py example.com
  python3 site_audit.py site1.com site2.org --html report.html
  python3 site_audit.py -f targets.txt --full --html report.html --json report.json
  python3 site_audit.py www.example.gov --passive --html report.html --open
"""

import argparse
import concurrent.futures as cf
import datetime as dt
import html
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import urllib.parse
import urllib.request
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

VERSION = "2.2"
UA = "Mozilla/5.0 (compatible; SiteAudit/%s; +security-self-assessment)" % VERSION

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"
ICONS = {PASS: "✔", WARN: "⚠", FAIL: "✖", INFO: "ℹ"}
LABELS = {PASS: "سليم", WARN: "تحذير", FAIL: "خطر", INFO: "معلومة"}
COLORS = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", INFO: "\033[36m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"

C_TLS, C_HTTPS, C_HDR, C_CONTENT, C_TECH = "TLS والشهادة", "HTTPS والتحويلات", "هيدرات الأمان", "السكربتات والمحتوى", "التقنيات والمكتبات"
C_WP, C_COOKIE, C_EXPOSE, C_SECTXT = "WordPress", "الكوكيز و CORS والطرق", "ملفات ومجلدات مكشوفة", "security.txt"
C_DNS, C_PORTS, C_SUBS = "DNS والبريد", "المنافذ المكشوفة", "النطاقات الفرعية"
C_NET, C_WAF = "العنوان والشبكة", "جدار حماية تطبيقات الويب (WAF)"


# ═════════════════════════════ أدوات عامة ═════════════════════════════

class Ctx:
    def __init__(self, timeout):
        self.timeout = timeout
        self.verify = True


class Results:
    def __init__(self, target):
        self.target = target
        self.final_url = None
        self.domain = None
        self.ips = []
        self.items = []

    def add(self, category, status, title, detail="", fix=""):
        self.items.append({"category": category, "status": status, "title": title,
                           "detail": detail, "fix": fix})

    def counts(self):
        c = {PASS: 0, WARN: 0, FAIL: 0, INFO: 0}
        for i in self.items:
            c[i["status"]] += 1
        return c

    def score(self):
        c = self.counts()
        return max(0, 100 - c[FAIL] * 12 - c[WARN] * 4)

    def grade(self):
        s = self.score()
        for g, lim in (("A", 90), ("B", 80), ("C", 70), ("D", 60)):
            if s >= lim:
                return g
        return "F"

    def sorted_items(self):
        order = []
        for i in self.items:
            if i["category"] not in order:
                order.append(i["category"])
        return sorted(self.items, key=lambda i: order.index(i["category"]))

    def to_dict(self):
        return {"target": self.target, "final_url": self.final_url, "domain": self.domain, "ips": self.ips,
                "score": self.score(), "grade": self.grade(), "counts": self.counts(),
                "results": self.sorted_items()}


class Response:
    def __init__(self, status, headers, body, url):
        self.status, self.headers, self.body, self.url = status, headers, body, url

    def header(self, name):
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None

    def header_all(self, name):
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def text(self):
        return self.body.decode("utf-8", "replace")


def fetch(ctx, url, method="GET", extra_headers=None, max_body=2_000_000, verify=None):
    """طلب HTTP واحد بدون تتبع التحويلات."""
    u = urllib.parse.urlsplit(url)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    hdrs = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity"}
    if extra_headers:
        hdrs.update(extra_headers)
    verify = ctx.verify if verify is None else verify
    if u.scheme == "https":
        sc = ssl.create_default_context()
        if not verify:
            sc.check_hostname = False
            sc.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=ctx.timeout, context=sc)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=ctx.timeout)
    try:
        conn.request(method, path, headers=hdrs)
        r = conn.getresponse()
        body = b"" if method in ("HEAD", "OPTIONS", "TRACE") else r.read(max_body)
        return Response(r.status, r.getheaders(), body, url)
    finally:
        conn.close()


def fetch_follow(ctx, url, max_hops=8):
    """يتبع التحويلات ويعيد (الاستجابة النهائية، السلسلة)."""
    chain = []
    for _ in range(max_hops):
        r = fetch(ctx, url)
        chain.append((url, r.status))
        loc = r.header("Location")
        if r.status in (301, 302, 303, 307, 308) and loc:
            url = urllib.parse.urljoin(url, loc)
            continue
        return r, chain
    return r, chain


RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "DNSKEY": 48, "CAA": 257}


def doh(name, rtype, timeout, dnssec=False):
    """استعلام DNS عبر DNS-over-HTTPS. status=3 يعني NXDOMAIN."""
    q = urllib.parse.urlencode({"name": name, "type": rtype, "do": "1" if dnssec else "0"})
    last = None
    for base in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
        try:
            req = urllib.request.Request(base + "?" + q, headers={"Accept": "application/dns-json", "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                j = json.loads(r.read().decode())
            want = RTYPES.get(rtype)
            return {"ok": True, "status": j.get("Status"), "ad": bool(j.get("AD")),
                    "answers": [a.get("data", "") for a in j.get("Answer", []) if a.get("type") == want],
                    "all": j.get("Answer", [])}
        except Exception as e:  # noqa: BLE001
            last = e
    return {"ok": False, "error": str(last), "status": None, "ad": False, "answers": [], "all": []}


def txt_join(data):
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts) if parts else data.strip('"')


SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "sch", "mil", "nic", "ltd", "plc",
                "me", "gob", "or", "ne", "go", "info", "biz", "med", "web"}
PRIVATE_SUFFIXES = ("github.io", "gitlab.io", "herokuapp.com", "pages.dev", "workers.dev", "r2.dev",
                    "vercel.app", "netlify.app", "blogspot.com", "azurewebsites.net", "cloudfront.net",
                    "firebaseapp.com", "web.app", "appspot.com", "onrender.com", "fly.dev")


def registrable_domain(host):
    host = host.strip(".").lower()
    for sfx in PRIVATE_SUFFIXES:
        if host.endswith("." + sfx):
            return ".".join(host.split(".")[-(sfx.count(".") + 2):])
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


# ═════════════════════════════ TLS ═════════════════════════════

TLS_VERSIONS = [("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1"), ("TLS 1.2", "TLSv1_2"), ("TLS 1.3", "TLSv1_3")]
CLIENT_SIDE_ERRORS = ("NO_PROTOCOLS_AVAILABLE", "UNSUPPORTED_PROTOCOL", "NO_CIPHERS_AVAILABLE",
                      "no protocols available", "unsupported protocol", "No cipher can be selected")


def try_tls(host, port, ver_name, timeout, ciphers="ALL:@SECLEVEL=0"):
    """True = قبِل، False = رفض، None = لا يمكن الاختبار من هذا الجهاز."""
    ver = getattr(ssl.TLSVersion, ver_name, None)
    if ver is None:
        return None, None
    sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sc.check_hostname = False
    sc.verify_mode = ssl.CERT_NONE
    try:
        sc.set_ciphers(ciphers)
        sc.minimum_version = ver
        sc.maximum_version = ver
    except (ValueError, ssl.SSLError):
        return None, None
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with sc.wrap_socket(s, server_hostname=host) as ss:
                return True, ss.cipher()
    except ssl.SSLError as e:
        return (None, None) if any(x in str(e) for x in CLIENT_SIDE_ERRORS) else (False, None)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return False, None
    except OSError:
        return None, None


def check_tls(res, ctx, host, port, label=""):
    cat = C_TLS
    pre = (label + ": ") if label else ""
    acc = {lab: try_tls(host, port, name, ctx.timeout) for lab, name in TLS_VERSIONS}

    for lab in ("TLS 1.0", "TLS 1.1"):
        ok, ciph = acc[lab]
        if ok:
            res.add(cat, FAIL, pre + "%s مقبول" % lab, "التشفير: %s" % (ciph[0] if ciph else "?"),
                    "اضبط الحد الأدنى على TLS 1.2 (في Cloudflare: Edge Certificates ← Minimum TLS Version).")
        elif ok is False:
            res.add(cat, PASS, pre + "%s مرفوض" % lab)
        else:
            res.add(cat, INFO, pre + "تعذّر اختبار %s من هذا الجهاز" % lab, "مكتبة OpenSSL المحلية لا تسمح به.",
                    "openssl s_client -tls1 -connect %s:%d" % (host, port))
    ok12, _ = acc["TLS 1.2"]
    ok13, c13 = acc["TLS 1.3"]
    if ok13:
        res.add(cat, PASS, pre + "TLS 1.3 مدعوم", c13[0] if c13 else "")
    elif ok13 is False:
        res.add(cat, WARN, pre + "TLS 1.3 غير مدعوم", "", "فعّل TLS 1.3 في الخادم.")
    if ok12 is False and not ok13:
        res.add(cat, FAIL, pre + "لا يقبل أي بروتوكول حديث")

    if ok12:
        weak, wc = try_tls(host, port, "TLSv1_2", ctx.timeout, ciphers="3DES:RC4:NULL:EXPORT:!aNULL:@SECLEVEL=0")
        if weak:
            res.add(cat, WARN, pre + "تشفير ضعيف مقبول في TLS 1.2", wc[0] if wc else "", "عطّل 3DES/RC4/NULL.")
        elif weak is False:
            res.add(cat, PASS, pre + "لا يقبل تشفير 3DES/RC4")
        nofs, nc = try_tls(host, port, "TLSv1_2", ctx.timeout, ciphers="kRSA:!aNULL:@SECLEVEL=0")
        if nofs:
            res.add(cat, WARN, pre + "تبادل مفاتيح RSA بدون Forward Secrecy مقبول", nc[0] if nc else "",
                    "اقصر التشفير على ECDHE مع AES-GCM أو ChaCha20.")

    try:
        sc = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=ctx.timeout) as s:
            with sc.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
        na = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (na - dt.datetime.utcnow()).days
        iss = dict(x[0] for x in cert.get("issuer", ()))
        detail = "تنتهي %s (بعد %d يوماً) — المُصدِر: %s" % (na.date(), days, iss.get("organizationName", iss.get("commonName", "?")))
        if days < 7:
            res.add(cat, FAIL, pre + "الشهادة على وشك الانتهاء", detail, "جدّد الشهادة فوراً.")
        elif days < 21:
            res.add(cat, WARN, pre + "الشهادة تنتهي قريباً", detail, "تأكد أن التجديد التلقائي يعمل.")
        else:
            res.add(cat, PASS, pre + "الشهادة صالحة وموثوقة", detail)
    except ssl.SSLCertVerificationError as e:
        ctx.verify = False
        res.add(cat, FAIL, pre + "الشهادة غير موثوقة", getattr(e, "verify_message", str(e)),
                "استخدم شهادة من جهة موثوقة تطابق اسم النطاق ومكتملة السلسلة.")
    except Exception as e:  # noqa: BLE001
        res.add(cat, WARN, pre + "تعذّر فحص الشهادة", str(e))


# ═════════════════════════════ HTTPS والهيدرات ═════════════════════════════

def check_https_redirect(res, ctx, host):
    try:
        r = fetch(ctx, "http://%s/" % host, max_body=1)
    except Exception as e:  # noqa: BLE001
        res.add(C_HTTPS, INFO, "المنفذ 80 (HTTP) لا يستجيب", str(e))
        return
    loc = r.header("Location") or ""
    if r.status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
        st = PASS if r.status in (301, 308) else WARN
        res.add(C_HTTPS, st, "HTTP يتحول إلى HTTPS (%d)" % r.status, loc, "" if st == PASS else "استخدم تحويلاً دائماً 301/308.")
    elif r.status in (301, 302, 303, 307, 308):
        res.add(C_HTTPS, FAIL, "HTTP يتحول إلى عنوان غير مشفر", loc, "اجعل التحويل إلى https://")
    else:
        res.add(C_HTTPS, FAIL, "HTTP لا يتحول إلى HTTPS", "الاستجابة: %d" % r.status,
                "فعّل التحويل الدائم من HTTP إلى HTTPS.")


def parse_csp(value):
    d = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            d[bits[0].lower()] = bits[1:]
    return d


def check_headers(res, r):
    cat = C_HDR
    hsts = r.header("Strict-Transport-Security")
    if not hsts:
        res.add(cat, FAIL, "HSTS غير موجود", "", "أضف Strict-Transport-Security: max-age=31536000")
    else:
        m = re.search(r"max-age=\s*\"?(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        if age < 15552000:
            res.add(cat, WARN, "مدة HSTS قصيرة", hsts, "اجعل max-age لا يقل عن 15552000 (6 أشهر).")
        else:
            notes = [n for n, k in (("بدون includeSubDomains", "includesubdomains"), ("بدون preload", "preload")) if k not in hsts.lower()]
            res.add(cat, PASS, "HSTS مفعّل", hsts + ((" — " + "، ".join(notes)) if notes else ""))

    csp, csp_ro = r.header("Content-Security-Policy"), r.header("Content-Security-Policy-Report-Only")
    if csp:
        d = parse_csp(csp)
        script = d.get("script-src", d.get("default-src", []))
        bad = [x for x in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:") if x in script]
        nonce = any(x.startswith("'nonce-") or x == "'strict-dynamic'" for x in script)
        if bad and not ("'unsafe-inline'" in bad and nonce and len(bad) == 1):
            res.add(cat, WARN, "CSP مفعّل لكن script-src متساهل", "يحتوي: " + " ".join(bad),
                    "أزل unsafe-inline/unsafe-eval والمصادر العامة، أو استخدم nonce.")
        elif not script:
            res.add(cat, WARN, "CSP بدون script-src أو default-src", csp[:120])
        else:
            res.add(cat, PASS, "CSP مفعّل (وضع الإلزام)")
        for k in ("object-src", "base-uri", "frame-ancestors"):
            if k not in d and not (k == "object-src" and "'none'" in d.get("default-src", [])):
                res.add(cat, INFO, "CSP بدون %s" % k, "", "أضف %s للتشديد." % k)
    elif csp_ro:
        res.add(cat, WARN, "CSP بوضع المراقبة فقط (Report-Only)", "السياسة لا تمنع شيئاً.",
                "بعد التأكد من عدم وجود مخالفات غيّر الهيدر إلى Content-Security-Policy.")
    else:
        res.add(cat, FAIL if "text/html" in (r.header("Content-Type") or "") else WARN,
                "لا يوجد Content-Security-Policy", "", "أضف CSP يحدد مصادر السكربتات المسموحة.")

    xcto = (r.header("X-Content-Type-Options") or "").lower()
    res.add(cat, PASS if xcto == "nosniff" else WARN,
            "X-Content-Type-Options" + (": nosniff" if xcto == "nosniff" else " مفقود"), "",
            "" if xcto == "nosniff" else "أضف X-Content-Type-Options: nosniff")

    xfo = r.header("X-Frame-Options")
    fa = "frame-ancestors" in (csp or "").lower()
    res.add(cat, PASS if (xfo or fa) else WARN,
            "حماية من Clickjacking" if (xfo or fa) else "لا حماية من Clickjacking",
            xfo or ("CSP frame-ancestors" if fa else ""),
            "" if (xfo or fa) else "أضف X-Frame-Options: DENY أو frame-ancestors في CSP.")

    rp = r.header("Referrer-Policy")
    ok_rp = rp and rp.lower().split(",")[-1].strip() not in ("unsafe-url", "no-referrer-when-downgrade")
    res.add(cat, PASS if ok_rp else WARN, "Referrer-Policy" if ok_rp else "Referrer-Policy مفقود أو متساهل", rp or "",
            "" if ok_rp else "أضف Referrer-Policy: strict-origin-when-cross-origin")

    pp = r.header("Permissions-Policy")
    res.add(cat, PASS if pp else WARN, "Permissions-Policy" + ("" if pp else " مفقود"), (pp or "")[:160],
            "" if pp else "أضف Permissions-Policy: geolocation=(), camera=(), microphone=()")

    coop = r.header("Cross-Origin-Opener-Policy")
    if coop:
        res.add(cat, PASS, "Cross-Origin-Opener-Policy", coop)

    leaks = ["%s: %s" % (h, r.header(h)) for h in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                                                   "X-Generator", "X-Drupal-Cache", "X-Runtime") if r.header(h)]
    server = r.header("Server") or ""
    if re.search(r"\d", server):
        leaks.append("Server: " + server)
    if leaks:
        res.add(cat, WARN, "الخادم يكشف تقنياته أو إصداراتها", " | ".join(leaks), "أخفِ هذه الهيدرات أو أرقام الإصدارات.")
    else:
        res.add(cat, PASS, "لا تسريب لإصدارات البرمجيات", ("Server: " + server) if server else "")


# ═════════════════════════════ المحتوى والتقنيات ═════════════════════════════

SCRIPT_TAG = re.compile(r"<script\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w-]+)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))')
IMPORT_RE = re.compile(r"""(?:\bimport\s*(?:[\w*{}\s,$]+\s*from\s*)?|\bimport\s*\(\s*|\bexport\s*[\w*{}\s,$]+\s*from\s*)["'`]([^"'`]+)["'`]""")
ABS_JS = re.compile(r"""https?://[^\s"'`()<>\\]+\.m?js(?=["'`\s?#)]|$)""")


def attrs(tag):
    out = {}
    for m in ATTR.finditer(tag):
        out[m.group(1).lower()] = m.group(3) or m.group(4) or m.group(5) or ""
    return out


# مكتبات معروفة: (الاسم، أنماط الإصدار في الرابط أو المحتوى، الحد الأدنى الآمن، ملاحظة)
LIBS = [
    ("jQuery", [r"(?<![\w.-])jquery[.-](\d+\.\d+\.\d+)(?:\.slim)?(?:\.min)?\.js", r"jquery@(\d+\.\d+\.\d+)", r"/jquery/(\d+\.\d+\.\d+)/jquery", r"/\*!? jQuery v(\d+\.\d+\.\d+) ", r"jQuery JavaScript Library v(\d+\.\d+\.\d+)"],
     "3.5.0", "أقدم من 3.5.0: ثغرتا XSS (CVE-2020-11022 و CVE-2020-11023). أقدم من 3.4.0: Prototype Pollution (CVE-2019-11358). أقدم من 3.0.0: تنفيذ ردود Ajax عبر النطاقات (CVE-2015-9251)."),
    ("jQuery UI", [r"jquery-ui[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", r"jQuery UI - v(\d+\.\d+\.\d+)", r"/jqueryui/(\d+\.\d+\.\d+)/"],
     "1.13.2", "إصدارات أقدم من 1.13.2 فيها ثغرات XSS."),
    ("Bootstrap", [r"bootstrap@(\d+\.\d+\.\d+)", r"/bootstrap/(\d+\.\d+\.\d+)/", r"Bootstrap v(\d+\.\d+\.\d+)"],
     "4.3.1", "إصدارات 3.x أقدم من 3.4.1 و4.x أقدم من 4.3.1 فيها ثغرات XSS."),
    ("AngularJS", [r"angular@(1\.\d+\.\d+)", r"/angular\.js/(1\.\d+\.\d+)/", r"AngularJS v(1\.\d+\.\d+)"],
     "99.0.0", "AngularJS 1.x متوقف عن الدعم منذ 2022 ولن يحصل على إصلاحات."),
    ("Lodash", [r"lodash@(\d+\.\d+\.\d+)", r"/lodash\.js/(\d+\.\d+\.\d+)/"],
     "4.17.21", "إصدارات أقدم من 4.17.21 فيها ثغرات Prototype Pollution."),
    ("Moment.js", [r"moment@(\d+\.\d+\.\d+)", r"/moment\.js/(\d+\.\d+\.\d+)/"],
     "2.29.4", "إصدارات أقدم من 2.29.4 فيها ثغرة ReDoS."),
]


# الإصدارات الرئيسية الحقيقية: الرئيسي → أعلى إصدار فرعي معروف (للتحقق من صحة الاكتشاف)
VALID_MINOR = {"jQuery": {1: 12, 2: 2, 3: 9, 4: 9}, "Bootstrap": {2: 3, 3: 4, 4: 6, 5: 9}, "AngularJS": {1: 8}}


def detect_libs(text, found, src):
    for name, pats, safe, note in LIBS:
        for p in pats:
            for v in re.findall(p, text, re.I if not p.startswith("/\\*") else 0):
                found.setdefault(name, {}).setdefault(v, set()).add(src)


def check_content(res, ctx, base_url, home, max_js=40):
    cat = C_CONTENT
    page = home.text()
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(base_url))
    libs = {}
    detect_libs(page, libs, "الصفحة الرئيسية")

    ext_tags, local_js = [], []
    for m in SCRIPT_TAG.finditer(page):
        a = attrs(m.group(1))
        src = a.get("src")
        if not src:
            continue
        full = urllib.parse.urljoin(base_url, src)
        if full.startswith(origin):
            local_js.append(full)
        else:
            ext_tags.append((full, "integrity" in a))
        detect_libs(full, libs, full)

    for url, sri in ext_tags:
        if sri:
            res.add(cat, PASS, "سكربت خارجي محمي بـ SRI", url)
        else:
            res.add(cat, WARN, "سكربت خارجي بدون SRI", url, "أضف integrity و crossorigin، أو استضف الملف محلياً.")

    seen, queue, dyn = set(), list(local_js), set()
    evals = []
    while queue and len(seen) < max_js:
        u = queue.pop(0)
        if u in seen:
            continue
        seen.add(u)
        try:
            r = fetch(ctx, u)
        except Exception:  # noqa: BLE001
            continue
        if r.status != 200:
            continue
        code = r.text()
        detect_libs(code[:4000], libs, u)
        for spec in IMPORT_RE.findall(code):
            full = urllib.parse.urljoin(u, spec)
            if full.startswith(origin):
                if full not in seen and re.search(r"\.m?js(\?|$)", full):
                    queue.append(full)
            elif full.startswith("http"):
                dyn.add(full)
        for absu in ABS_JS.findall(code):
            if not absu.startswith(origin):
                dyn.add(absu)
        if re.search(r"//[#@]\s*sourceMappingURL=(?!data:)", code):
            res.add(cat, INFO, "ملف source map مُشار إليه", u, "احذف source maps من النسخة المنشورة إن لم تكن مقصودة.")
        if re.search(r"(?<![\w.$])eval\s*\(|new\s+Function\s*\(", code):
            evals.append(u.rsplit("/", 1)[-1])
    if evals:
        res.add(cat, INFO, "استخدام eval أو new Function في %d ملف" % len(evals), "، ".join(evals[:6]),
                "شائع في المكتبات المضغوطة؛ تأكد أنه لا يعالج مدخلات المستخدم.")
    for u in sorted(dyn):
        detect_libs(u, libs, u)
        res.add(cat, WARN, "سكربت يُحمَّل ديناميكياً من مصدر خارجي", u, "الاستيراد الديناميكي لا يدعم SRI — استضف الملف محلياً.")
    if local_js:
        res.add(cat, INFO, "تم تحليل %d ملف JavaScript محلي" % len(seen))
    if not ext_tags and not dyn:
        res.add(cat, PASS, "لا سكربتات من مصادر خارجية")

    mixed = sorted(set(re.findall(r"""(?:src|href|action|data)\s*=\s*["'](http://[^"']+)""", page, re.I)))
    mixed_res = [m for m in mixed if not re.search(r"<a\b[^>]*href=[\"']" + re.escape(m), page, re.I)]
    if mixed_res:
        res.add(cat, WARN, "موارد تُحمَّل عبر HTTP غير مشفر (%d)" % len(mixed_res), " | ".join(mixed_res[:5]), "حوّل الروابط إلى https://")
    else:
        res.add(cat, PASS, "لا محتوى مختلط (HTTP)")

    for f in re.findall(r"<form\b[^>]*>", page, re.I):
        act = attrs(f).get("action", "")
        if act.startswith("http://"):
            res.add(cat, FAIL, "نموذج يرسل بيانات عبر HTTP", act, "اجعل action يبدأ بـ https://")
    if re.search(r'<input[^>]+type=["\']?password', page, re.I) and not base_url.startswith("https"):
        res.add(cat, FAIL, "حقل كلمة مرور في صفحة غير مشفرة")

    # المكتبات القديمة
    for name, pats, safe, note in LIBS:
        for v, srcs in sorted(libs.get(name, {}).items()):
            where = "المصدر: " + " | ".join(sorted(srcs)[:3])
            vt = vtuple(v)
            valid = VALID_MINOR.get(name)
            if valid and (vt[0] not in valid or vt[1] > valid[vt[0]]):
                res.add(C_TECH, INFO, "رقم إصدار غير معروف لـ %s: %s" % (name, v),
                        where + " — غالباً ليس %s نفسه بل ملف آخر يحمل رقماً مشابهاً؛ تحقق يدوياً." % name)
                continue
            old = vt < vtuple(safe) if name != "Bootstrap" else (
                (vt[0] == 3 and vt < (3, 4, 1)) or (vt[0] == 4 and vt < (4, 3, 1)) or vt[0] < 3)
            if old:
                res.add(C_TECH, WARN, "%s %s قديم" % (name, v), note + " — " + where, "حدّث المكتبة إلى آخر إصدار.")
            else:
                res.add(C_TECH, PASS, "%s %s" % (name, v), where)
    return page


TECH_HEADERS = [
    ("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"), ("x-vercel-id", "Vercel"),
    ("x-nf-request-id", "Netlify"), ("x-github-request-id", "GitHub Pages"), ("x-served-by", "Fastly"),
    ("x-azure-ref", "Azure Front Door"), ("x-akamai-transformed", "Akamai"), ("x-sucuri-id", "Sucuri WAF"),
    ("x-shopify-stage", "Shopify"), ("x-wix-request-id", "Wix"), ("x-firebase-hosting", "Firebase"),
    ("fly-request-id", "Fly.io"), ("x-render-origin-server", "Render"),
]
TECH_BODY = [
    (r"/wp-content/|/wp-includes/", "WordPress"), (r"Joomla!|/media/jui/", "Joomla"),
    (r"Drupal\.settings|/sites/default/files/", "Drupal"), (r"cdn\.shopify\.com", "Shopify"),
    (r"static\.wixstatic\.com", "Wix"), (r"squarespace\.com", "Squarespace"), (r"__NEXT_DATA__|/_next/static/", "Next.js"),
    (r"__NUXT__|/_nuxt/", "Nuxt"), (r"ng-version=", "Angular"), (r"data-reactroot|react-dom", "React"),
    (r"Ghost \d|ghost-", "Ghost"), (r"/static/js/main\.[0-9a-f]+\.js", "Create React App"),
    (r"blogger\.com|blogspot\.com", "Blogger"), (r"Magento|/static/version\d+/", "Magento"),
]


def detect_tech(res, home, page):
    tech = []
    for h, name in TECH_HEADERS:
        if home.header(h):
            tech.append(name)
    server = home.header("Server")
    if server and server.lower() not in ("cloudflare",):
        tech.append("Server: " + server)
    pb = home.header("X-Powered-By")
    if pb:
        tech.append("Powered-By: " + pb)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', page, re.I)
    if gen:
        tech.append("Generator: " + gen.group(1))
    for pat, name in TECH_BODY:
        if re.search(pat, page, re.I) and name not in tech:
            tech.append(name)
    alt = home.header("Alt-Svc") or ""
    if "h3" in alt:
        tech.append("HTTP/3")
    res.add(C_TECH, INFO, "التقنيات المكتشفة", "، ".join(dict.fromkeys(tech)) if tech else "لم يُتعرّف على تقنيات محددة")
    return tech


def check_wordpress(res, ctx, origin, page, active=True):
    cat = C_WP
    gen = re.search(r'<meta[^>]+generator[^>]+WordPress\s*([\d.]+)', page, re.I)
    if gen:
        res.add(cat, WARN, "إصدار WordPress ظاهر في الصفحة", gen.group(1), "أخفِ meta generator.")
    if not active:
        res.add(cat, INFO, "فحوصات WordPress المتقدمة متوقفة (الوضع السلبي)", "لم تُطلب مسارات xmlrpc أو REST أو debug.log.")
        return
    try:
        r = fetch(ctx, origin + "/wp-json/wp/v2/users", max_body=200000)
        if r.status == 200 and r.text().lstrip().startswith("["):
            users = [u.get("slug", "?") for u in json.loads(r.text())][:10]
            res.add(cat, WARN, "واجهة REST تكشف أسماء المستخدمين", "، ".join(users),
                    "قيّد /wp-json/wp/v2/users لغير المسجّلين (إضافة أمان أو قاعدة WAF).")
        else:
            res.add(cat, PASS, "أسماء المستخدمين غير مكشوفة عبر REST")
    except Exception:  # noqa: BLE001
        pass
    try:
        r = fetch(ctx, origin + "/?author=1", max_body=1)
        loc = r.header("Location") or ""
        if "/author/" in loc:
            res.add(cat, WARN, "تعداد المستخدمين عبر ?author=", loc, "امنع تحويل ?author= إلى صفحة المؤلف.")
    except Exception:  # noqa: BLE001
        pass
    for path, test, st, title, fix in (
        ("/xmlrpc.php", lambda r: r.status == 405 or b"XML-RPC server accepts POST" in r.body, WARN,
         "xmlrpc.php مفعّل", "عطّله إن لم تستخدمه؛ يُستغل في تخمين كلمات المرور."),
        ("/wp-content/debug.log", lambda r: r.status == 200 and b"PHP " in r.body[:5000], FAIL,
         "سجل التصحيح debug.log مكشوف", "احذفه وعطّل WP_DEBUG_LOG في الإنتاج."),
        ("/readme.html", lambda r: r.status == 200 and b"WordPress" in r.body, INFO,
         "ملف readme.html موجود", "احذفه لأنه يكشف أن الموقع WordPress."),
        ("/wp-content/uploads/", lambda r: r.status == 200 and b"Index of" in r.body, WARN,
         "فهرسة مجلد uploads مفعّلة", "عطّل Directory Listing."),
        ("/wp-config.php.bak", lambda r: r.status == 200 and b"DB_PASSWORD" in r.body, FAIL,
         "نسخة احتياطية من wp-config مكشوفة", "احذفها فوراً وغيّر كلمة مرور قاعدة البيانات."),
    ):
        try:
            r = fetch(ctx, origin + path, max_body=65536)
            if test(r):
                res.add(cat, st, title, path, fix)
        except Exception:  # noqa: BLE001
            pass
    res.add(cat, INFO, "تذكير", "حدّث WordPress والإضافات والقوالب باستمرار، وفعّل المصادقة الثنائية للمدراء.")


# ═════════════════════════════ كوكيز، CORS، طرق ═════════════════════════════

def check_cookies(res, responses):
    seen = set()
    for r in responses:
        for c in r.header_all("Set-Cookie"):
            name = c.split("=", 1)[0].strip()
            if name in seen:
                continue
            seen.add(name)
            low = c.lower()
            missing = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in low]
            if "samesite=none" in low and "secure" not in low:
                missing.append("Secure (مطلوب مع SameSite=None)")
            if missing:
                res.add(C_COOKIE, WARN, "كوكي %s بدون %s" % (name, "، ".join(missing)), "",
                        "أضف الخصائص الناقصة (HttpOnly قد لا يناسب كوكيز يقرأها JavaScript).")
            else:
                res.add(C_COOKIE, PASS, "كوكي %s محمي" % name)
    if not seen:
        res.add(C_COOKIE, INFO, "لا توجد كوكيز في الصفحة الرئيسية")


def check_cors_methods(res, ctx, url, active=True):
    evil = "https://evil-%s.example" % "".join(random.choices(string.ascii_lowercase, k=6))
    try:
        r = fetch(ctx, url, extra_headers={"Origin": evil}, max_body=1)
        acao, acac = r.header("Access-Control-Allow-Origin"), (r.header("Access-Control-Allow-Credentials") or "").lower() == "true"
        if acao == evil:
            res.add(C_COOKIE, FAIL if acac else WARN, "CORS يعكس أي Origin" + (" مع Credentials" if acac else ""),
                    "Access-Control-Allow-Origin: " + acao, "اسمح فقط بقائمة نطاقات محددة.")
        elif acao == "null":
            res.add(C_COOKIE, WARN, "CORS يسمح بـ Origin: null", "", "لا تسمح بـ null.")
        elif acao == "*":
            res.add(C_COOKIE, INFO, "CORS مفتوح للجميع (*)", "مقبول لمحتوى عام بلا بيانات خاصة.")
        else:
            res.add(C_COOKIE, PASS, "CORS لا يسمح بمصادر غريبة")
    except Exception as e:  # noqa: BLE001
        res.add(C_COOKIE, INFO, "تعذّر فحص CORS", str(e))
    if not active:
        return
    try:
        r = fetch(ctx, url, method="TRACE")
        if r.status == 200:
            res.add(C_COOKIE, WARN, "طريقة TRACE مفعّلة", "", "عطّل TRACE في الخادم.")
        else:
            res.add(C_COOKIE, PASS, "طريقة TRACE معطّلة", "الاستجابة %d" % r.status)
    except Exception:  # noqa: BLE001
        pass


# ═════════════════════════════ ملفات مكشوفة و security.txt ═════════════════════════════

def not_html(b):
    return b"<html" not in b[:600].lower() and b"<!doctype" not in b[:600].lower()


SENSITIVE = [
    ("/.git/HEAD", FAIL, lambda b: b.startswith(b"ref:") or re.match(rb"^[0-9a-f]{40}\s*$", b) is not None),
    ("/.git/config", FAIL, lambda b: b"[core]" in b),
    ("/.svn/entries", FAIL, lambda b: re.match(rb"^\d+\s", b) is not None or b"svn:" in b),
    ("/.hg/hgrc", FAIL, lambda b: b"[paths]" in b),
    ("/.env", FAIL, lambda b: re.search(rb"^[A-Z_][A-Z0-9_]*=", b, re.M) is not None and not_html(b)),
    ("/.env.local", FAIL, lambda b: re.search(rb"^[A-Z_][A-Z0-9_]*=", b, re.M) is not None and not_html(b)),
    ("/.env.production", FAIL, lambda b: re.search(rb"^[A-Z_][A-Z0-9_]*=", b, re.M) is not None and not_html(b)),
    ("/.aws/credentials", FAIL, lambda b: b"aws_access_key_id" in b.lower()),
    ("/.npmrc", FAIL, lambda b: b"_authToken" in b),
    ("/.htpasswd", FAIL, lambda b: re.search(rb"^[\w.-]+:\$?[\w./$]{10,}", b, re.M) is not None and not_html(b)),
    ("/.DS_Store", WARN, lambda b: b[4:8] == b"Bud1"),
    ("/.vscode/sftp.json", FAIL, lambda b: b'"host"' in b and b'"password"' in b),
    ("/config.php.bak", FAIL, lambda b: b"<?php" in b),
    ("/wp-config.php~", FAIL, lambda b: b"DB_PASSWORD" in b),
    ("/web.config", WARN, lambda b: b"<configuration" in b),
    ("/backup.zip", FAIL, lambda b: b.startswith(b"PK\x03\x04")),
    ("/backup.tar.gz", FAIL, lambda b: b.startswith(b"\x1f\x8b")),
    ("/site.zip", FAIL, lambda b: b.startswith(b"PK\x03\x04")),
    ("/dump.sql", FAIL, lambda b: re.search(rb"(CREATE TABLE|INSERT INTO|-- MySQL dump)", b[:20000], re.I) is not None),
    ("/database.sql", FAIL, lambda b: re.search(rb"(CREATE TABLE|INSERT INTO|-- MySQL dump)", b[:20000], re.I) is not None),
    ("/db.sqlite", FAIL, lambda b: b.startswith(b"SQLite format 3")),
    ("/composer.json", INFO, lambda b: b.lstrip().startswith(b"{") and b'"require"' in b),
    ("/package.json", INFO, lambda b: b.lstrip().startswith(b"{") and b'"dependencies"' in b),
    ("/server-status", WARN, lambda b: b"Apache Server Status" in b),
    ("/server-info", WARN, lambda b: b"Apache Server Information" in b),
    ("/phpinfo.php", FAIL, lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("/info.php", FAIL, lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("/actuator/env", FAIL, lambda b: b'"propertySources"' in b),
    ("/actuator/heapdump", FAIL, lambda b: b.startswith(b"JAVA PROFILE")),
    ("/elmah.axd", FAIL, lambda b: b"Error Log for" in b),
]
LISTING_DIRS = ["/uploads/", "/images/", "/files/", "/backup/", "/backups/", "/assets/", "/static/", "/tmp/", "/logs/"]
ADMIN_PATHS = [("/phpmyadmin/", b"phpMyAdmin"), ("/adminer.php", b"Adminer"), ("/pma/", b"phpMyAdmin")]


def check_exposed(res, ctx, origin):
    cat = C_EXPOSE

    def one(item):
        path, st, test = item
        try:
            r = fetch(ctx, origin + path, max_body=65536)
            return (path, st) if (r.status == 200 and r.body and test(r.body)) else None
        except Exception:  # noqa: BLE001
            return None

    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        hits = [h for h in ex.map(one, SENSITIVE) if h]
    for path, st in hits:
        res.add(cat, st, ("ملف حساس مكشوف: " if st == FAIL else "ملف مكشوف: ") + path, "",
                "احذف الملف من مجلد الويب أو امنع الوصول إليه.")
    if not any(st == FAIL for _, st in hits):
        res.add(cat, PASS, "لا ملفات حساسة مكشوفة", "تم فحص %d مساراً شائعاً" % len(SENSITIVE))

    listing = []
    for d in LISTING_DIRS:
        try:
            r = fetch(ctx, origin + d, max_body=20000)
            if r.status == 200 and re.search(rb"<title>\s*Index of /|Directory listing for /|\[To Parent Directory\]", r.body, re.I):
                listing.append(d)
        except Exception:  # noqa: BLE001
            pass
    if listing:
        res.add(cat, WARN, "فهرسة المجلدات مفعّلة", " ".join(listing), "عطّل Directory Listing (Options -Indexes / autoindex off).")
    else:
        res.add(cat, PASS, "لا فهرسة مجلدات في المسارات الشائعة")

    for path, sig in ADMIN_PATHS:
        try:
            r = fetch(ctx, origin + path, max_body=20000)
            if r.status == 200 and sig in r.body:
                res.add(cat, WARN, "لوحة إدارة قاعدة بيانات مكشوفة للعامة", path, "قيّد الوصول بعنوان IP أو VPN.")
        except Exception:  # noqa: BLE001
            pass


def check_security_txt(res, ctx, origin):
    cat = C_SECTXT
    body, status = "", None
    for p in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = fetch(ctx, origin + p)
            status = r.status
            if r.status == 200 and "contact:" in r.text().lower() and not_html(r.body):
                body = r.text()
                break
        except Exception:  # noqa: BLE001
            continue
    if not body:
        res.add(cat, WARN, "security.txt غير موجود", "/.well-known/security.txt ← %s" % status,
                "أنشئ ملفاً حسب RFC 9116 فيه Contact و Expires.")
        return
    m = re.search(r"^\s*Expires:\s*(\S+)", body, re.I | re.M)
    if not m:
        res.add(cat, WARN, "security.txt بدون Expires", "", "حقل Expires مطلوب.")
        return
    try:
        exp = dt.datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=dt.timezone.utc)
        days = (exp - dt.datetime.now(dt.timezone.utc)).days
    except ValueError:
        res.add(cat, WARN, "تاريخ Expires غير صالح", m.group(1))
        return
    if days < 0:
        res.add(cat, FAIL, "security.txt منتهي الصلاحية", m.group(1), "حدّث Expires.")
    elif days < 30:
        res.add(cat, WARN, "security.txt ينتهي خلال %d يوماً" % days, m.group(1), "حدّث Expires.")
    else:
        res.add(cat, PASS, "security.txt موجود وصالح", "ينتهي %s" % exp.date())


# ═════════════════════════════ DNS والبريد ═════════════════════════════

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "dkim", "mail",
                  "smtp", "zoho", "mxvault", "mandrill", "cm", "pm", "sendgrid", "mailjet", "amazonses",
                  "cf2024-1", "protonmail", "protonmail2", "fm1", "fm2", "everlytickey1", "sig1", "hs1"]


def spf_lookups(record, timeout, depth=0, seen=None):
    """يحسب عدد استعلامات DNS في SPF بشكل متكرر (الحد الأقصى 10)."""
    seen = seen or set()
    n = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "redirect=")):
            n += 1
            tgt = t.split(":", 1)[-1] if t.startswith("include:") else t.split("=", 1)[1]
            if depth < 5 and tgt not in seen:
                seen.add(tgt)
                sub = [txt_join(a) for a in doh(tgt, "TXT", timeout)["answers"]]
                sub = [s for s in sub if s.lower().startswith("v=spf1")]
                if sub:
                    n += spf_lookups(sub[0], timeout, depth + 1, seen)
        elif t == "a" or t.startswith(("a:", "a/", "mx", "ptr", "exists:")):
            n += 1
    return n


def check_dns(res, domain, host, timeout):
    cat = C_DNS
    probe = doh(domain, "TXT", timeout)
    if not probe["ok"]:
        res.add(cat, INFO, "تعذّر الاستعلام عن DNS", probe.get("error", ""))
        return
    txt = [txt_join(a) for a in probe["answers"]]
    mx = doh(domain, "MX", timeout)["answers"]
    null_mx = len(mx) == 1 and mx[0].split()[-1] in (".", "")
    has_mail = bool(mx) and not null_mx

    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        res.add(cat, FAIL if has_mail else WARN, "لا يوجد سجل SPF", "",
                "أضف TXT: v=spf1 … -all (أو v=spf1 -all إن كان النطاق لا يرسل بريداً).")
    elif len(spf) > 1:
        res.add(cat, FAIL, "أكثر من سجل SPF", " | ".join(spf), "يجب أن يكون سجل SPF واحداً فقط.")
    else:
        s = spf[0]
        tail = s.split()[-1].lower()
        if tail == "-all":
            res.add(cat, PASS, "SPF صارم (-all)", s)
        elif tail == "~all":
            res.add(cat, WARN, "SPF بوضع softfail (~all)", s, "بعد مراجعة تقارير DMARC غيّره إلى -all.")
        elif tail in ("+all", "all"):
            res.add(cat, FAIL, "SPF يسمح لأي خادم (+all)", s, "غيّره إلى -all فوراً.")
        elif tail == "?all":
            res.add(cat, WARN, "SPF محايد (?all)", s, "غيّره إلى -all.")
        else:
            res.add(cat, INFO, "SPF", s)
        n = spf_lookups(s, timeout)
        if n > 10:
            res.add(cat, FAIL, "SPF يتجاوز حد 10 استعلامات DNS", "%d استعلام" % n, "قلّل include أو استخدم SPF flattening.")

    dm = [txt_join(a) for a in doh("_dmarc." + domain, "TXT", timeout)["answers"]]
    dm = [d for d in dm if d.lower().startswith("v=dmarc1")]
    if not dm:
        res.add(cat, FAIL if has_mail else WARN, "لا يوجد سجل DMARC", "",
                "أضف _dmarc TXT: v=DMARC1; p=none; rua=mailto:… ثم ارفع السياسة تدريجياً.")
    else:
        d = dm[0]
        pol = (re.search(r"\bp\s*=\s*(\w+)", d) or [None, "?"])[1].lower()
        pct = re.search(r"\bpct\s*=\s*(\d+)", d)
        if pol == "reject":
            res.add(cat, PASS, "DMARC بسياسة reject", d)
        elif pol == "quarantine":
            res.add(cat, PASS, "DMARC بسياسة quarantine", d, "يمكن رفعها إلى reject.")
        else:
            res.add(cat, WARN, "DMARC بوضع المراقبة (p=%s)" % pol, d, "بعد مراجعة التقارير ارفعها إلى quarantine ثم reject.")
        if pct and int(pct.group(1)) < 100:
            res.add(cat, INFO, "DMARC يطبَّق على %s%% فقط من الرسائل" % pct.group(1))
        if "rua=" not in d.lower():
            res.add(cat, WARN, "DMARC بدون عنوان تقارير rua", "", "أضف rua=mailto:… لتصلك التقارير.")

    def dk(sel):
        ans = doh("%s._domainkey.%s" % (sel, domain), "TXT", timeout)
        return sel if any("p=" in txt_join(a) for a in ans["answers"]) or any(
            a.get("type") == 5 for a in ans.get("all", [])) else None
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        found = [s for s in ex.map(dk, DKIM_SELECTORS) if s]
    if found:
        res.add(cat, PASS, "DKIM موجود", "المحدِّدات: " + "، ".join(found))
    elif has_mail:
        res.add(cat, INFO, "لم يُعثر على DKIM بالمحدِّدات الشائعة", "قد يستخدم محدِّداً آخر — تحقق من رأس رسالة مرسلة.")

    if has_mail:
        sts = [txt_join(a) for a in doh("_mta-sts." + domain, "TXT", timeout)["answers"]]
        rpt = [txt_join(a) for a in doh("_smtp._tls." + domain, "TXT", timeout)["answers"]]
        res.add(cat, PASS if sts else INFO, "MTA-STS " + ("مفعّل" if sts else "غير مفعّل"), sts[0] if sts else "",
                "" if sts else "اختياري: يفرض TLS على البريد الوارد.")
        res.add(cat, PASS if rpt else INFO, "TLS-RPT " + ("مفعّل" if rpt else "غير مفعّل"), rpt[0] if rpt else "")
        res.add(cat, INFO, "خوادم البريد (MX)", " | ".join(mx))
    elif not mx:
        res.add(cat, INFO, "النطاق لا يستقبل بريداً (لا MX)", "", "إن لم يرسل بريداً: v=spf1 -all و DMARC p=reject.")

    caa = doh(domain, "CAA", timeout)["answers"]
    if caa:
        res.add(cat, PASS, "سجلات CAA موجودة (%d)" % len(caa), " | ".join(caa))
    else:
        res.add(cat, WARN, "لا توجد سجلات CAA", "", "حدّد جهات إصدار الشهادات المسموح لها.")

    ds = doh(domain, "DS", timeout)["answers"]
    ad = doh(host, "A", timeout, dnssec=True)["ad"]
    if ds and ad:
        res.add(cat, PASS, "DNSSEC مفعّل ومُتحقَّق منه")
    elif ds:
        res.add(cat, WARN, "سجل DS موجود لكن التحقق لم ينجح", "", "راجع إعدادات DNSSEC أو انتظر اكتمال التفعيل.")
    else:
        res.add(cat, WARN, "DNSSEC غير مفعّل", "", "فعّله لدى مزوّد DNS وأضف DS لدى المسجّل.")

    ns = doh(domain, "NS", timeout)["answers"]
    if ns:
        res.add(cat, INFO, "خوادم الأسماء (NS)", " | ".join(n.rstrip(".") for n in ns))
        if len(ns) < 2:
            res.add(cat, WARN, "خادم أسماء واحد فقط", "", "استخدم خادمين على الأقل.")


# ═════════════════════════════ المنافذ ═════════════════════════════

PORTS = {
    21: ("FTP", WARN), 22: ("SSH", INFO), 23: ("Telnet", FAIL), 25: ("SMTP", INFO), 110: ("POP3", INFO),
    135: ("MS-RPC", FAIL), 139: ("NetBIOS", FAIL), 143: ("IMAP", INFO), 445: ("SMB", FAIL),
    1433: ("MS SQL", FAIL), 1521: ("Oracle DB", FAIL), 2049: ("NFS", FAIL), 2375: ("Docker API (بدون TLS)", FAIL),
    2376: ("Docker API", WARN), 3306: ("MySQL", FAIL), 3389: ("RDP", FAIL), 5432: ("PostgreSQL", FAIL),
    5900: ("VNC", FAIL), 5984: ("CouchDB", FAIL), 6379: ("Redis", FAIL), 8080: ("HTTP بديل", INFO),
    8443: ("HTTPS بديل", INFO), 9000: ("PHP-FPM/Portainer", WARN), 9200: ("Elasticsearch", FAIL),
    10250: ("Kubelet", FAIL), 11211: ("Memcached", FAIL), 27017: ("MongoDB", FAIL),
}


def check_ports(res, host, behind_cdn):
    cat = C_PORTS
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return

    def probe(p):
        try:
            with socket.create_connection((ip, p), timeout=2):
                return p
        except OSError:
            return None
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        open_ports = sorted(p for p in ex.map(probe, PORTS) if p)
    if behind_cdn:
        res.add(cat, INFO, "الموقع خلف CDN", "المنافذ المفحوصة هي منافذ الـ CDN (%s) لا الخادم الأصلي." % ip,
                "تأكد أن الخادم الأصلي لا يقبل اتصالات إلا من نطاقات الـ CDN.")
    if not open_ports:
        res.add(cat, PASS, "لا منافذ خطرة مفتوحة", "تم فحص %d منفذاً على %s" % (len(PORTS), ip))
    for p in open_ports:
        name, st = PORTS[p]
        if behind_cdn and p in (8080, 8443):
            st = INFO
        res.add(cat, st, "المنفذ %d مفتوح (%s)" % (p, name), ip,
                "" if st == INFO else "أغلقه في الجدار الناري أو قيّده بعناوين IP موثوقة/VPN.")


# ═════════════════════════════ النطاقات الفرعية ═════════════════════════════

TAKEOVER_SIGS = ("github.io", "herokuapp.com", "herokudns.com", "azurewebsites.net", "cloudapp.net", "trafficmanager.net",
                 "blob.core.windows.net", "s3.amazonaws.com", "s3-website", "cloudfront.net", "elasticbeanstalk.com",
                 "netlify.app", "vercel.app", "pages.dev", "surge.sh", "bitbucket.io", "ghost.io", "myshopify.com",
                 "wpengine.com", "pantheonsite.io", "zendesk.com", "readthedocs.io", "fly.dev", "onrender.com")


def check_subdomains(res, domain, timeout, limit=80):
    cat = C_SUBS
    try:
        req = urllib.request.Request("https://crt.sh/?q=%25." + domain + "&output=json", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=max(timeout, 25)) as r:
            data = json.loads(r.read().decode() or "[]")
    except Exception as e:  # noqa: BLE001
        res.add(cat, INFO, "تعذّر جلب النطاقات الفرعية من سجلات الشهادات (crt.sh)", str(e)[:120])
        return
    names = set()
    for row in data:
        for n in row.get("name_value", "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith("." + domain):
                names.add(n)
    names = sorted(names)
    res.add(cat, INFO, "نطاقات فرعية في سجلات الشهادات: %d" % len(names), "، ".join(names[:25]) + (" …" if len(names) > 25 else ""))

    def look(n):
        a = doh(n, "A", timeout)
        cname = [x.get("data", "").rstrip(".") for x in a.get("all", []) if x.get("type") == 5]
        return n, a.get("status"), bool(a["answers"]), cname
    live, dead = [], []
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        for n, status, has_a, cname in ex.map(look, names[:limit]):
            if cname and not has_a and any(s in cname[-1] for s in TAKEOVER_SIGS):
                res.add(cat, FAIL, "خطر استيلاء على نطاق فرعي: " + n, "CNAME → %s لا يُحلّ" % cname[-1],
                        "احذف سجل CNAME أو أعد إنشاء المورد على الخدمة.")
            elif cname and not has_a:
                res.add(cat, WARN, "CNAME معلّق: " + n, "→ " + cname[-1], "احذف السجل إن لم يعد مستخدماً.")
            elif has_a:
                live.append(n)
            else:
                dead.append(n)
    if live:
        res.add(cat, INFO, "نطاقات فرعية فعّالة: %d" % len(live), "، ".join(live[:30]),
                "افحص كل واحد منها بالأداة نفسها.")
    if len(names) > limit:
        res.add(cat, INFO, "تم فحص أول %d نطاق فرعي فقط" % limit)


# ═════════════════════════════ العنوان والشبكة ═════════════════════════════

# شبكات معروفة لمزوّدي CDN/WAF: ASN → (الاسم، هل وجود الموقع عليها دليل قوي على WAF)
CDN_ASNS = {
    13335: ("Cloudflare", True), 209242: ("Cloudflare", True), 20940: ("Akamai", True), 16625: ("Akamai", True),
    19551: ("Imperva Incapsula", True), 30148: ("Sucuri", True), 57724: ("DDoS-Guard", True),
    54113: ("Fastly", False), 16509: ("Amazon AWS / CloudFront", False), 14618: ("Amazon AWS", False),
    8075: ("Microsoft Azure", False), 15169: ("Google", False), 396982: ("Google Cloud", False),
    60068: ("CDN77", False), 12989: ("StackPath", False), 22822: ("Edgio / Limelight", False),
}


def ip_info(ip, timeout):
    """ASN والمنظمة والدولة والاسم العكسي لعنوان IP عبر Team Cymru (DNS)."""
    info = {"ip": ip, "version": 6 if ":" in ip else 4, "asn": None, "org": "", "cc": "", "prefix": "", "ptr": ""}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return info
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        info["org"] = "عنوان خاص/محلي"
        return info
    rev = addr.reverse_pointer
    if addr.version == 4:
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        q = rev.replace(".ip6.arpa", "") + ".origin6.asn.cymru.com"
    ans = [txt_join(a) for a in doh(q, "TXT", timeout)["answers"]]
    if ans:
        parts = [p.strip() for p in ans[0].split("|")]
        try:
            info["asn"] = int(parts[0].split()[0])
        except (ValueError, IndexError):
            pass
        info["prefix"] = parts[1] if len(parts) > 1 else ""
        info["cc"] = parts[2] if len(parts) > 2 else ""
    if info["asn"]:
        nm = [txt_join(a) for a in doh("AS%d.asn.cymru.com" % info["asn"], "TXT", timeout)["answers"]]
        if nm:
            info["org"] = nm[0].split("|")[-1].strip()
    ptr = doh(rev, "PTR", timeout)["answers"]
    if ptr:
        info["ptr"] = ptr[0].rstrip(".")
    return info


def resolve_ips(host):
    v4, v6 = [], []
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
            ip = sa[0]
            (v6 if fam == socket.AF_INET6 else v4).append(ip)
    except OSError:
        pass
    return list(dict.fromkeys(v4)), list(dict.fromkeys(v6))


def check_network(res, host, timeout):
    cat = C_NET
    v4, v6 = resolve_ips(host)
    if not v4 and not v6:
        res.add(cat, WARN, "تعذّر معرفة عنوان IP", host)
        return []
    ips = (v4[:4] + v6[:2])
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        infos = list(ex.map(lambda ip: ip_info(ip, timeout), ips))
    res.ips = infos
    for i in infos:
        parts = []
        if i["asn"]:
            parts.append("AS%d %s" % (i["asn"], i["org"]))
        elif i["org"]:
            parts.append(i["org"])
        if i["cc"]:
            parts.append("الدولة: " + i["cc"])
        if i["prefix"]:
            parts.append("الشبكة: " + i["prefix"])
        if i["ptr"]:
            parts.append("PTR: " + i["ptr"])
        res.add(cat, INFO, "IPv%d: %s" % (i["version"], i["ip"]), " — ".join(parts))
    if len(v4) > 4:
        res.add(cat, INFO, "عناوين IPv4 إضافية: %d" % (len(v4) - 4), "، ".join(v4[4:10]))
    if not v6:
        res.add(cat, INFO, "الموقع لا يدعم IPv6", "لا يوجد سجل AAAA")
    for i in infos:
        if i["asn"] in CDN_ASNS:
            res.add(cat, INFO, "الموقع مستضاف خلف " + CDN_ASNS[i["asn"]][0], "العنوان الظاهر هو عنوان المزوّد وليس الخادم الأصلي.")
            break
    return infos


# ═════════════════════════════ جدار حماية تطبيقات الويب (WAF) ═════════════════════════════

# كل بصمة: hdr = [(هيدر, نمط القيمة أو None)]، cookie = أنماط أسماء الكوكيز، body = أنماط صفحة الحظر.
# weak_hdr / weak_cookie = مؤشرات على CDN أو موازن أحمال لا تعني بالضرورة وجود WAF مفعّل.
WAFS = [
    {"name": "Cloudflare", "kind": "سحابي (CDN + WAF)",
     "hdr": [("cf-ray", None), ("server", r"^cloudflare")], "cookie": [r"^__cf_bm$", r"^cf_clearance$", r"^__cflb$"],
     "body": [r"Attention Required! \| Cloudflare", r"cf-error-details", r"Cloudflare Ray ID", r"Sorry, you have been blocked"]},
    {"name": "Akamai (Kona / App & API Protector)", "kind": "سحابي",
     "hdr": [("server", r"AkamaiGHost|AkamaiNetStorage"), ("akamai-grn", None)], "cookie": [r"^ak_bmsc$", r"^bm_sz$", r"^_abck$"],
     "weak_hdr": [("x-akamai-transformed", None)],
     "body": [r"Reference&#32;&#35;\d+\.[0-9a-f]+", r"Reference #\d+\.[0-9a-f]+\.\d+\.[0-9a-f]+"]},
    {"name": "Imperva Incapsula", "kind": "سحابي",
     "hdr": [("x-iinfo", None), ("x-cdn", r"Incapsula|Imperva")], "cookie": [r"^incap_ses_", r"^visid_incap_", r"^nlbi_"],
     "body": [r"Incapsula incident ID", r"_Incapsula_Resource", r"Powered By Incapsula"]},
    {"name": "AWS WAF", "kind": "سحابي (Amazon)",
     "hdr": [("x-amzn-waf-action", None)], "cookie": [r"^aws-waf-token$"],
     "weak_hdr": [("x-amz-cf-id", None), ("x-amz-cf-pop", None)],
     "body": [r"Request blocked\.[\s\S]{0,400}cloudfront", r"Generated by cloudfront \(CloudFront\)", r"AWS WAF"]},
    {"name": "F5 BIG-IP ASM / Advanced WAF", "kind": "جهاز داخلي (On-premise)",
     "hdr": [("x-wa-info", None), ("server", r"BigIP|BIG-IP")], "cookie": [r"^TS[0-9a-f]{6,}$", r"^TS[0-9a-f]{8}_\d+$"],
     "weak_cookie": [r"^BIGipServer", r"^F5_", r"^MRHSession$", r"^LastMRH_Session$"],
     "body": [r"The requested URL was rejected\. Please consult with your administrator", r"Your support ID is:?\s*\d+"]},
    {"name": "Fortinet FortiWeb", "kind": "جهاز داخلي",
     "hdr": [], "cookie": [r"^FORTIWAFSID$"],
     "body": [r"FortiWeb", r"\.fgd_icon", r"Server Unavailable![\s\S]{0,300}FortiGate"]},
    {"name": "Fortinet FortiGate (حظر محتوى)", "kind": "جدار ناري للشبكة",
     "hdr": [], "cookie": [], "body": [r"FortiGuard Web Filtering", r"Web Page Blocked![\s\S]{0,400}Fortinet"]},
    {"name": "Barracuda WAF", "kind": "جهاز داخلي",
     "hdr": [], "cookie": [r"^barra_counter_session$", r"^BNI__BARRACUDA_LB_COOKIE$", r"^BNI_persistence$"],
     "body": [r"Barracuda Networks", r"barracuda_web_application_firewall"]},
    {"name": "Citrix NetScaler / ADC", "kind": "جهاز داخلي",
     "hdr": [("via", r"NS-CACHE"), ("cneonction", None), ("nncoection", None)], "cookie": [r"^ns_af", r"^citrix_ns_id"],
     "weak_cookie": [r"^NSC_"],
     "body": [r"NS Transaction ID", r"AppFW Session ID", r"Violation Category:\s*APPFW"]},
    {"name": "Sucuri CloudProxy", "kind": "سحابي",
     "hdr": [("x-sucuri-id", None), ("x-sucuri-cache", None), ("server", r"Sucuri|Cloudproxy")], "cookie": [],
     "body": [r"Sucuri WebSite Firewall", r"cloudproxy@sucuri\.net"]},
    {"name": "ModSecurity", "kind": "وحدة على الخادم (Apache / Nginx / IIS)",
     "hdr": [("server", r"mod_security|NOYB")], "cookie": [],
     "body": [r"This error was generated by Mod_Security", r"ModSecurity Action", r"Mod_Security"]},
    {"name": "Microsoft Azure WAF (Front Door / App Gateway)", "kind": "سحابي (Microsoft)",
     "hdr": [], "cookie": [], "weak_hdr": [("x-azure-ref", None), ("x-msedge-ref", None)],
     "body": [r"Azure Web Application Firewall", r"Microsoft-Azure-Application-Gateway"]},
    {"name": "Fastly Next-Gen WAF (Signal Sciences)", "kind": "سحابي",
     "hdr": [("x-sigsci-requestid", None), ("x-sigsci-agentresponse", None)], "cookie": [],
     "weak_hdr": [("x-fastly-request-id", None), ("fastly-debug-digest", None)], "body": []},
    {"name": "Radware AppWall / Cloud WAF", "kind": "جهاز داخلي أو سحابي",
     "hdr": [("x-sl-compstate", None)], "cookie": [],
     "body": [r"Unauthorized Activity Has Been Detected", r"radwarealerts", r"Radware"]},
    {"name": "Wordfence", "kind": "إضافة WordPress",
     "hdr": [], "cookie": [r"^wfwaf-authcookie"],
     "body": [r"Generated by Wordfence", r"wordfence\.com/help/firewall", r"Your access to this site has been limited"]},
    {"name": "DDoS-Guard", "kind": "سحابي",
     "hdr": [("server", r"ddos-guard")], "cookie": [r"^__ddg"], "body": [r"DDoS-Guard"]},
    {"name": "Palo Alto (حظر جدار ناري)", "kind": "جدار ناري للشبكة",
     "hdr": [], "cookie": [], "body": [r"Palo Alto Next Generation Security Platform", r"Web Page Blocked[\s\S]{0,400}PAN-OS"]},
    {"name": "Wallarm", "kind": "سحابي أو داخلي",
     "hdr": [("server", r"nginx-wallarm")], "cookie": [], "body": [r"wallarm"]},
    {"name": "Varnish / Nginx (حظر عام)", "kind": "", "hdr": [], "cookie": [], "body": []},
]
WAFS = [w for w in WAFS if w["hdr"] or w["cookie"] or w["body"] or w.get("weak_hdr") or w.get("weak_cookie")]

BLOCK_WORDS = re.compile(r"(request (was )?(blocked|rejected|denied)|access denied|has been blocked|security polic(y|ies)|"
                         r"support id|incident id|web application firewall|not acceptable|forbidden by|violat)", re.I)


def cookie_names(resp):
    out = []
    for c in resp.header_all("Set-Cookie"):
        out.append(c.split("=", 1)[0].strip())
    return out


def waf_fingerprint(resp):
    """يعيد {اسم: {"kind":..,"strong":[أدلة],"weak":[أدلة]}} من استجابة واحدة."""
    found = {}
    if resp is None:
        return found
    hdrs = {k.lower(): v for k, v in resp.headers}
    cookies = cookie_names(resp)
    body = resp.body[:60000].decode("utf-8", "replace") if resp.body else ""
    for w in WAFS:
        strong, weak = [], []
        for h, pat in w.get("hdr", []):
            if h in hdrs and (pat is None or re.search(pat, hdrs[h], re.I)):
                strong.append("هيدر %s" % h + (": " + hdrs[h][:40] if pat else ""))
        for h, pat in w.get("weak_hdr", []):
            if h in hdrs and (pat is None or re.search(pat, hdrs[h], re.I)):
                weak.append("هيدر %s" % h)
        for pat in w.get("cookie", []):
            for c in cookies:
                if re.search(pat, c, re.I):
                    strong.append("كوكي " + c)
        for pat in w.get("weak_cookie", []):
            for c in cookies:
                if re.search(pat, c, re.I):
                    weak.append("كوكي " + c)
        for pat in w.get("body", []):
            if body and re.search(pat, body, re.I):
                strong.append("نص صفحة الحظر")
                break
        if strong or weak:
            found[w["name"]] = {"kind": w["kind"], "strong": list(dict.fromkeys(strong)), "weak": list(dict.fromkeys(weak))}
    return found


def merge_fp(a, b):
    for k, v in b.items():
        if k not in a:
            a[k] = {"kind": v["kind"], "strong": [], "weak": []}
        a[k]["strong"] = list(dict.fromkeys(a[k]["strong"] + v["strong"]))
        a[k]["weak"] = list(dict.fromkeys(a[k]["weak"] + v["weak"]))
    return a


WAF_TESTS = [
    ("XSS", "<script>alert(document.domain)</script>"),
    ("SQL Injection", "1' OR '1'='1' UNION SELECT NULL--"),
    ("Path Traversal", "../../../../../../etc/passwd"),
    ("Command Injection", ";cat /etc/passwd|id"),
]


def is_blocked(resp, base):
    """هل تبدو الاستجابة حظراً مقارنة بالطلب العادي؟"""
    if resp is None:
        return True, "قُطع الاتصال"
    if resp.status != base.status and resp.status in (400, 401, 403, 405, 406, 409, 418, 419, 429, 444, 451, 456, 493, 500, 501, 502, 503, 999):
        return True, "%d" % resp.status
    loc = resp.header("Location") or ""
    if resp.status in (301, 302, 303, 307) and re.search(r"block|denied|captcha|challenge|error", loc, re.I) and not (base.header("Location") or ""):
        return True, "تحويل إلى " + loc[:60]
    text = resp.body[:30000].decode("utf-8", "replace") if resp.body else ""
    btext = base.body[:30000].decode("utf-8", "replace") if base.body else ""
    if BLOCK_WORDS.search(text) and not BLOCK_WORDS.search(btext):
        return True, "%d + صفحة حظر" % resp.status
    if waf_fingerprint(resp) and any(v["strong"] and "نص صفحة الحظر" in v["strong"] for v in waf_fingerprint(resp).values()):
        return True, "%d + صفحة حظر" % resp.status
    return False, "%d" % resp.status


def check_waf(res, ctx, origin, home, infos, domain, timeout, active):
    cat = C_WAF
    fp = waf_fingerprint(home)

    for i in infos or []:
        if i.get("asn") in CDN_ASNS:
            name, strong = CDN_ASNS[i["asn"]]
            key = next((k for k in [w["name"] for w in WAFS] if k.lower().startswith(name.split()[0].lower())), name)
            merge_fp(fp, {key: {"kind": next((w["kind"] for w in WAFS if w["name"] == key), "مزوّد شبكة"),
                                "strong": ["عنوان IP ضمن شبكة AS%d" % i["asn"]] if strong else [],
                                "weak": [] if strong else ["عنوان IP ضمن شبكة AS%d" % i["asn"]]}})

    # اختبار الحجب
    results, blocked_n = [], 0
    if active:
        tag = "".join(random.choices(string.ascii_lowercase, k=8))
        try:
            base = fetch(ctx, "%s/?q=%s" % (origin, tag), max_body=60000)
        except Exception as e:  # noqa: BLE001
            base = None
            res.add(cat, INFO, "تعذّر إرسال طلب المقارنة", str(e)[:120])
        if base is not None:
            for name, payload in WAF_TESTS:
                url = "%s/?q=%s" % (origin, urllib.parse.quote(payload, safe=""))
                try:
                    r = fetch(ctx, url, max_body=60000)
                except (ConnectionResetError, ConnectionAbortedError, http.client.RemoteDisconnected):
                    r = None
                except Exception:  # noqa: BLE001
                    continue
                blk, why = is_blocked(r, base)
                if r is not None:
                    merge_fp(fp, waf_fingerprint(r))
                results.append((name, blk, why))
                blocked_n += blk
            try:
                r = fetch(ctx, origin + "/", extra_headers={"User-Agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"}, max_body=60000)
                blk, why = is_blocked(r, base)
                merge_fp(fp, waf_fingerprint(r))
            except (ConnectionResetError, ConnectionAbortedError, http.client.RemoteDisconnected):
                blk, why = True, "قُطع الاتصال"
            except Exception:  # noqa: BLE001
                blk, why = None, ""
            if blk is not None:
                results.append(("أداة فحص (User-Agent: sqlmap)", blk, why))

    strong = {k: v for k, v in fp.items() if v["strong"]}
    weak = {k: v for k, v in fp.items() if not v["strong"] and v["weak"]}
    for k, v in strong.items():
        res.add(cat, PASS, "WAF مكتشف: " + k, ("النوع: %s — " % v["kind"] if v["kind"] else "") + "الأدلة: " + "، ".join(v["strong"] + v["weak"]))
    for k, v in weak.items():
        res.add(cat, INFO, "مؤشرات على " + k, "الأدلة: " + "، ".join(v["weak"]) + " — قد يكون CDN أو موازن أحمال بدون WAF مفعّل.")
    if len(strong) > 1:
        res.add(cat, INFO, "أكثر من طبقة حماية", "مثلاً WAF سحابي أمام جهاز داخلي — هذا شائع ومفيد.")

    if active and results:
        total = len([r for r in results if r[0] in dict(WAF_TESTS)])
        detail = " | ".join("%s: %s (%s)" % (n, "محجوب" if b else "مرّ", w) for n, b, w in results)
        if total and blocked_n == total:
            res.add(cat, PASS, "الـ WAF يحجب كل اختبارات الهجوم (%d/%d)" % (blocked_n, total), detail)
        elif blocked_n:
            res.add(cat, WARN, "الـ WAF يحجب بعض الهجمات فقط (%d/%d)" % (blocked_n, total), detail,
                    "راجع القواعد المفعّلة (OWASP Core Rule Set) وتأكد أن كل الفئات بوضع الحظر.")
        elif strong:
            res.add(cat, WARN, "WAF موجود لكنه لم يحجب أي اختبار (0/%d)" % total, detail,
                    "قد يكون بوضع المراقبة (Detection/Log only) أو القواعد غير مفعّلة — فعّل وضع الحظر.")
        else:
            res.add(cat, WARN, "لا يوجد WAF ظاهر ولم يُحجب أي اختبار (0/%d)" % total, detail,
                    "ضع الموقع خلف WAF (سحابي مثل Cloudflare أو جهاز مثل FortiWeb/F5) أو فعّل ModSecurity مع OWASP CRS.")
        ua = [r for r in results if r[0].startswith("أداة")]
        if ua:
            res.add(cat, PASS if ua[0][1] else INFO, "حجب أدوات الفحص المعروفة: " + ("نعم" if ua[0][1] else "لا"), ua[0][2])
    elif not strong:
        res.add(cat, INFO, "لم يُكتشف WAF من البصمات السلبية",
                "الوضع السلبي لا يرسل اختبارات هجوم؛ بعض أنظمة WAF لا تظهر إلا عند الحظر." if not active else "")

    # هل عنوان الخادم الأصلي مكشوف؟ (استعلامات DNS فقط)
    cloud_asns = {i["asn"] for i in (infos or []) if i.get("asn") in CDN_ASNS}
    if cloud_asns and domain:
        names = [domain, "www." + domain, "direct." + domain, "origin." + domain, "dev." + domain, "staging." + domain,
                 "test." + domain, "old." + domain, "admin." + domain, "portal." + domain, "api." + domain,
                 "cpanel." + domain, "ftp." + domain, "mail." + domain, "webmail." + domain, "remote." + domain, "vpn." + domain]

        def look(n):
            return n, doh(n, "A", timeout)["answers"]
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            looked = list(ex.map(look, names))
        cand = {}
        for n, ips in looked:
            for ip in ips:
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    cand.setdefault(ip, []).append(n)
        uniq = list(cand)[:12]
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            ipi = dict(zip(uniq, ex.map(lambda ip: ip_info(ip, timeout), uniq)))
        exposed = []
        for ip in uniq:
            inf = ipi[ip]
            if inf["asn"] and inf["asn"] not in CDN_ASNS and not inf["org"].startswith("عنوان خاص"):
                hosts = cand[ip]
                mail_only = all(h.split(".")[0] in ("mail", "webmail", "ftp", "cpanel", "vpn", "remote") for h in hosts)
                exposed.append((ip, hosts, inf, mail_only))
        for ip, hosts, inf, mail_only in exposed:
            res.add(cat, INFO if mail_only else WARN,
                    "عنوان خارج الـ WAF: " + "، ".join(hosts), "%s — AS%s %s (%s)" % (ip, inf["asn"], inf["org"], inf["cc"]),
                    "" if mail_only else "إن كان هذا الخادم الأصلي فيمكن تجاوز الـ WAF بالاتصال به مباشرة: "
                                         "اقبل الاتصالات فقط من نطاقات الـ WAF وغيّر العنوان إن كان مكشوفاً سابقاً.")
        if not exposed:
            res.add(cat, PASS, "لا عناوين ظاهرة خارج الـ WAF في النطاقات الشائعة", "تم فحص %d اسماً" % len(names))


# ═════════════════════════════ التشغيل لموقع واحد ═════════════════════════════

def audit(target, args, log):
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    u = urllib.parse.urlsplit(t)
    host, port = (u.hostname or "").lower(), u.port or 443
    res = Results(host + ((":%d" % port) if port != 443 else ""))
    if not host:
        res.add(C_HTTPS, FAIL, "رابط غير صالح", target)
        return res
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror:
        # لا موقع على هذا الاسم، لكن فحوصات DNS والبريد ما زالت مفيدة للنطاق
        res.domain = args.domain or registrable_domain(host)
        res.add(C_NET, INFO, "لا يوجد موقع على هذا الاسم", "%s ليس له سجل A أو AAAA — طبيعي إن كان النطاق للبريد فقط "
                "أو الموقع على اسم فرعي. إن كان يُفترض أن يعمل فتحقق من الاسم أو أضف السجل/التحويل." % host)
        if not args.skip_dns:
            log("DNS والبريد (%s)" % res.domain)
            check_dns(res, res.domain, host, args.timeout)
        if args.subdomains or args.full:
            log("النطاقات الفرعية")
            check_subdomains(res, res.domain, args.timeout)
        return res

    ctx = Ctx(args.timeout)
    res.domain = args.domain or registrable_domain(host)
    start = "https://%s%s%s" % (host, (":%d" % port) if port != 443 else "", u.path or "/")
    active = not args.skip_probes

    log("العنوان والشبكة")
    infos = check_network(res, host, args.timeout)

    log("TLS والشهادة")
    check_tls(res, ctx, host, port)
    if port == 443:
        log("التحويل إلى HTTPS")
        check_https_redirect(res, ctx, host)

    log("الصفحة الرئيسية")
    home, chain = None, []
    try:
        home, chain = fetch_follow(ctx, start)
    except Exception as e:  # noqa: BLE001
        res.add(C_HTTPS, FAIL, "تعذّر جلب الصفحة", str(e)[:200])

    responses = []
    if home is not None:
        res.final_url = home.url
        if len(chain) > 1:
            res.add(C_HTTPS, INFO, "سلسلة التحويلات (%d)" % (len(chain) - 1), " ← ".join("%s [%d]" % c for c in chain))
            if any(c[0].startswith("http://") for c in chain[1:]):
                res.add(C_HTTPS, FAIL, "التحويلات تمر عبر HTTP غير مشفر", "", "اجعل كل التحويلات على https://")
        fu = urllib.parse.urlsplit(home.url)
        if fu.hostname and fu.hostname.lower() != host and fu.scheme == "https":
            log("TLS للنطاق النهائي " + fu.hostname)
            check_tls(res, ctx, fu.hostname, fu.port or 443, label=fu.hostname)
        if home.status >= 400:
            res.add(C_HTTPS, WARN, "الصفحة ترجع %d" % home.status, home.url,
                    "قد يكون بسبب حماية من الروبوتات؛ النتائج قد تكون ناقصة.")
        origin = "%s://%s" % (fu.scheme, fu.netloc)

        check_headers(res, home)
        log("المحتوى والتقنيات")
        page = check_content(res, ctx, home.url, home)
        tech = detect_tech(res, home, page)
        if "WordPress" in tech or "Generator: WordPress" in " ".join(tech) or "/wp-content/" in page:
            log("فحوصات WordPress")
            check_wordpress(res, ctx, origin, page, active)
        responses.append(home)
        check_cookies(res, responses)
        check_cors_methods(res, ctx, home.url, active)
        log("جدار الحماية (WAF)" + ("" if active else " — سلبي"))
        check_waf(res, ctx, origin, home, infos, None if args.skip_dns else res.domain, args.timeout, active)
        log("security.txt")
        check_security_txt(res, ctx, origin)
        if not args.skip_probes:
            log("الملفات والمجلدات المكشوفة")
            check_exposed(res, ctx, origin)
    behind_cdn = bool(home is not None and any(home.header(h) for h, _ in TECH_HEADERS[:9]))

    if not args.skip_dns:
        log("DNS والبريد (%s)" % res.domain)
        check_dns(res, res.domain, host, args.timeout)
    if (args.ports or args.full) and not active:
        res.add(C_PORTS, INFO, "فحص المنافذ لم يُشغَّل", "الوضع السلبي (--passive) لا يفحص المنافذ.")
    elif args.ports or args.full:
        log("المنافذ")
        check_ports(res, host, behind_cdn)
    if args.subdomains or args.full:
        log("النطاقات الفرعية")
        check_subdomains(res, res.domain, args.timeout)
    return res


# ═════════════════════════════ التقارير ═════════════════════════════

def print_report(res, use_color, quiet=False):
    def c(s, code):
        return (code + s + RESET) if use_color else s
    print()
    print(c("═" * 66, DIM))
    print(c("  فحص أمني: %s" % res.target, BOLD) + (c("   → " + res.final_url, DIM) if res.final_url else ""))
    if res.ips:
        print(c("  IP: ", DIM) + ", ".join(i["ip"] + ((" (AS%d %s)" % (i["asn"], i["org"][:40])) if i["asn"] else "") for i in res.ips[:3]))
    print(c("═" * 66, DIM))
    cat = None
    for i in res.sorted_items():
        st = i["status"]
        if quiet and st in (PASS, INFO):
            continue
        if i["category"] != cat:
            cat = i["category"]
            print("\n" + c("■ " + cat, BOLD))
        print("  " + c(ICONS[st] + " " + LABELS[st].ljust(6), COLORS[st]) + " " + i["title"])
        if i["detail"]:
            print("           " + c(i["detail"][:300], DIM))
        if i["fix"] and st in (FAIL, WARN):
            print("           " + c("↳ الحل: " + i["fix"], COLORS[INFO]))
    n = res.counts()
    print("\n" + c("─" * 66, DIM))
    print("  " + c("النتيجة: %d/100 (%s)" % (res.score(), res.grade()), BOLD) + "   " +
          c("%d خطر" % n[FAIL], COLORS[FAIL]) + " · " + c("%d تحذير" % n[WARN], COLORS[WARN]) + " · " +
          c("%d سليم" % n[PASS], COLORS[PASS]))
    print(c("─" * 66, DIM))


def print_summary(all_res, use_color):
    if len(all_res) < 2:
        return
    def c(s, code):
        return (code + s + RESET) if use_color else s
    print("\n" + c("ملخص المواقع", BOLD))
    for r in sorted(all_res, key=lambda r: r.score()):
        n = r.counts()
        col = COLORS[FAIL] if n[FAIL] else (COLORS[WARN] if n[WARN] else COLORS[PASS])
        ip = r.ips[0]["ip"] if r.ips else "-"
        print("  " + c(("%3d %s" % (r.score(), r.grade())), col) + "  " + r.target.ljust(30) + ip.ljust(17) +
              "  %d خطر · %d تحذير" % (n[FAIL], n[WARN]))
    print()


CSS = """:root{--bg:#0e1116;--card:#161b22;--line:#2a313c;--fg:#e6edf3;--mut:#8b949e;--pass:#3fb950;--warn:#d29922;--fail:#f85149;--info:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 "IBM Plex Sans Arabic",-apple-system,"Segoe UI",Tahoma,sans-serif}
.wrap{max-width:940px;margin:0 auto;padding:32px 20px 60px}h1{margin:0 0 4px;font-size:24px}.sub{color:var(--mut);font-size:13px}
table{width:100%;border-collapse:collapse;margin:18px 0;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:10px 14px;border-top:1px solid var(--line);text-align:right}th{color:var(--mut);font-weight:600;font-size:13px;border-top:0}
td a{color:var(--fg)}.g{font-weight:700}.gA,.gB{color:var(--pass)}.gC,.gD{color:var(--warn)}.gF{color:var(--fail)}
.site{margin-top:44px;padding-top:20px;border-top:2px solid var(--line)}.head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap}
.score{text-align:center}.score b{display:block;font-size:42px;line-height:1}.score span{color:var(--mut);font-size:13px}
.chips{display:flex;gap:8px;margin:14px 0 4px;flex-wrap:wrap}.chip{border:1px solid var(--line);border-radius:999px;padding:3px 12px;font-size:13px}
.chip.fail{color:var(--fail)}.chip.warn{color:var(--warn)}.chip.pass{color:var(--pass)}
h2{font-size:22px;margin:0}h3{font-size:15px;margin:24px 0 8px;color:var(--mut);font-weight:600}
.list{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.item{display:flex;gap:14px;padding:11px 16px;border-top:1px solid var(--line)}.item:first-child{border-top:0}
.badge{flex:0 0 76px;font-size:13px;font-weight:600}.pass .badge{color:var(--pass)}.warn .badge{color:var(--warn)}.fail .badge{color:var(--fail)}.info .badge{color:var(--info)}
.t{font-weight:600}.det{color:var(--mut);font-size:13px;word-break:break-all;font-family:ui-monospace,Menlo,monospace}.fix{color:var(--info);font-size:13px;margin-top:3px}
.filter{margin:10px 0;color:var(--mut);font-size:13px}.filter label{margin-left:14px;cursor:pointer}
body.hide-ok .item.pass,body.hide-ok .item.info{display:none}
footer{margin-top:36px;color:var(--mut);font-size:12px}
.ip{font-family:ui-monospace,Menlo,monospace;font-size:13px;color:var(--mut)}.ipl{font-family:ui-monospace,Menlo,monospace}"""


def write_html(all_res, path):
    e = html.escape
    rows = []
    for r in sorted(all_res, key=lambda r: r.score()):
        n = r.counts()
        ipcell = "<br>".join(e(i["ip"]) for i in r.ips[:2]) or "-"
        rows.append('<tr><td><a href="#%s" dir="ltr">%s</a></td><td dir="ltr" class="ip">%s</td><td class="g g%s">%d (%s)</td><td style="color:var(--fail)">%d</td><td style="color:var(--warn)">%d</td><td style="color:var(--pass)">%d</td></tr>'
                    % (e(r.target), e(r.target), ipcell, r.grade(), r.score(), r.grade(), n[FAIL], n[WARN], n[PASS]))
    sections = []
    for r in all_res:
        n = r.counts()
        body, cat = [], None
        for i in r.sorted_items():
            if i["category"] != cat:
                if cat is not None:
                    body.append("</div>")
                cat = i["category"]
                body.append("<h3>%s</h3><div class=\"list\">" % e(cat))
            det = '<div class="det" dir="auto">%s</div>' % e(i["detail"]) if i["detail"] else ""
            fix = '<div class="fix">الحل: %s</div>' % e(i["fix"]) if i["fix"] and i["status"] in (FAIL, WARN) else ""
            body.append('<div class="item %s"><span class="badge">%s %s</span><div><div class="t">%s</div>%s%s</div></div>'
                        % (i["status"], ICONS[i["status"]], LABELS[i["status"]], e(i["title"]), det, fix))
        if cat is not None:
            body.append("</div>")
        ipline = " · ".join("%s%s" % (i["ip"], (" — AS%d %s %s" % (i["asn"], i["org"], i["cc"])) if i["asn"] else "") for i in r.ips[:3])
        ipdiv = ('<div class="sub ipl" dir="ltr">IP: %s</div>' % e(ipline)) if ipline else ""
        sections.append('<section class="site" id="%s"><div class="head"><div><h2 dir="ltr">%s</h2><div class="sub" dir="ltr">%s</div>%s</div>'
                        '<div class="score"><b class="g%s">%d</b><span>من 100 — %s</span></div></div>'
                        '<div class="chips"><span class="chip fail">%d خطر</span><span class="chip warn">%d تحذير</span><span class="chip pass">%d سليم</span><span class="chip">%d معلومة</span></div>%s</section>'
                        % (e(r.target), e(r.target), e(r.final_url or ""), ipdiv, r.grade(), r.score(), r.grade(), n[FAIL], n[WARN], n[PASS], n[INFO], "".join(body)))
    doc = ('<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           "<title>تقرير الفحص الأمني</title><style>%s</style></head><body><div class=\"wrap\">"
           "<h1>تقرير الفحص الأمني</h1><div class=\"sub\">%s — site_audit %s — %d موقع</div>"
           "<table><tr><th>الموقع</th><th>IP</th><th>النتيجة</th><th>خطر</th><th>تحذير</th><th>سليم</th></tr>%s</table>"
           "<div class=\"filter\"><label><input type=\"checkbox\" onchange=\"document.body.classList.toggle('hide-ok',this.checked)\"> إظهار المشاكل فقط</label></div>"
           "%s<footer>فحص خارجي غير مُتلِف في لحظة معينة، ولا يغني عن اختبار اختراق كامل. استخدمه فقط على مواقع مصرّح لك بفحصها.</footer>"
           "</div></body></html>") % (CSS, dt.datetime.now().strftime("%Y-%m-%d %H:%M"), VERSION, len(all_res), "".join(rows), "".join(sections))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# ═════════════════════════════ main ═════════════════════════════

# ═════════════════════════════ الوضع التفاعلي ═════════════════════════════
# يعمل عند فتح الأداة بنقرة مزدوجة (Windows) أو تشغيلها بدون أي خيارات.
# طرفية Windows لا تعرض العربية بشكل سليم، لذلك القائمة فيها بالإنجليزية؛ والتقرير عربي دائماً.

UI = {
    "en": {
        "title": "Site Audit %s - website security scanner" % VERSION,
        "legal": "Only scan websites you own or have written permission to test.",
        "ask_site": "Website(s) to scan, e.g. example.com  (q = quit): ",
        "menu": ["Choose scan type:",
                 "  [1] Passive  - safe for ANY website (looks like a normal visitor)",
                 "  [2] Standard - your own sites: + WAF blocking test, exposed files",
                 "  [3] Full     - Standard + open ports + subdomains (your servers only)",
                 "  [4] Custom   - choose each option"],
        "ask_choice": "Choice [1-4] (Enter = 1): ",
        "ask_auth": "Do you own this website or have written permission to test it? (y/N): ",
        "no_auth": "OK - switching to Passive mode.",
        "c_active": "Send active probes (WAF test, sensitive files)? (y/N): ",
        "c_ports": "Scan dangerous open ports? (y/N): ",
        "c_subs": "Look up subdomains and takeover risk? (y/N): ",
        "c_dns": "Check DNS and e-mail records? (Y/n): ",
        "scanning": "Scanning %s ",
        "result": "  Score %d/100 (%s)  -  %d critical, %d warnings, %d passed",
        "saved": "HTML report saved:",
        "opening": "Opening the report in your browser...",
        "again": "Scan another website? (y/N): ",
        "bye": "Press Enter to exit...",
        "error": "Unexpected error:",
        "yes": ("y", "yes"),
    },
    "ar": {
        "title": "أداة الفحص الأمني %s" % VERSION,
        "legal": "افحص فقط المواقع التي تملكها أو لديك إذن مكتوب بفحصها.",
        "ask_site": "الموقع أو المواقع المراد فحصها، مثل example.com (q للخروج): ",
        "menu": ["اختر نوع الفحص:",
                 "  [1] سلبي  - آمن لأي موقع، يتصرف كزائر عادي",
                 "  [2] عادي  - لمواقعك: يضيف اختبار حجب WAF والملفات المكشوفة",
                 "  [3] شامل  - العادي + المنافذ + النطاقات الفرعية (لخوادمك فقط)",
                 "  [4] مخصص - اختر كل خيار بنفسك"],
        "ask_choice": "اختيارك [1-4] (Enter = 1): ",
        "ask_auth": "هل تملك هذا الموقع أو لديك إذن مكتوب بفحصه؟ (y/N): ",
        "no_auth": "حسناً، سيتم الفحص بالوضع السلبي.",
        "c_active": "إرسال اختبارات نشطة (اختبار WAF والملفات الحساسة)؟ (y/N): ",
        "c_ports": "فحص المنافذ الخطرة؟ (y/N): ",
        "c_subs": "فحص النطاقات الفرعية وخطر الاستيلاء؟ (y/N): ",
        "c_dns": "فحص سجلات DNS والبريد؟ (Y/n): ",
        "scanning": "جارٍ فحص %s ",
        "result": "  النتيجة %d/100 (%s) - %d خطر، %d تحذير، %d سليم",
        "saved": "تم حفظ تقرير HTML:",
        "opening": "يُفتح التقرير في المتصفح...",
        "again": "فحص موقع آخر؟ (y/N): ",
        "bye": "اضغط Enter للخروج...",
        "error": "خطأ غير متوقع:",
        "yes": ("y", "yes", "نعم", "ن"),
    },
}


def reports_dir():
    """مجلد التقارير: Documents/SiteAudit-Reports (أو المجلد الرئيسي إن لم يوجد Documents)."""
    home = os.path.expanduser("~")
    docs = os.path.join(home, "Documents")
    base = docs if os.path.isdir(docs) else home
    path = os.path.join(base, "SiteAudit-Reports")
    os.makedirs(path, exist_ok=True)
    return path


def open_file(path):
    try:
        if os.name == "nt":
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            os.system('open "%s"' % path)
        else:
            import webbrowser
            webbrowser.open("file://" + path)
    except Exception:  # noqa: BLE001
        pass


def interactive():
    L = UI["en" if os.name == "nt" else "ar"]

    def ask(prompt):
        try:
            return input(prompt).strip()
        except EOFError:
            return "q"

    def yes(prompt, default=False):
        a = ask(prompt).lower()
        return default if not a else a in L["yes"]

    print("=" * 66)
    print("  " + L["title"])
    print("  " + L["legal"])
    print("=" * 66)
    code = 0
    while True:
        print()
        raw = ask(L["ask_site"])
        if raw.lower() in ("q", "quit", "exit"):
            break
        targets = list(dict.fromkeys(t for t in re.split(r"[\s,;]+", raw) if t))
        if not targets:
            continue
        print()
        for line in L["menu"]:
            print(line)
        choice = ask(L["ask_choice"]) or "1"
        ns = argparse.Namespace(domain=None, full=False, ports=False, subdomains=False,
                                skip_probes=True, skip_dns=False, timeout=10)
        if choice in ("2", "3", "4"):
            if not yes(L["ask_auth"]):
                print(L["no_auth"])
                choice = "1"
        if choice == "2":
            ns.skip_probes = False
        elif choice == "3":
            ns.skip_probes, ns.full = False, True
        elif choice == "4":
            ns.skip_probes = not yes(L["c_active"])
            ns.ports = (not ns.skip_probes) and yes(L["c_ports"])
            ns.subdomains = yes(L["c_subs"])
            ns.skip_dns = not yes(L["c_dns"], default=True)

        all_res = []
        for t in targets:
            print()
            sys.stdout.write(L["scanning"] % t)
            sys.stdout.flush()

            def log(_m):
                sys.stdout.write(".")
                sys.stdout.flush()
            r = audit(t, ns, log)
            all_res.append(r)
            n = r.counts()
            print()
            print(L["result"] % (r.score(), r.grade(), n[FAIL], n[WARN], n[PASS]))
            if n[FAIL]:
                code = 1

        stamp = dt.datetime.now().strftime("%Y-%m-%d_%H%M")
        first = re.sub(r"[^\w.-]", "_", all_res[0].target)
        name = ("%s_%s.html" % (first, stamp)) if len(all_res) == 1 else ("%d-sites_%s.html" % (len(all_res), stamp))
        path = os.path.join(reports_dir(), name)
        write_html(all_res, path)
        print()
        print(L["saved"])
        print("  " + path)
        print(L["opening"])
        open_file(path)
        print()
        if not yes(L["again"]):
            break
    print()
    ask(L["bye"])
    return code


def main():
    ap = argparse.ArgumentParser(description="فحص أمني خارجي عام وغير مُتلِف لمواقع الويب ونطاقاتها.",
                                 epilog="استخدمها فقط على مواقع تملكها أو لديك إذن بفحصها.")
    ap.add_argument("targets", nargs="*", help="موقع أو أكثر، مثل example.com أو https://www.example.org")
    ap.add_argument("-f", "--file", help="ملف فيه موقع في كل سطر (الأسطر التي تبدأ بـ # تُتجاهل)")
    ap.add_argument("--domain", help="النطاق الرئيسي لفحوصات DNS (لموقع واحد؛ افتراضياً يُستنتج)")
    ap.add_argument("--full", action="store_true", help="تشغيل كل الفحوصات بما فيها المنافذ والنطاقات الفرعية")
    ap.add_argument("--ports", action="store_true", help="فحص المنافذ الخطرة الشائعة")
    ap.add_argument("--subdomains", action="store_true", help="جمع النطاقات الفرعية من سجلات الشهادات وفحص خطر الاستيلاء")
    ap.add_argument("--passive", "--skip-probes", dest="skip_probes", action="store_true",
                    help="وضع سلبي: لا يطلب مسارات حساسة ولا يرسل اختبارات هجوم ولا يفحص المنافذ (مناسب لمواقع لا تملكها)")
    ap.add_argument("--skip-dns", action="store_true", help="تخطي فحوصات DNS والبريد")
    ap.add_argument("--html", metavar="FILE", help="حفظ تقرير HTML (يجمع كل المواقع)")
    ap.add_argument("--json", metavar="FILE", help="حفظ النتائج بصيغة JSON")
    ap.add_argument("-q", "--quiet", action="store_true", help="عرض المشاكل فقط في الطرفية")
    ap.add_argument("--timeout", type=float, default=10, help="مهلة كل اتصال بالثواني (افتراضي 10)")
    ap.add_argument("--no-color", action="store_true", help="بدون ألوان")
    ap.add_argument("--open", action="store_true", help="فتح تقرير HTML في المتصفح بعد الانتهاء")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="الوضع التفاعلي: يسألك عن الموقع ونوع الفحص ويحفظ تقرير HTML تلقائياً (يعمل أيضاً عند التشغيل بدون خيارات)")
    a = ap.parse_args()

    # Windows: مخرجات UTF-8 للعربية، وتفعيل ألوان ANSI في الطرفية
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if os.name == "nt":
        os.system("")

    # الوضع التفاعلي: بطلب صريح، أو عند التشغيل بدون أي خيارات (مثل النقر المزدوج على الملف في Windows)
    if a.interactive or (len(sys.argv) == 1 and sys.stdin.isatty()):
        try:
            sys.exit(interactive())
        except KeyboardInterrupt:
            sys.exit(130)
        except Exception as e:  # noqa: BLE001 — حتى لا تُغلق النافذة قبل أن يقرأ المستخدم الخطأ
            import traceback
            traceback.print_exc()
            print("\n" + UI["en" if os.name == "nt" else "ar"]["error"], e)
            try:
                input(UI["en" if os.name == "nt" else "ar"]["bye"])
            except EOFError:
                pass
            sys.exit(1)

    targets = list(a.targets)
    if a.file:
        with open(a.file, encoding="utf-8") as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
    targets = list(dict.fromkeys(targets))
    if not targets:
        ap.error("حدّد موقعاً واحداً على الأقل أو ملفاً بـ -f")
    if a.domain and len(targets) > 1:
        ap.error("--domain يُستخدم مع موقع واحد فقط")

    use_color = sys.stdout.isatty() and not a.no_color and os.environ.get("NO_COLOR") is None
    all_res = []
    for idx, t in enumerate(targets, 1):
        prefix = ("[%d/%d] " % (idx, len(targets))) if len(targets) > 1 else ""
        def log(m, p=prefix, t=t):
            print(((DIM + "… " + RESET) if use_color else "… ") + p + t + " — " + m, file=sys.stderr)
        r = audit(t, a, log)
        all_res.append(r)
        print_report(r, use_color, a.quiet)

    print_summary(all_res, use_color)
    if a.html:
        write_html(all_res, a.html)
        print("تقرير HTML: " + os.path.abspath(a.html))
        if a.open:
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(a.html))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"tool": "site_audit", "version": VERSION, "date": dt.datetime.now().isoformat(),
                       "sites": [r.to_dict() for r in all_res]}, fh, ensure_ascii=False, indent=2)
        print("ملف JSON: " + os.path.abspath(a.json))
    sys.exit(1 if any(r.counts()[FAIL] for r in all_res) else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
