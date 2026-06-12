#!/usr/bin/env python3
"""Site Doctor - WordPress diagnostic scan, content inventory, and analytics/SEO report.

Pure Python 3 standard library. Uses `dig` for DNS records if present on PATH
(falls back to socket-based resolution), and Google's public PageSpeed Insights
API for Lighthouse scores (falls back to a self-computed scorecard if PSI is
unreachable or rate-limited). No third-party packages required.

USAGE
-----
    python3 site_doctor.py [URL] [OPTIONS]

If URL is omitted, you will be prompted to enter one interactively
(e.g. https://example.com). The scheme defaults to https:// if not given.

By default (no mode flags given), Site Doctor runs ALL THREE diagnostics
in a single pass - diagnostic scan, WordPress content inventory, and
analytics/SEO report - and writes one combined HTML report covering
everything that ran. Pass one or more mode flags below to narrow this down
to a subset.

MODE FLAGS (omit all to run everything)
----------------------------------------
    --scan          Diagnostic scan only: request timing (DNS/connect/TLS/
                     TTFB/download), HTTP headers, caching, security headers,
                     cookies, CORS/mixed content, TLS certificate and
                     protocol support, DNS records, robots.txt/sitemap/
                     favicon, redirect behaviour, server/CDN fingerprint,
                     WordPress core/theme/plugin/user fingerprinting, and
                     the weighted Health Scorecard (0-100, grade A-F).

    --inventory     WordPress content inventory only: walks every public
                     post type exposed via /wp-json/wp/v2/..., paginates
                     through all results, de-duplicates by type+ID, and
                     prints a table of ID, Type, Date, Category, Title.

    --analytics     Analytics & SEO report only: real Lighthouse scores via
                     Google PageSpeed Insights (Performance, SEO,
                     Accessibility, Best Practices, Core Web Vitals), with
                     an automatic fallback to a self-computed performance
                     scorecard if PSI is unavailable. Also runs a per-page
                     SEO breakdown (title/meta length, H1 count, word count,
                     image alt coverage, link counts, Open Graph/Twitter
                     tags, structured data, load time) across the site's
                     content.

                     Note: --inventory and --analytics both require the
                     content inventory, so requesting --analytics alone
                     will still fetch the inventory in the background (it
                     just won't be printed/included unless --inventory is
                     also given).

OTHER OPTIONS
-------------
    --max-pages N   Number of pages to run the per-page SEO analysis on
                     during --analytics (default: 10). Increase this for a
                     more complete SEO audit of larger sites, at the cost of
                     a longer run time (one extra HTTP request per page).

    --no-psi        Skip the Google PageSpeed Insights API call entirely and
                     go straight to the self-computed performance scorecard.
                     Useful when offline, rate-limited, or for faster runs.

    --out PATH      Write the HTML report to PATH instead of the default
                     ./site-doctor-report-<host>-<timestamp>.html in the
                     current directory.

EXAMPLES
--------
    python3 site_doctor.py
        Prompt for a URL, then run scan + inventory + analytics.

    python3 site_doctor.py https://example.com
        Run all three diagnostics against example.com.

    python3 site_doctor.py https://example.com --scan
        Run only the diagnostic scan and health scorecard.

    python3 site_doctor.py https://example.com --inventory
        Run only the WordPress content inventory.

    python3 site_doctor.py https://example.com --analytics --max-pages 25 --no-psi
        Run only the analytics/SEO report, skip PageSpeed Insights, and
        analyze 25 pages instead of the default 10.

    python3 site_doctor.py https://example.com --out reports/example.html
        Run all three diagnostics and write the HTML report to a custom path.

OUTPUT
------
A color-coded report is printed to the terminal for each mode that ran
(colors auto-disable when stdout is not a TTY), and a single branded,
self-contained HTML report is written to disk containing every section that
ran during that invocation (health scorecard, tables, badges, and per-page
cards).
"""

import sys
import os
import re
import json
import gzip
import zlib
import socket
import ssl
import time
import shutil
import subprocess
import html as html_lib
import http.client
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, urljoin
from urllib.request import Request, urlopen

VERSION = "1.0"
USER_AGENT = "SiteDoctor/%s (+pure-python diagnostic tool)" % VERSION
TIMEOUT = 12
MAX_REDIRECTS = 6

ISATTY = sys.stdout.isatty()


class C:
    RESET = "\033[0m" if ISATTY else ""
    BOLD = "\033[1m" if ISATTY else ""
    DIM = "\033[2m" if ISATTY else ""
    RED = "\033[31m" if ISATTY else ""
    GREEN = "\033[32m" if ISATTY else ""
    YELLOW = "\033[33m" if ISATTY else ""
    BLUE = "\033[34m" if ISATTY else ""
    MAGENTA = "\033[35m" if ISATTY else ""
    CYAN = "\033[36m" if ISATTY else ""
    WHITE = "\033[97m" if ISATTY else ""
    GRAY = "\033[90m" if ISATTY else ""


def c(text, color):
    return f"{color}{text}{C.RESET}" if color else str(text)


def status_color(code):
    if code is None:
        return C.RED
    if 200 <= code < 300:
        return C.GREEN
    if 300 <= code < 400:
        return C.CYAN
    if 400 <= code < 500:
        return C.YELLOW
    return C.RED


def yesno(value, warn_if_false=False):
    if value:
        return c("YES", C.GREEN)
    return c("NO", C.YELLOW if warn_if_false else C.RED)


# ---------------------------------------------------------------------------
# HTML parsing helpers (regex-based, tolerant of malformed markup)
# ---------------------------------------------------------------------------

_ATTR_RE = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"'
                      r'|([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*\'([^\']*)\'')


def _parse_attrs(attr_str):
    attrs = {}
    for m in _ATTR_RE.finditer(attr_str):
        if m.group(1) is not None:
            attrs[m.group(1).lower()] = m.group(2)
        else:
            attrs[m.group(3).lower()] = m.group(4)
    return attrs


def parse_meta_tags(body):
    return [_parse_attrs(m.group(1)) for m in re.finditer(r'<meta\b([^>]*)>', body, re.I)]


def parse_link_tags(body):
    return [_parse_attrs(m.group(1)) for m in re.finditer(r'<link\b([^>]*)>', body, re.I)]


def get_meta(metas, key, attr='name'):
    for m in metas:
        if m.get(attr, '').lower() == key.lower():
            return html_lib.unescape(m.get('content', ''))
    return None


def get_title(body):
    m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
    if not m:
        return None
    return html_lib.unescape(re.sub(r'\s+', ' ', m.group(1)).strip())


def get_h1s(body):
    out = []
    for m in re.finditer(r'<h1\b[^>]*>(.*?)</h1>', body, re.I | re.S):
        text = re.sub(r'<[^>]+>', ' ', m.group(1))
        out.append(html_lib.unescape(re.sub(r'\s+', ' ', text)).strip())
    return out


def get_jsonld_types(body):
    types = []
    for m in re.finditer(r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', body, re.I | re.S):
        try:
            data = json.loads(m.group(1).strip())
        except Exception:
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict) and '@type' in item:
                t = item['@type']
                types.append(t if isinstance(t, str) else ','.join(t))
    return types


def analyze_images(body):
    imgs = re.findall(r'<img\b[^>]*>', body, re.I)
    missing_alt = sum(1 for img in imgs if 'alt=' not in img.lower())
    return len(imgs), missing_alt


def analyze_links(body, host):
    hrefs = re.findall(r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', body, re.I)
    internal = external = 0
    for h in hrefs:
        if h.startswith('#') or h.startswith(('mailto:', 'tel:', 'javascript:')):
            continue
        if h.startswith('http://') or h.startswith('https://') or h.startswith('//'):
            if host in h:
                internal += 1
            else:
                external += 1
        else:
            internal += 1
    return internal, external


def word_count(body):
    text = re.sub(r'<(script|style|noscript)[^>]*>.*?</\1>', ' ', body, flags=re.I | re.S)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = html_lib.unescape(text)
    return len(text.split())


def detect_trackers(body):
    found = []
    checks = {
        'Google Analytics (GA4)': r'gtag\(|G-[A-Z0-9]{6,}',
        'Google Tag Manager': r'GTM-[A-Z0-9]+',
        'Universal Analytics': r'UA-\d{4,}-\d+',
        'Meta/Facebook Pixel': r'connect\.facebook\.net/[^"\']*/fbevents',
        'Matomo/Piwik': r'matomo\.js|piwik\.js',
        'Jetpack Stats': r'stats\.wp\.com',
        'Hotjar': r'hotjar\.com',
        'Cloudflare Web Analytics': r'static\.cloudflareinsights\.com',
    }
    for name, pattern in checks.items():
        if re.search(pattern, body, re.I):
            found.append(name)
    return found


# ---------------------------------------------------------------------------
# Low-level timed HTTP fetch (DNS / connect / TLS / TTFB / download timings)
# ---------------------------------------------------------------------------

class FetchResult:
    def __init__(self):
        self.url = None
        self.status = None
        self.headers = {}
        self.body = b""
        self.text = ""
        self.error = None
        self.timings = {}
        self.tls = None
        self.redirect_chain = []


_SSL_CONTEXT = None


def _configure_ca(ctx):
    """Point a fresh SSL context at a working CA bundle on Python installs
    whose bundled OpenSSL points at a missing CA file (common with python.org
    installers on macOS), falling back to the OS CA bundle or certifi."""
    paths = ssl.get_default_verify_paths()
    cafile_ok = paths.cafile and os.path.exists(paths.cafile)
    capath_ok = paths.capath and os.path.exists(paths.capath)
    if not cafile_ok and not capath_ok:
        for candidate in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
                          "/etc/pki/tls/certs/ca-bundle.crt"):
            if os.path.exists(candidate):
                try:
                    ctx.load_verify_locations(cafile=candidate)
                    break
                except ssl.SSLError:
                    continue
        else:
            try:
                import certifi
                ctx.load_verify_locations(cafile=certifi.where())
            except Exception:
                pass


def get_ssl_context():
    """Shared verifying SSL context for plain requests. Do not mutate
    (e.g. set_alpn_protocols) - build a fresh context via new_ssl_context()
    for callers that need custom settings."""
    global _SSL_CONTEXT
    if _SSL_CONTEXT is None:
        ctx = ssl.create_default_context()
        _configure_ca(ctx)
        _SSL_CONTEXT = ctx
    return _SSL_CONTEXT


def new_ssl_context():
    ctx = ssl.create_default_context()
    _configure_ca(ctx)
    return ctx


def _read_headers_dict(resp):
    out = {}
    for k, v in resp.getheaders():
        out[k] = (out[k] + ", " + v) if k in out else v
    return out


def _single_request(url, method="GET", extra_headers=None, timeout=TIMEOUT):
    """Perform one HTTP request over a manually-managed socket, capturing
    DNS / TCP connect / TLS handshake / TTFB / download timings."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    timings = {}
    t_start = time.perf_counter()

    addrinfo = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    t_dns = time.perf_counter()
    timings["dns_ms"] = (t_dns - t_start) * 1000

    family, socktype, proto, _, sockaddr = addrinfo[0]
    raw_sock = socket.socket(family, socktype, proto)
    raw_sock.settimeout(timeout)
    raw_sock.connect(sockaddr)
    t_connect = time.perf_counter()
    timings["connect_ms"] = (t_connect - t_dns) * 1000

    tls_info = None
    sock = raw_sock
    if scheme == "https":
        ctx = get_ssl_context()
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        t_tls = time.perf_counter()
        timings["tls_ms"] = (t_tls - t_connect) * 1000
        tls_info = {
            "cert": sock.getpeercert(),
            "version": sock.version(),
            "cipher": sock.cipher(),
        }
    else:
        timings["tls_ms"] = 0.0

    headers = {
        "Host": host,
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)
    header_block = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    request_bytes = f"{method} {path} HTTP/1.1\r\n{header_block}\r\n".encode("ascii", "ignore")

    t_send = time.perf_counter()
    sock.sendall(request_bytes)

    resp = http.client.HTTPResponse(sock, method=method)
    resp.begin()
    t_ttfb = time.perf_counter()
    timings["ttfb_ms"] = (t_ttfb - t_send) * 1000

    raw_body = resp.read() if method != "HEAD" else b""
    t_done = time.perf_counter()
    timings["download_ms"] = (t_done - t_ttfb) * 1000
    timings["total_ms"] = (t_done - t_start) * 1000

    status = resp.status
    resp_headers = _read_headers_dict(resp)
    sock.close()

    encoding = resp_headers.get("Content-Encoding", "").lower()
    body = raw_body
    try:
        if encoding == "gzip":
            body = gzip.decompress(raw_body)
        elif encoding == "deflate":
            body = zlib.decompress(raw_body)
    except Exception:
        body = raw_body

    result = FetchResult()
    result.url = url
    result.status = status
    result.headers = resp_headers
    result.body = body
    result.timings = timings
    result.tls = tls_info
    try:
        result.text = body.decode("utf-8", errors="replace")
    except Exception:
        result.text = ""
    return result


def timed_fetch(url, method="GET", extra_headers=None, timeout=TIMEOUT, max_redirects=MAX_REDIRECTS):
    chain = []
    current = url
    result = None
    for _ in range(max_redirects + 1):
        try:
            result = _single_request(current, method=method, extra_headers=extra_headers, timeout=timeout)
        except Exception as e:
            err = FetchResult()
            err.url = current
            err.error = str(e)
            err.redirect_chain = chain
            return err
        chain.append((current, result.status))
        if result.status in (301, 302, 303, 307, 308):
            location = result.headers.get("Location")
            if not location:
                break
            current = urljoin(current, location)
            continue
        break
    result.redirect_chain = chain
    result.url = current
    return result


def http_get_json(url, timeout=TIMEOUT):
    result = timed_fetch(url, timeout=timeout)
    if result.error or result.status != 200:
        return result, None
    try:
        return result, json.loads(result.text)
    except Exception:
        return result, None


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

DIG_AVAILABLE = shutil.which("dig") is not None


def dig(record_type, name):
    if not DIG_AVAILABLE:
        return None
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", record_type, name],
            capture_output=True, text=True, timeout=6,
        )
        return [l.strip() for l in out.stdout.splitlines() if l.strip()]
    except Exception:
        return None


def resolve_a_aaaa(host):
    a, aaaa = dig("A", host) or [], dig("AAAA", host) or []
    if not a and not aaaa:
        try:
            for fam, _, _, _, addr in socket.getaddrinfo(host, None):
                ip = addr[0]
                if fam == socket.AF_INET and ip not in a:
                    a.append(ip)
                elif fam == socket.AF_INET6 and ip not in aaaa:
                    aaaa.append(ip)
        except Exception:
            pass
    return a, aaaa


def reverse_dns(ip):
    rev = dig("-x", ip)
    if rev:
        return rev[0].rstrip(".")
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def gather_dns(host):
    a, aaaa = resolve_a_aaaa(host)
    dns = {
        "A": a,
        "AAAA": aaaa,
        "MX": dig("MX", host) or [],
        "TXT": dig("TXT", host) or [],
        "NS": dig("NS", host) or [],
        "CNAME": dig("CNAME", host) or [],
    }
    dns["PTR"] = reverse_dns(a[0]) if a else None
    return dns


# ---------------------------------------------------------------------------
# TLS helpers
# ---------------------------------------------------------------------------

def check_alpn_h2(host, port=443, timeout=TIMEOUT):
    try:
        ctx = new_ssl_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return s.selected_alpn_protocol()
    except Exception:
        return None


def check_protocol_support(host, port=443, timeout=TIMEOUT):
    """Best-effort probe of which TLS protocol versions the server accepts.
    Returns True/False per version, or None if the local OpenSSL build can't
    test that version at all."""
    results = {}
    versions = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    for label, ver in versions.items():
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host):
                    results[label] = True
        except ssl.SSLError:
            results[label] = False
        except Exception:
            results[label] = None
    return results


def parse_cert(cert):
    if not cert:
        return None

    def _name(field):
        return ", ".join(f"{k}={v}" for tup in cert.get(field, []) for k, v in tup)

    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    days_left = None
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
        except Exception:
            pass
    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    return {
        "subject": _name("subject"),
        "issuer": _name("issuer"),
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "sans": sans,
    }


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def normalize_url(raw):
    raw = raw.strip()
    if not re.match(r'^https?://', raw, re.I):
        raw = 'https://' + raw
    parsed = urlparse(raw)
    path = parsed.path.rstrip('/')
    return f"{parsed.scheme.lower()}://{parsed.netloc}{path}"


# ---------------------------------------------------------------------------
# Diagnostic scan: individual checks
# ---------------------------------------------------------------------------

def fetch_security_headers(headers):
    checks = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-Frame-Options": "X-Frame-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
        "Cross-Origin-Opener-Policy": "COOP",
        "Cross-Origin-Resource-Policy": "CORP",
    }
    lower_headers = {k.lower(): v for k, v in headers.items()}
    return {label: lower_headers.get(hkey.lower()) for hkey, label in checks.items()}


def analyze_caching(headers):
    lower = {k.lower(): v for k, v in headers.items()}
    return {
        "Cache-Control": lower.get("cache-control"),
        "Expires": lower.get("expires"),
        "ETag": lower.get("etag"),
        "Last-Modified": lower.get("last-modified"),
        "Age": lower.get("age"),
        "X-Cache": lower.get("x-cache") or lower.get("x-cache-status") or lower.get("cf-cache-status"),
        "CDN-Cache-Control": lower.get("cdn-cache-control"),
    }


def detect_server_tech(headers):
    lower = {k.lower(): v for k, v in headers.items()}
    cdn = None
    cdn_hints = {
        "cf-ray": "Cloudflare",
        "x-served-by": "Fastly / Varnish",
        "x-vercel-id": "Vercel",
        "x-amz-cf-id": "Amazon CloudFront",
        "x-sucuri-id": "Sucuri",
        "x-litespeed-cache": "LiteSpeed",
    }
    for h, name in cdn_hints.items():
        if h in lower:
            cdn = name
            break
    if cdn is None and "cloudflare" in lower.get("server", "").lower():
        cdn = "Cloudflare"
    return {
        "Server": lower.get("server"),
        "X-Powered-By": lower.get("x-powered-by"),
        "CDN/Proxy": cdn,
        "Via": lower.get("via"),
    }


def analyze_cookies(headers):
    raw = headers.get("Set-Cookie", "")
    cookies = []
    if not raw:
        return cookies
    for part in re.split(r',(?=\s*[^;=,]+=[^;=,]+)', raw):
        part = part.strip()
        if not part:
            continue
        name = part.split('=')[0].strip()
        cookies.append({
            "name": name,
            "secure": bool(re.search(r';\s*secure\b', part, re.I)) or part.lower().endswith("secure"),
            "httponly": bool(re.search(r'httponly', part, re.I)),
            "samesite": bool(re.search(r'samesite', part, re.I)),
        })
    return cookies


def check_cors(headers):
    return headers.get("Access-Control-Allow-Origin")


def check_mixed_content(base_url, body):
    if not base_url.startswith("https://"):
        return []
    refs = re.findall(r'(?:src|href)=["\']http://([^"\']+)["\']', body, re.I)
    return list(dict.fromkeys(refs))[:10]


def check_robots_and_sitemap(base_url):
    robots = timed_fetch(urljoin(base_url + '/', 'robots.txt'))
    robots_exists = robots.status == 200 and not robots.error
    sitemaps = re.findall(r'(?im)^sitemap:\s*(\S+)', robots.text) if robots_exists else []
    sitemap_url = sitemaps[0] if sitemaps else urljoin(base_url + '/', 'sitemap.xml')
    sitemap_result = timed_fetch(sitemap_url)
    sitemap_exists = sitemap_result.status == 200 and not sitemap_result.error
    url_count = None
    if sitemap_exists:
        url_count = len(re.findall(r'<(?:url|sitemap)>', sitemap_result.text, re.I))
    return {
        "robots_txt": robots_exists,
        "robots_status": robots.status,
        "sitemaps_declared": sitemaps,
        "sitemap_url": sitemap_url,
        "sitemap_exists": sitemap_exists,
        "sitemap_entry_count": url_count,
    }


def check_favicon(base_url):
    result = timed_fetch(urljoin(base_url + '/', 'favicon.ico'), method="HEAD")
    return result.status == 200 and not result.error


def check_redirect_behavior(base_url):
    parsed = urlparse(base_url)
    host = parsed.hostname
    out = {}

    if parsed.scheme == "https":
        http_url = f"http://{parsed.netloc}{parsed.path}"
        r = timed_fetch(http_url, max_redirects=3)
        final = r.redirect_chain[-1][0] if r.redirect_chain else http_url
        out["http_to_https"] = final.startswith("https://")
        out["http_redirect_chain"] = r.redirect_chain
    else:
        out["http_to_https"] = False
        out["http_redirect_chain"] = []

    alt_host = host[4:] if host.startswith("www.") else "www." + host
    r2 = timed_fetch(f"{parsed.scheme}://{alt_host}{parsed.path}", max_redirects=3)
    out["alt_host"] = alt_host
    out["alt_host_status"] = r2.status
    out["alt_host_redirects_to"] = r2.redirect_chain[-1][0] if len(r2.redirect_chain) > 1 else None
    return out


def check_404_handling(base_url):
    probe = urljoin(base_url + '/', f"site-doctor-404-check-{int(time.time())}")
    r = timed_fetch(probe)
    return {"status": r.status, "is_404": r.status == 404}


# ---------------------------------------------------------------------------
# WordPress fingerprinting
# ---------------------------------------------------------------------------

def detect_plugins_from_namespaces(namespaces):
    """Map common REST namespaces back to the plugin that registers them."""
    known = {
        "yoast/v1": "Yoast SEO",
        "wpseo/v1": "Yoast SEO (legacy)",
        "rankmath/v1": "Rank Math SEO",
        "contact-form-7/v1": "Contact Form 7",
        "wpforms/v1": "WPForms",
        "woocommerce/v1": "WooCommerce",
        "woocommerce/v2": "WooCommerce",
        "woocommerce/v3": "WooCommerce",
        "wc/v3": "WooCommerce Store API",
        "wc/store/v1": "WooCommerce Store API",
        "jetpack/v4": "Jetpack",
        "akismet/v1": "Akismet",
        "elementor/v1": "Elementor",
        "wpml/v1": "WPML",
        "acf/v3": "Advanced Custom Fields PRO",
        "redirection/v1": "Redirection",
        "wp-statistics/v2": "WP Statistics",
    }
    found = {}
    for ns in namespaces:
        if ns in known:
            found[known[ns]] = None
    return found


def fingerprint_wordpress(base_url, home_body, home_headers):
    info = {
        "is_wordpress": False,
        "version": None,
        "version_source": None,
        "theme": None,
        "plugins": {},
        "rest_api_enabled": False,
        "rest_namespaces": [],
        "xmlrpc_enabled": None,
        "users_exposed": [],
        "wp_login_exists": None,
        "readme_exposed": False,
        "site_name": None,
        "site_description": None,
    }

    metas = parse_meta_tags(home_body)
    gen = get_meta(metas, "generator")
    if gen and "wordpress" in gen.lower():
        info["is_wordpress"] = True
        m = re.search(r'([\d.]+)', gen)
        if m:
            info["version"] = m.group(1)
            info["version_source"] = "meta generator tag"

    _, root_json = http_get_json(urljoin(base_url + '/', 'wp-json/'))
    if isinstance(root_json, dict):
        info["is_wordpress"] = True
        info["rest_api_enabled"] = True
        info["site_name"] = root_json.get("name")
        info["site_description"] = root_json.get("description")
        ns = root_json.get("namespaces", [])
        info["rest_namespaces"] = ns
        info["plugins"].update(detect_plugins_from_namespaces(ns))

    readme = timed_fetch(urljoin(base_url + '/', 'readme.html'))
    if readme.status == 200 and not readme.error:
        info["readme_exposed"] = True
        info["is_wordpress"] = True
        m = re.search(r'[Vv]ersion\s+([\d.]+)', readme.text)
        if m and not info["version"]:
            info["version"] = m.group(1)
            info["version_source"] = "readme.html"

    if not info["version"]:
        feed = timed_fetch(urljoin(base_url + '/', 'feed/'))
        if feed.status == 200 and not feed.error:
            m = re.search(r'generator>https?://wordpress\.org/\?v=([\d.]+)', feed.text)
            if m:
                info["is_wordpress"] = True
                info["version"] = m.group(1)
                info["version_source"] = "feed generator tag"

    for m in re.finditer(r'wp-content/(plugins|themes)/([^/\'"?]+)/[^\'">]*?(?:\?ver=([\w.\-]+))?["\']', home_body, re.I):
        kind, slug, ver = m.group(1), m.group(2), m.group(3)
        if kind == "themes" and not info["theme"]:
            info["theme"] = {"slug": slug, "version": ver}
        elif kind == "plugins":
            if slug not in info["plugins"] or (ver and not info["plugins"].get(slug)):
                info["plugins"][slug] = ver

    if info["plugins"] or info["theme"]:
        info["is_wordpress"] = True

    xr = timed_fetch(urljoin(base_url + '/', 'xmlrpc.php'), method="HEAD")
    info["xmlrpc_enabled"] = (xr.status in (200, 405)) if not xr.error else None

    wl = timed_fetch(urljoin(base_url + '/', 'wp-login.php'), method="HEAD")
    info["wp_login_exists"] = (wl.status == 200) if not wl.error else None

    _, users_json = http_get_json(urljoin(base_url + '/', 'wp-json/wp/v2/users?per_page=100'))
    if isinstance(users_json, list):
        for u in users_json:
            info["users_exposed"].append({
                "id": u.get("id"),
                "name": u.get("name"),
                "slug": u.get("slug"),
            })

    return info


# ---------------------------------------------------------------------------
# Health scorecard
# ---------------------------------------------------------------------------

def compute_health_score(scan):
    categories = []  # (name, earned, possible, notes)

    sh = scan["security_headers"]
    weights = {
        "HSTS": 4, "CSP": 4, "X-Content-Type-Options": 3,
        "X-Frame-Options": 3, "Referrer-Policy": 3, "Permissions-Policy": 3,
    }
    pts, notes = 0, []
    for key, w in weights.items():
        if sh.get(key):
            pts += w
        else:
            notes.append(f"Missing {key}")
    categories.append(("Security Headers", pts, sum(weights.values()), notes))

    pts, notes = 0, []
    tls = scan.get("tls")
    if tls:
        if tls.get("days_left") is not None:
            if tls["days_left"] > 14:
                pts += 5
            else:
                notes.append(f"Certificate expires in {tls['days_left']} days")
        else:
            pts += 2
        proto = tls.get("protocol")
        if proto == "TLSv1.3":
            pts += 5
        elif proto == "TLSv1.2":
            pts += 4
            notes.append("Negotiated TLS 1.2 (TLS 1.3 not used)")
        else:
            notes.append(f"Weak/old protocol negotiated: {proto}")
        support = scan.get("tls_protocol_support") or {}
        if support.get("TLSv1.0") or support.get("TLSv1.1"):
            notes.append("Server still accepts TLS 1.0/1.1 (insecure legacy protocols)")
        else:
            pts += 5
    else:
        notes.append("Site not served over HTTPS")
    categories.append(("TLS / HTTPS", pts, 15, notes))

    pts, notes = 0, []
    ttfb = scan["home"].timings.get("ttfb_ms", 0)
    total = scan["home"].timings.get("total_ms", 0)
    if ttfb < 200:
        pts += 8
    elif ttfb < 600:
        pts += 5
        notes.append(f"TTFB is {ttfb:.0f}ms (good is <200ms)")
    else:
        notes.append(f"TTFB is {ttfb:.0f}ms (slow)")
    if total < 800:
        pts += 6
    elif total < 2000:
        pts += 3
        notes.append(f"Total response time {total:.0f}ms")
    else:
        notes.append(f"Total response time {total:.0f}ms (slow)")
    if scan["home"].headers.get("Content-Encoding", "") in ("gzip", "br", "deflate"):
        pts += 3
    else:
        notes.append("Response not compressed (no Content-Encoding)")
    if scan["caching"].get("Cache-Control"):
        pts += 3
    else:
        notes.append("No Cache-Control header on homepage")
    categories.append(("Performance", pts, 20, notes))

    wp = scan["wordpress"]
    if wp["is_wordpress"]:
        pts, notes = 0, []
        if not wp["version"]:
            pts += 4
        else:
            notes.append(f"WordPress version exposed: {wp['version']} ({wp['version_source']})")
        if wp["xmlrpc_enabled"] is False:
            pts += 4
        elif wp["xmlrpc_enabled"] is True:
            notes.append("xmlrpc.php is accessible (potential brute-force/DoS vector)")
        if not wp["users_exposed"]:
            pts += 4
        else:
            names = ", ".join(u["slug"] for u in wp["users_exposed"][:5] if u.get("slug"))
            notes.append(f"User accounts exposed via REST API: {names}")
        if not wp["readme_exposed"]:
            pts += 3
        else:
            notes.append("readme.html is publicly accessible")
        categories.append(("WordPress Hygiene", pts, 15, notes))
    else:
        categories.append(("WordPress Hygiene", None, 15, ["Not detected as WordPress"]))

    pts, notes = 0, []
    redirects = scan["redirects"]
    if scan["base_url"].startswith("https://"):
        if redirects.get("http_to_https"):
            pts += 5
        else:
            notes.append("HTTP does not redirect to HTTPS")
    else:
        notes.append("Site is not using HTTPS")
    if scan["not_found"]["is_404"]:
        pts += 5
    else:
        notes.append(f"Non-existent URL returned HTTP {scan['not_found']['status']} instead of 404")
    categories.append(("HTTP Behaviour", pts, 10, notes))

    pts, notes = 0, []
    seo = scan["seo_home"]
    if seo["title"]:
        pts += 4
        if not (10 <= len(seo["title"]) <= 65):
            notes.append(f"Title length is {len(seo['title'])} chars (recommended 10-65)")
    else:
        notes.append("Missing <title>")
    if seo["meta_description"]:
        pts += 4
        if not (50 <= len(seo["meta_description"]) <= 160):
            notes.append(f"Meta description length is {len(seo['meta_description'])} chars (recommended 50-160)")
    else:
        notes.append("Missing meta description")
    if len(seo["h1s"]) == 1:
        pts += 3
    elif len(seo["h1s"]) == 0:
        notes.append("No <h1> found")
    else:
        notes.append(f"{len(seo['h1s'])} <h1> tags found (recommended: 1)")
    if seo["viewport"]:
        pts += 3
    else:
        notes.append("Missing viewport meta tag (not mobile-optimized)")
    if scan["robots_sitemap"]["robots_txt"]:
        pts += 3
    else:
        notes.append("robots.txt not found")
    if scan["robots_sitemap"]["sitemap_exists"]:
        pts += 3
    else:
        notes.append("XML sitemap not found")
    categories.append(("SEO Basics", pts, 20, notes))

    total_earned = sum(p for _, p, _, _ in categories if p is not None)
    total_possible = sum(pp for _, p, pp, _ in categories if p is not None)
    score = round(100 * total_earned / total_possible) if total_possible else 0
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return {"categories": categories, "score": score, "grade": grade}


# ---------------------------------------------------------------------------
# Master diagnostic scan
# ---------------------------------------------------------------------------

def run_diagnostic_scan(base_url, log=None):
    parsed = urlparse(base_url)
    host = parsed.hostname

    def step(msg):
        if log:
            log(msg)

    step("Fetching homepage and timing the connection...")
    home = timed_fetch(base_url)
    scan = {"base_url": base_url, "host": host, "home": home}
    if home.error:
        scan["fatal_error"] = home.error
        return scan

    step("Resolving DNS records...")
    scan["dns"] = gather_dns(host)

    step("Checking security headers and caching behaviour...")
    scan["security_headers"] = fetch_security_headers(home.headers)
    scan["caching"] = analyze_caching(home.headers)
    scan["server_tech"] = detect_server_tech(home.headers)
    scan["cookies"] = analyze_cookies(home.headers)
    scan["cors"] = check_cors(home.headers)
    scan["mixed_content"] = check_mixed_content(base_url, home.text)
    scan["trackers"] = detect_trackers(home.text)

    step("Checking robots.txt, sitemap, and favicon...")
    scan["robots_sitemap"] = check_robots_and_sitemap(base_url)
    scan["favicon"] = check_favicon(base_url)

    step("Checking redirect behaviour (HTTP/HTTPS, www)...")
    scan["redirects"] = check_redirect_behavior(base_url)
    scan["not_found"] = check_404_handling(base_url)

    if home.tls:
        step("Inspecting TLS certificate and protocol support...")
        scan["tls"] = parse_cert(home.tls["cert"]) or {
            "subject": None, "issuer": None, "not_before": None,
            "not_after": None, "days_left": None, "sans": [],
        }
        scan["tls"]["protocol"] = home.tls["version"]
        scan["tls"]["cipher"] = home.tls["cipher"][0] if home.tls["cipher"] else None
        scan["tls_protocol_support"] = check_protocol_support(host)
        scan["alpn"] = check_alpn_h2(host)
    else:
        scan["tls"] = None
        scan["tls_protocol_support"] = None
        scan["alpn"] = None

    step("Fingerprinting WordPress core, theme, plugins, and users...")
    scan["wordpress"] = fingerprint_wordpress(base_url, home.text, home.headers)

    metas = parse_meta_tags(home.text)
    scan["seo_home"] = {
        "title": get_title(home.text),
        "meta_description": get_meta(metas, "description"),
        "viewport": get_meta(metas, "viewport"),
        "h1s": get_h1s(home.text),
        "jsonld_types": get_jsonld_types(home.text),
    }

    step("Computing health scorecard...")
    scan["health"] = compute_health_score(scan)
    return scan


# ---------------------------------------------------------------------------
# WordPress content inventory (REST API)
# ---------------------------------------------------------------------------

EXCLUDED_TYPES = {
    "attachment", "nav_menu_item", "wp_block", "wp_template",
    "wp_template_part", "wp_navigation", "wp_font_face", "wp_font_family",
    "wp_global_styles",
}


def fetch_wp_post_types(base_url):
    _, data = http_get_json(urljoin(base_url + '/', 'wp-json/wp/v2/types'))
    types = []
    if isinstance(data, dict):
        for slug, info in data.items():
            if not isinstance(info, dict) or slug in EXCLUDED_TYPES:
                continue
            if info.get("viewable", True):
                types.append({
                    "slug": slug,
                    "rest_base": info.get("rest_base") or slug,
                    "name": info.get("name", slug),
                })
    if not types:
        types = [
            {"slug": "post", "rest_base": "posts", "name": "Posts"},
            {"slug": "page", "rest_base": "pages", "name": "Pages"},
        ]
    return types


def fetch_taxonomy_map(base_url, taxonomy_rest_base):
    out = {}
    page = 1
    while True:
        url = f"{urljoin(base_url + '/', 'wp-json/wp/v2/' + taxonomy_rest_base)}?per_page=100&page={page}&_fields=id,name"
        result, data = http_get_json(url)
        if not isinstance(data, list) or not data:
            break
        for item in data:
            out[item.get("id")] = item.get("name")
        try:
            total_pages = int(result.headers.get("X-WP-TotalPages", "1") or "1")
        except ValueError:
            total_pages = 1
        if page >= total_pages:
            break
        page += 1
    return out


def fetch_items(base_url, rest_base, per_page=100, max_pages=50):
    items = []
    page = 1
    total_pages = 1
    while page <= total_pages and page <= max_pages:
        url = (f"{urljoin(base_url + '/', 'wp-json/wp/v2/' + rest_base)}"
               f"?per_page={per_page}&page={page}&_fields=id,date,link,title,categories,slug,type,status")
        result, data = http_get_json(url)
        if not isinstance(data, list) or not data:
            break
        items.extend(data)
        if page == 1:
            try:
                total_pages = int(result.headers.get("X-WP-TotalPages", "1") or "1")
            except ValueError:
                total_pages = 1
        page += 1
    return items, total_pages


def build_inventory(base_url, log=None):
    def step(msg):
        if log:
            log(msg)

    step("Discovering public post types...")
    types = fetch_wp_post_types(base_url)

    step("Fetching category names...")
    categories_map = fetch_taxonomy_map(base_url, "categories")

    seen = set()
    inventory = []
    truncated = []
    for t in types:
        step(f"Fetching all '{t['name']}' items via /wp-json/wp/v2/{t['rest_base']}...")
        items, total_pages = fetch_items(base_url, t["rest_base"])
        if total_pages > 50:
            truncated.append((t["name"], total_pages))
        for item in items:
            key = (t["slug"], item.get("id"))
            if key in seen:
                continue
            seen.add(key)
            cat_names = [categories_map.get(cid, str(cid)) for cid in (item.get("categories") or [])]
            title_obj = item.get("title")
            title = title_obj.get("rendered") if isinstance(title_obj, dict) else (title_obj or "")
            title = html_lib.unescape(re.sub(r'<[^>]+>', '', title)).strip()
            inventory.append({
                "id": item.get("id"),
                "type": t["slug"],
                "date": (item.get("date") or "")[:10],
                "categories": ", ".join(cat_names) if cat_names else "",
                "title": title or "(untitled)",
                "link": item.get("link"),
            })

    inventory.sort(key=lambda x: x["date"], reverse=True)
    return {"items": inventory, "types": types, "truncated": truncated}


# ---------------------------------------------------------------------------
# Analytics / SEO report
# ---------------------------------------------------------------------------

PSI_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
PSI_CATEGORIES = ["performance", "seo", "accessibility", "best-practices"]


def psi_lookup(url, strategy, timeout=30):
    qs = urlencode({"url": url, "strategy": strategy, "category": PSI_CATEGORIES}, doseq=True)
    full_url = f"{PSI_ENDPOINT}?{qs}"
    try:
        req = Request(full_url, headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=timeout, context=get_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"ok": False, "error": str(e)}

    lighthouse = data.get("lighthouseResult", {})
    categories = lighthouse.get("categories", {})
    audits = lighthouse.get("audits", {})

    scores = {}
    for val in categories.values():
        score = val.get("score")
        scores[val.get("title", "Unknown")] = round(score * 100) if score is not None else None

    def audit_val(key):
        return audits.get(key, {}).get("displayValue")

    metrics = {
        "First Contentful Paint": audit_val("first-contentful-paint"),
        "Largest Contentful Paint": audit_val("largest-contentful-paint"),
        "Total Blocking Time": audit_val("total-blocking-time"),
        "Cumulative Layout Shift": audit_val("cumulative-layout-shift"),
        "Speed Index": audit_val("speed-index"),
        "Time to Interactive": audit_val("interactive"),
    }
    return {"ok": True, "scores": scores, "metrics": metrics}


def custom_perf_scorecard(home_result):
    """Self-contained Lighthouse-style score, used when PSI is unreachable."""
    body = home_result.text
    timings = home_result.timings
    size_kb = len(home_result.body) / 1024
    scripts = len(re.findall(r'<script\b', body, re.I))
    stylesheets = len(re.findall(r'<link[^>]+rel=["\']stylesheet["\']', body, re.I))
    images, missing_alt = analyze_images(body)
    compressed = home_result.headers.get("Content-Encoding") in ("gzip", "br", "deflate")

    score = 100
    notes = []
    ttfb = timings.get("ttfb_ms", 0)
    total = timings.get("total_ms", 0)
    if ttfb > 600:
        score -= 20
        notes.append(f"High TTFB ({ttfb:.0f}ms)")
    elif ttfb > 200:
        score -= 8
    if total > 2000:
        score -= 20
        notes.append(f"Slow total load time ({total:.0f}ms)")
    elif total > 800:
        score -= 8
    if size_kb > 1500:
        score -= 15
        notes.append(f"Large HTML document ({size_kb:.0f} KB)")
    elif size_kb > 500:
        score -= 5
    if scripts > 25:
        score -= 10
        notes.append(f"{scripts} <script> tags on homepage")
    if not compressed:
        score -= 10
        notes.append("Response is not compressed")
    score = max(0, min(100, score))

    return {
        "ok": True,
        "source": "self-computed",
        "score": score,
        "details": {
            "page_size_kb": round(size_kb, 1),
            "scripts": scripts,
            "stylesheets": stylesheets,
            "images": images,
            "images_missing_alt": missing_alt,
            "compressed": compressed,
            "ttfb_ms": round(ttfb),
            "total_ms": round(total),
        },
        "notes": notes,
    }


def analyze_page_seo(url, host):
    result = timed_fetch(url)
    if result.error:
        return {"url": url, "error": result.error}

    body = result.text
    metas = parse_meta_tags(body)
    links = parse_link_tags(body)
    title = get_title(body)
    desc = get_meta(metas, "description")
    h1s = get_h1s(body)
    canonical = next((l.get("href") for l in links if l.get("rel", "").lower() == "canonical"), None)
    images, missing_alt = analyze_images(body)
    internal, external = analyze_links(body, host)
    og_count = sum(1 for m in metas if m.get("property", "").lower().startswith("og:"))
    twitter_count = sum(1 for m in metas if m.get("name", "").lower().startswith("twitter:"))
    jsonld = get_jsonld_types(body)
    wc = word_count(body)

    issues = []
    if not title:
        issues.append("Missing <title>")
    elif not (10 <= len(title) <= 65):
        issues.append(f"Title length {len(title)} (recommended 10-65)")
    if not desc:
        issues.append("Missing meta description")
    elif not (50 <= len(desc) <= 160):
        issues.append(f"Meta description length {len(desc)} (recommended 50-160)")
    if len(h1s) != 1:
        issues.append(f"{len(h1s)} <h1> tags (recommended: 1)")
    if not canonical:
        issues.append("Missing canonical link")
    if missing_alt:
        issues.append(f"{missing_alt}/{images} images missing alt text")
    if wc < 300:
        issues.append(f"Low word count ({wc})")
    if not og_count:
        issues.append("No Open Graph tags")

    return {
        "url": url,
        "status": result.status,
        "ttfb_ms": round(result.timings.get("ttfb_ms", 0)),
        "total_ms": round(result.timings.get("total_ms", 0)),
        "size_kb": round(len(result.body) / 1024, 1),
        "title": title,
        "title_len": len(title) if title else 0,
        "meta_description": desc,
        "desc_len": len(desc) if desc else 0,
        "h1_count": len(h1s),
        "canonical": canonical,
        "images": images,
        "images_missing_alt": missing_alt,
        "internal_links": internal,
        "external_links": external,
        "og_tags": og_count,
        "twitter_tags": twitter_count,
        "jsonld_types": jsonld,
        "word_count": wc,
        "issues": issues,
    }


def run_analytics(base_url, home_result, inventory_items, max_pages=10, use_psi=True, log=None):
    def step(msg):
        if log:
            log(msg)

    host = urlparse(base_url).hostname

    psi = {"mobile": None, "desktop": None}
    if use_psi:
        for strategy in ("mobile", "desktop"):
            step(f"Requesting Google PageSpeed Insights ({strategy})...")
            psi[strategy] = psi_lookup(base_url, strategy)

    fallback = None
    psi_ok = any(psi[s] and psi[s].get("ok") for s in ("mobile", "desktop"))
    if not psi_ok:
        step("PageSpeed Insights unavailable - computing self-contained performance scorecard...")
        fallback = custom_perf_scorecard(home_result)

    home_url = base_url if base_url.endswith("/") else base_url + "/"
    urls_to_check = [home_url]
    seen_urls = {home_url}
    total_candidates = len(inventory_items)
    for item in inventory_items:
        link = item.get("link")
        if link and link not in seen_urls:
            urls_to_check.append(link)
            seen_urls.add(link)
        if len(urls_to_check) - 1 >= max_pages:
            break

    skipped = max(0, total_candidates - max_pages)

    page_reports = []
    for url in urls_to_check:
        step(f"Analyzing on-page SEO: {url}")
        page_reports.append(analyze_page_seo(url, host))

    return {
        "psi": psi,
        "fallback": fallback,
        "pages": page_reports,
        "pages_analyzed": len(page_reports),
        "pages_total": total_candidates + 1,
        "pages_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

def flag_bad_if_true(value):
    if value is None:
        return c("unknown", C.GRAY)
    return c("YES", C.RED) if value else c("NO", C.GREEN)


def tls_support_label(value, accepted_is_good):
    if value is None:
        return c("not tested", C.GRAY)
    if value:
        return c("ACCEPTED", C.GREEN if accepted_is_good else C.RED)
    return c("rejected", C.RED if accepted_is_good else C.GREEN)


def print_header(text):
    width = 78
    print()
    print(c("=" * width, C.CYAN))
    print(c(text.center(width), C.BOLD + C.CYAN))
    print(c("=" * width, C.CYAN))


def print_section(text):
    print()
    print(c(f"-- {text} " + "-" * max(0, 74 - len(text)), C.BLUE + C.BOLD))


def print_kv(label, value, color=None):
    text = c(value, color) if color else value
    print(f"  {label:<32} {text}")


def print_table(headers, rows, color_fn=None):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    widths = [min(w, 60) for w in widths]

    header_line = "  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(c(header_line, C.BOLD))
    print("  " + "  ".join("-" * w for w in widths))
    for ri, row in enumerate(rows):
        cells = []
        for ci, cell in enumerate(row):
            text = str(cell)
            if len(text) > widths[ci]:
                text = text[:widths[ci] - 1] + "…"
            text = text.ljust(widths[ci])
            if color_fn:
                col = color_fn(ri, ci, cell)
                if col:
                    text = c(text, col)
            cells.append(text)
        print("  " + "  ".join(cells))


# ---------------------------------------------------------------------------
# Diagnostic scan: terminal report
# ---------------------------------------------------------------------------

def print_scan_report(scan):
    print_header(f"DIAGNOSTIC SCAN: {scan['base_url']}")
    if scan.get("fatal_error"):
        print(c(f"  Could not connect: {scan['fatal_error']}", C.RED))
        return

    home = scan["home"]

    print_section("Timing Metrics")
    t = home.timings
    print_table(
        ["Phase", "Time (ms)"],
        [
            ["DNS Lookup", f"{t.get('dns_ms', 0):.1f}"],
            ["TCP Connect", f"{t.get('connect_ms', 0):.1f}"],
            ["TLS Handshake", f"{t.get('tls_ms', 0):.1f}"],
            ["Time to First Byte", f"{t.get('ttfb_ms', 0):.1f}"],
            ["Download", f"{t.get('download_ms', 0):.1f}"],
            ["Total", f"{t.get('total_ms', 0):.1f}"],
        ],
    )

    print_section("HTTP Response")
    print_kv("Status", str(home.status), status_color(home.status))
    print_kv("Final URL", home.url)
    if len(home.redirect_chain) > 1:
        chain_str = " -> ".join(f"{u} ({s})" for u, s in home.redirect_chain)
        print_kv("Redirect Chain", chain_str)
    print_kv("Content-Type", home.headers.get("Content-Type", "-"))
    print_kv("Content-Length", f"{len(home.body):,} bytes")
    print_kv("Content-Encoding", home.headers.get("Content-Encoding", "none"))

    print_section("Server / Technology")
    tech = scan["server_tech"]
    for k, v in tech.items():
        print_kv(k, v if v else c("not disclosed", C.GRAY))
    print_kv("ALPN Protocol", scan["alpn"] or c("none", C.GRAY))
    print_kv("HTTP/2 Supported", yesno(scan["alpn"] == "h2", warn_if_false=True))

    print_section("Caching Behaviour")
    for k, v in scan["caching"].items():
        print_kv(k, v if v else c("not set", C.GRAY))

    print_section("Security Headers")
    for k, v in scan["security_headers"].items():
        if v:
            shown = v if len(v) <= 60 else v[:57] + "..."
            print_kv(k, shown, C.GREEN)
        else:
            print_kv(k, "MISSING", C.RED)

    print_section("Cookies")
    if scan["cookies"]:
        print_table(
            ["Name", "Secure", "HttpOnly", "SameSite"],
            [[ck["name"], yesno(ck["secure"], True), yesno(ck["httponly"], True), yesno(ck["samesite"], True)]
             for ck in scan["cookies"]],
        )
    else:
        print(c("  No cookies set on homepage response", C.GRAY))

    print_section("CORS & Mixed Content")
    print_kv("Access-Control-Allow-Origin", scan["cors"] or c("not set", C.GRAY))
    if scan["mixed_content"]:
        print_kv("Mixed Content (http:// refs)", c(f"{len(scan['mixed_content'])} found", C.RED))
        for ref in scan["mixed_content"][:5]:
            print(f"      http://{ref}")
    else:
        print_kv("Mixed Content", c("none detected", C.GREEN))

    print_section("TLS / SSL Certificate")
    tls = scan["tls"]
    if tls:
        print_kv("Protocol", tls.get("protocol") or "-")
        print_kv("Cipher", tls.get("cipher") or "-")
        print_kv("Subject", tls.get("subject") or "-")
        print_kv("Issuer", tls.get("issuer") or "-")
        print_kv("Valid Until", tls.get("not_after") or "-")
        days = tls.get("days_left")
        if days is not None:
            color = C.GREEN if days > 30 else (C.YELLOW if days > 7 else C.RED)
            print_kv("Days Until Expiry", str(days), color)
        sans = tls.get("sans") or []
        sans_str = ", ".join(sans[:5]) + (f" (+{len(sans) - 5} more)" if len(sans) > 5 else "")
        print_kv("Subject Alt Names", sans_str or "-")
        support = scan["tls_protocol_support"] or {}
        print_kv("TLS 1.0 (legacy)", tls_support_label(support.get("TLSv1.0"), accepted_is_good=False))
        print_kv("TLS 1.1 (legacy)", tls_support_label(support.get("TLSv1.1"), accepted_is_good=False))
        print_kv("TLS 1.2", tls_support_label(support.get("TLSv1.2"), accepted_is_good=True))
        print_kv("TLS 1.3", tls_support_label(support.get("TLSv1.3"), accepted_is_good=True))
    else:
        print(c("  Site is not served over HTTPS", C.RED))

    print_section("DNS Records")
    dns = scan["dns"]
    for rec in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
        vals = dns.get(rec) or []
        print_kv(rec, "; ".join(vals) if vals else c("none", C.GRAY))
    print_kv("Reverse DNS (PTR)", dns.get("PTR") or c("none", C.GRAY))

    print_section("Robots.txt, Sitemap, Favicon & Redirects")
    rs = scan["robots_sitemap"]
    rd = scan["redirects"]
    print_kv("robots.txt present", yesno(rs["robots_txt"], True))
    print_kv("Declared Sitemaps", ", ".join(rs["sitemaps_declared"]) if rs["sitemaps_declared"] else c("none declared", C.GRAY))
    print_kv("Sitemap reachable", yesno(rs["sitemap_exists"], True))
    if rs["sitemap_entry_count"] is not None:
        print_kv("Sitemap entries", str(rs["sitemap_entry_count"]))
    print_kv("favicon.ico present", yesno(scan["favicon"], True))
    print_kv("HTTP redirects to HTTPS", yesno(rd["http_to_https"]))
    alt_status = f"{rd['alt_host_status']}" + (f" -> {rd['alt_host_redirects_to']}" if rd["alt_host_redirects_to"] else "")
    print_kv(f"{rd['alt_host']} status", alt_status)
    print_kv("Unknown URL returns 404", yesno(scan["not_found"]["is_404"]))
    print_kv("  (actual status seen)", str(scan["not_found"]["status"]), C.GRAY)

    print_section("Traffic, Visitors & Server Load")
    if scan["trackers"]:
        print("  Detected analytics/tracking scripts:")
        for tr in scan["trackers"]:
            print(f"    - {tr}")
    else:
        print(c("  No analytics/tracking scripts detected in homepage HTML.", C.GRAY))
    print(c("  Visitor counts and CPU/memory load are not measurable externally over", C.GRAY))
    print(c("  HTTP - they require access to the site's analytics platform or hosting", C.GRAY))
    print(c("  dashboard (Google Analytics, Jetpack Stats, server logs, top/htop, etc.)", C.GRAY))

    print_section("WordPress Fingerprint")
    wp = scan["wordpress"]
    print_kv("Detected as WordPress", yesno(wp["is_wordpress"]))
    if wp["is_wordpress"]:
        print_kv("Site Name", wp["site_name"] or "-")
        if wp["version"]:
            print_kv("WordPress Version", c(wp["version"], C.YELLOW) + c(f"  (via {wp['version_source']})", C.GRAY))
        else:
            print_kv("WordPress Version", c("hidden", C.GREEN))
        if wp["theme"]:
            print_kv("Active Theme", f"{wp['theme']['slug']} ({wp['theme']['version'] or 'version hidden'})")
        else:
            print_kv("Active Theme", c("not detected", C.GRAY))
        print_kv("REST API enabled", yesno(wp["rest_api_enabled"]))
        print_kv("XML-RPC (xmlrpc.php) reachable", flag_bad_if_true(wp["xmlrpc_enabled"]))
        print_kv("readme.html exposed", flag_bad_if_true(wp["readme_exposed"]))
        print_kv("wp-login.php reachable", yesno(wp["wp_login_exists"]))

        if wp["plugins"]:
            print_section("Detected Plugins / Components")
            rows = [[slug, ver or c("version hidden", C.GRAY)] for slug, ver in wp["plugins"].items()]
            print_table(["Plugin / Component", "Version"], rows)

        if wp["users_exposed"]:
            print_section("Exposed User Accounts (wp-json/wp/v2/users)")
            print_table(
                ["ID", "Display Name", "Username/Slug"],
                [[u["id"], u["name"], u["slug"]] for u in wp["users_exposed"]],
            )

    print_section("Health Scorecard")
    health = scan["health"]
    grade_color = {"A": C.GREEN, "B": C.GREEN, "C": C.YELLOW, "D": C.YELLOW, "F": C.RED}[health["grade"]]
    print(f"  Overall Score: {c(str(health['score']) + '/100', C.BOLD)}   Grade: {c(health['grade'], grade_color + C.BOLD)}")
    print()
    for name, earned, possible, notes in health["categories"]:
        if earned is None:
            print(f"  {name:<24} {c('N/A', C.GRAY)}")
            continue
        pct = earned / possible if possible else 0
        color = C.GREEN if pct >= 0.8 else (C.YELLOW if pct >= 0.5 else C.RED)
        print(f"  {name:<24} {c(f'{earned}/{possible}', color)}")
        for note in notes:
            print(c(f"      - {note}", C.GRAY))


# ---------------------------------------------------------------------------
# Content inventory: terminal report
# ---------------------------------------------------------------------------

def print_inventory_report(inventory):
    print_header("WORDPRESS CONTENT INVENTORY")
    items = inventory["items"]
    print_kv("Total Items (de-duplicated)", str(len(items)))

    types_summary = {}
    for item in items:
        types_summary[item["type"]] = types_summary.get(item["type"], 0) + 1
    print_kv("By Type", ", ".join(f"{k}: {v}" for k, v in types_summary.items()) or c("none found", C.GRAY))

    for name, total_pages in inventory["truncated"]:
        print(c(f"  Note: '{name}' has {total_pages} pages of results; only the first 50 pages "
                f"(~5000 items) were fetched.", C.YELLOW))

    if not items:
        print(c("\n  No posts or pages were returned by the REST API.", C.GRAY))
        return

    print()
    rows = [[it["id"], it["type"], it["date"], it["categories"] or "-", it["title"]] for it in items]
    print_table(["ID", "Type", "Date", "Category", "Title"], rows)


# ---------------------------------------------------------------------------
# Analytics / SEO report: terminal report
# ---------------------------------------------------------------------------

def print_analytics_report(analytics, base_url):
    print_header(f"ANALYTICS & SEO REPORT: {base_url}")

    print_section("PageSpeed Insights / Lighthouse")
    any_psi = False
    for strategy in ("mobile", "desktop"):
        result = analytics["psi"].get(strategy)
        if result and result.get("ok"):
            any_psi = True
            print(c(f"  {strategy.capitalize()}:", C.BOLD))
            for name, score in result["scores"].items():
                if score is None:
                    continue
                color = C.GREEN if score >= 90 else (C.YELLOW if score >= 50 else C.RED)
                print(f"    {name:<22} {c(str(score) + '/100', color)}")
            for name, val in result["metrics"].items():
                if val:
                    print(f"    {name:<22} {val}")
            print()
        elif result:
            print(c(f"  {strategy.capitalize()}: PSI unavailable ({result.get('error')})", C.GRAY))

    if analytics["fallback"]:
        fb = analytics["fallback"]
        score = fb["score"]
        color = C.GREEN if score >= 90 else (C.YELLOW if score >= 50 else C.RED)
        print(c(f"  Self-computed performance score: {score}/100  (source: {fb['source']})", C.BOLD))
        for k, v in fb["details"].items():
            print_kv(f"    {k}", str(v))
        for note in fb["notes"]:
            print(c(f"      - {note}", C.GRAY))
    elif not any_psi:
        print(c("  No performance data available.", C.GRAY))

    print_section(f"Per-Page SEO Breakdown ({analytics['pages_analyzed']} of {analytics['pages_total']} pages)")
    if analytics["pages_skipped"]:
        print(c(f"  Note: {analytics['pages_skipped']} additional page(s) were not analyzed "
                f"(limit reached). Use --max-pages to increase.", C.YELLOW))

    for page in analytics["pages"]:
        if page.get("error"):
            print(c(f"\n  {page['url']}: ERROR - {page['error']}", C.RED))
            continue
        print(f"\n  {c(page['url'], C.BOLD + C.CYAN)}  [{c(str(page['status']), status_color(page['status']))}]")
        if page["title"]:
            print_kv("    Title", f"{page['title']} ({page['title_len']} chars)")
        else:
            print_kv("    Title", c("missing", C.RED))
        if page["meta_description"]:
            print_kv("    Meta Description", f"present ({page['desc_len']} chars)")
        else:
            print_kv("    Meta Description", c("missing", C.RED))
        print_kv("    H1 Count", str(page["h1_count"]))
        print_kv("    Word Count", str(page["word_count"]))
        print_kv("    Images (missing alt)", f"{page['images']} ({page['images_missing_alt']})")
        print_kv("    Internal / External Links", f"{page['internal_links']} / {page['external_links']}")
        print_kv("    Open Graph / Twitter tags", f"{page['og_tags']} / {page['twitter_tags']}")
        print_kv("    Structured Data (JSON-LD)", ", ".join(page["jsonld_types"]) if page["jsonld_types"] else c("none", C.GRAY))
        print_kv("    Load Time (TTFB / total)", f"{page['ttfb_ms']}ms / {page['total_ms']}ms")
        if page["issues"]:
            print(c(f"    Issues: {'; '.join(page['issues'])}", C.YELLOW))
        else:
            print(c("    Issues: none", C.GREEN))


# ---------------------------------------------------------------------------
# HTML report: helpers and styling
# ---------------------------------------------------------------------------

HTML_CSS = """
:root {
  --bg: #0f1117; --panel: #181b25; --border: #2a2e3d; --text: #e6e8ef;
  --muted: #8b91a7; --accent: #5b8cff; --good: #36d399; --warn: #fbbd23;
  --bad: #f87272; --neutral: #8b91a7;
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--text); margin: 0; padding: 0 0 4rem;
}
.header { background: linear-gradient(135deg, #1c2333, #11141d); padding: 2.5rem 2rem; border-bottom: 1px solid var(--border); }
.header h1 { margin: 0 0 .25rem; font-size: 1.8rem; }
.header .meta { color: var(--muted); font-size: .9rem; }
.container { max-width: 1100px; margin: 0 auto; padding: 0 1.5rem; }
.section { margin-top: 2rem; }
.section h2 { font-size: 1.2rem; border-bottom: 2px solid var(--accent); padding-bottom: .4rem; margin-bottom: 1rem; }
.section h3 { font-size: 1rem; color: var(--muted); margin: 1.2rem 0 .5rem; }
table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: .9rem; }
th, td { border: 1px solid var(--border); padding: .45rem .6rem; text-align: left; vertical-align: top; }
thead th { background: var(--panel); color: var(--accent); }
table.kv th { width: 280px; color: var(--muted); font-weight: 500; background: transparent; }
table.kv tr:nth-child(odd) td, table.kv tr:nth-child(odd) th { background: rgba(255,255,255,.02); }
a { color: var(--accent); }
.badge { display: inline-block; padding: .1rem .55rem; border-radius: 999px; font-size: .75rem; font-weight: 600; }
.badge.good { background: rgba(54,211,153,.15); color: var(--good); }
.badge.warn { background: rgba(251,189,35,.15); color: var(--warn); }
.badge.bad { background: rgba(248,114,114,.15); color: var(--bad); }
.badge.neutral { background: rgba(139,145,167,.15); color: var(--neutral); }
.scorecard { display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap; margin-bottom: 1.5rem; }
.score-circle {
  width: 110px; height: 110px; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; flex-direction: column; border: 6px solid var(--accent); font-size: 1.8rem; font-weight: 700;
}
.score-circle small { font-size: .7rem; color: var(--muted); font-weight: 400; }
.cat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
.cat-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
.cat-card h4 { margin: 0 0 .4rem; display: flex; justify-content: space-between; align-items: center; }
.cat-card ul { margin: .5rem 0 0; padding-left: 1.1rem; color: var(--muted); font-size: .85rem; }
.notes-list { color: var(--muted); font-size: .85rem; }
.pill-row { display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: 1rem; }
.pill { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: .5rem .9rem; font-size: .85rem; }
.pill b { display: block; font-size: 1.1rem; }
.page-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
.page-card h4 { margin: 0 0 .5rem; word-break: break-all; }
.footer { text-align: center; color: var(--muted); font-size: .8rem; margin-top: 3rem; }
"""


def esc(x):
    return html_lib.escape("" if x is None else str(x), quote=True)


def badge(text, kind):
    return f'<span class="badge {kind}">{esc(text)}</span>'


def badge_yesno(value, warn_if_false=False):
    if value is None:
        return badge("UNKNOWN", "neutral")
    return badge("YES", "good") if value else badge("NO", "warn" if warn_if_false else "bad")


def badge_bad_if_true(value):
    if value is None:
        return badge("UNKNOWN", "neutral")
    return badge("YES", "bad") if value else badge("NO", "good")


def proto_support_badge(value, accepted_is_good):
    if value is None:
        return badge("not tested", "neutral")
    label = "ACCEPTED" if value else "rejected"
    is_good = (value == accepted_is_good)
    return badge(label, "good" if is_good else "bad")


def html_table(headers, rows):
    """`headers` are plain strings (escaped here); `rows` cells must already
    be safe HTML (use esc() or badge() before passing them in)."""
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>'


def html_kv_table(pairs):
    """`pairs` is a list of (label, value) where value must already be safe HTML."""
    rows = "".join(f"<tr><th>{esc(k)}</th><td>{v}</td></tr>" for k, v in pairs)
    return f'<table class="kv">{rows}</table>'


# ---------------------------------------------------------------------------
# HTML report: diagnostic scan section
# ---------------------------------------------------------------------------

def render_scan_html(scan):
    if scan.get("fatal_error"):
        return (f"<div class='section'><h2>Diagnostic Scan</h2>"
                f"<p class='notes-list'>Could not connect: {esc(scan['fatal_error'])}</p></div>")

    home = scan["home"]
    t = home.timings
    parts = []

    health = scan["health"]
    grade_class = {"A": "good", "B": "good", "C": "warn", "D": "warn", "F": "bad"}[health["grade"]]
    cat_cards = []
    for name, earned, possible, notes in health["categories"]:
        if earned is None:
            cat_cards.append(f"<div class='cat-card'><h4>{esc(name)} {badge('N/A', 'neutral')}</h4></div>")
            continue
        pct = earned / possible if possible else 0
        cls = "good" if pct >= 0.8 else ("warn" if pct >= 0.5 else "bad")
        notes_html = "".join(f"<li>{esc(n)}</li>" for n in notes) or "<li>No issues found</li>"
        cat_cards.append(
            f"<div class='cat-card'><h4>{esc(name)} {badge(f'{earned}/{possible}', cls)}</h4>"
            f"<ul>{notes_html}</ul></div>"
        )
    parts.append(f"""<div class="section">
      <h2>Health Scorecard</h2>
      <div class="scorecard">
        <div class="score-circle">{health['score']}<small>/ 100</small></div>
        <div>{badge('Grade ' + health['grade'], grade_class)}</div>
      </div>
      <div class="cat-grid">{''.join(cat_cards)}</div>
    </div>""")

    parts.append("<div class='section'><h2>Timing Metrics</h2>" + html_table(
        ["Phase", "Time (ms)"],
        [
            [esc("DNS Lookup"), esc(f"{t.get('dns_ms', 0):.1f}")],
            [esc("TCP Connect"), esc(f"{t.get('connect_ms', 0):.1f}")],
            [esc("TLS Handshake"), esc(f"{t.get('tls_ms', 0):.1f}")],
            [esc("Time to First Byte"), esc(f"{t.get('ttfb_ms', 0):.1f}")],
            [esc("Download"), esc(f"{t.get('download_ms', 0):.1f}")],
            [esc("Total"), esc(f"{t.get('total_ms', 0):.1f}")],
        ],
    ) + "</div>")

    redirect_html = ""
    if len(home.redirect_chain) > 1:
        chain_str = " &rarr; ".join(f"{esc(u)} ({s})" for u, s in home.redirect_chain)
        redirect_html = f"<p class='notes-list'>Redirect chain: {chain_str}</p>"

    tech = scan["server_tech"]
    parts.append("<div class='section'><h2>HTTP Response &amp; Server</h2>" + redirect_html + html_kv_table([
        ("Status", badge(str(home.status), "good" if home.status and home.status < 400 else "bad")),
        ("Final URL", esc(home.url)),
        ("Content-Type", esc(home.headers.get("Content-Type", "-"))),
        ("Content-Length", esc(f"{len(home.body):,} bytes")),
        ("Content-Encoding", esc(home.headers.get("Content-Encoding", "none"))),
        ("Server", esc(tech["Server"]) if tech["Server"] else "not disclosed"),
        ("X-Powered-By", esc(tech["X-Powered-By"]) if tech["X-Powered-By"] else "not disclosed"),
        ("CDN / Proxy", esc(tech["CDN/Proxy"]) if tech["CDN/Proxy"] else "none detected"),
        ("ALPN Protocol", esc(scan["alpn"]) if scan["alpn"] else "none"),
        ("HTTP/2 Supported", badge_yesno(scan["alpn"] == "h2", warn_if_false=True)),
    ]) + "</div>")

    parts.append("<div class='section'><h2>Caching Behaviour</h2>" + html_kv_table(
        [(k, esc(v) if v else "not set") for k, v in scan["caching"].items()]
    ) + "</div>")

    sec_rows = [(k, esc(v) if v else badge("MISSING", "bad")) for k, v in scan["security_headers"].items()]
    parts.append("<div class='section'><h2>Security Headers</h2>" + html_kv_table(sec_rows) + "</div>")

    if scan["cookies"]:
        cookie_rows = [
            [esc(ck["name"]), badge_yesno(ck["secure"], True), badge_yesno(ck["httponly"], True), badge_yesno(ck["samesite"], True)]
            for ck in scan["cookies"]
        ]
        cookies_html = html_table(["Name", "Secure", "HttpOnly", "SameSite"], cookie_rows)
    else:
        cookies_html = "<p class='notes-list'>No cookies set on homepage response.</p>"
    parts.append("<div class='section'><h2>Cookies</h2>" + cookies_html + "</div>")

    mixed_html = "<p class='notes-list'>None detected.</p>"
    if scan["mixed_content"]:
        items_html = "".join(f"<li>http://{esc(x)}</li>" for x in scan["mixed_content"])
        mixed_html = f"<ul class='notes-list'>{items_html}</ul>"
    parts.append("<div class='section'><h2>CORS &amp; Mixed Content</h2>" + html_kv_table([
        ("Access-Control-Allow-Origin", esc(scan["cors"]) if scan["cors"] else "not set"),
    ]) + f"<h3>Mixed Content (HTTP resources on an HTTPS page)</h3>{mixed_html}</div>")

    tls = scan["tls"]
    if tls:
        support = scan["tls_protocol_support"] or {}
        days = tls.get("days_left")
        days_cls = "good" if (days is not None and days > 30) else ("warn" if (days is not None and days > 7) else "bad")
        tls_rows = [
            ("Negotiated Protocol", esc(tls.get("protocol")) or "-"),
            ("Cipher Suite", esc(tls.get("cipher")) or "-"),
            ("Subject", esc(tls.get("subject")) or "-"),
            ("Issuer", esc(tls.get("issuer")) or "-"),
            ("Valid From", esc(tls.get("not_before")) or "-"),
            ("Valid Until", esc(tls.get("not_after")) or "-"),
            ("Days Until Expiry", badge(str(days), days_cls) if days is not None else "unknown"),
            ("Subject Alt Names", esc(", ".join(tls.get("sans") or []))),
            ("TLS 1.0 (legacy)", proto_support_badge(support.get("TLSv1.0"), accepted_is_good=False)),
            ("TLS 1.1 (legacy)", proto_support_badge(support.get("TLSv1.1"), accepted_is_good=False)),
            ("TLS 1.2", proto_support_badge(support.get("TLSv1.2"), accepted_is_good=True)),
            ("TLS 1.3", proto_support_badge(support.get("TLSv1.3"), accepted_is_good=True)),
        ]
        tls_html = html_kv_table(tls_rows)
    else:
        tls_html = "<p class='notes-list'>Site is not served over HTTPS.</p>"
    parts.append(f"<div class='section'><h2>TLS / SSL Certificate</h2>{tls_html}</div>")

    dns = scan["dns"]
    dns_rows = []
    for rec in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
        vals = dns.get(rec) or []
        dns_rows.append((rec, esc("; ".join(vals)) if vals else "none"))
    dns_rows.append(("Reverse DNS (PTR)", esc(dns.get("PTR")) if dns.get("PTR") else "none"))
    parts.append("<div class='section'><h2>DNS Records</h2>" + html_kv_table(dns_rows) + "</div>")

    rs = scan["robots_sitemap"]
    rd = scan["redirects"]
    alt_status = esc(rd["alt_host_status"])
    if rd["alt_host_redirects_to"]:
        alt_status += f" &rarr; {esc(rd['alt_host_redirects_to'])}"
    misc_rows = [
        ("robots.txt present", badge_yesno(rs["robots_txt"], True)),
        ("Declared Sitemaps", esc(", ".join(rs["sitemaps_declared"])) if rs["sitemaps_declared"] else "none declared"),
        ("Sitemap reachable", badge_yesno(rs["sitemap_exists"], True)),
        ("Sitemap entries", esc(rs["sitemap_entry_count"]) if rs["sitemap_entry_count"] is not None else "-"),
        ("favicon.ico present", badge_yesno(scan["favicon"], True)),
        ("HTTP redirects to HTTPS", badge_yesno(rd["http_to_https"])),
        (f"{esc(rd['alt_host'])} status", alt_status),
        ("Unknown URL returns HTTP 404", badge_yesno(scan["not_found"]["is_404"])),
        ("Actual status for unknown URL", esc(scan["not_found"]["status"])),
    ]
    parts.append("<div class='section'><h2>Robots, Sitemap &amp; Redirects</h2>" + html_kv_table(misc_rows) + "</div>")

    if scan["trackers"]:
        tr_html = "<ul>" + "".join(f"<li>{esc(t)}</li>" for t in scan["trackers"]) + "</ul>"
    else:
        tr_html = "<p class='notes-list'>No analytics/tracking scripts detected in the homepage HTML.</p>"
    parts.append(f"""<div class="section">
      <h2>Traffic, Visitors &amp; Server Load</h2>
      <h3>Detected Analytics / Tracking Scripts</h3>
      {tr_html}
      <h3>Visitor counts, CPU &amp; memory load</h3>
      <p class="notes-list">Not measurable externally over HTTP. Visitor/page-hit metrics live in the
      site's analytics platform (Google Analytics, Jetpack Stats, server logs, etc.), and CPU/memory load
      requires hosting-panel or SSH access (New Relic, <code>top</code>, <code>htop</code>, etc.). This
      scan can only detect whether a tracking script is present, shown above.</p>
    </div>""")

    wp = scan["wordpress"]
    if wp["is_wordpress"]:
        if wp["version"]:
            version_cell = f"{esc(wp['version'])} <span class='notes-list'>(via {esc(wp['version_source'])})</span>"
        else:
            version_cell = badge("hidden", "good")
        theme_cell = (f"{esc(wp['theme']['slug'])} ({esc(wp['theme']['version']) if wp['theme']['version'] else 'version hidden'})"
                      if wp["theme"] else "not detected")
        wp_rows = [
            ("Site Name", esc(wp["site_name"]) or "-"),
            ("Site Description", esc(wp["site_description"]) or "-"),
            ("WordPress Version", version_cell),
            ("Active Theme", theme_cell),
            ("REST API enabled", badge_yesno(wp["rest_api_enabled"])),
            ("XML-RPC (xmlrpc.php) reachable", badge_bad_if_true(wp["xmlrpc_enabled"])),
            ("readme.html exposed", badge_bad_if_true(wp["readme_exposed"])),
            ("wp-login.php reachable", badge_yesno(wp["wp_login_exists"])),
        ]
        wp_html = html_kv_table(wp_rows)
        if wp["plugins"]:
            plugin_rows = [[esc(slug), esc(ver) if ver else "version hidden"] for slug, ver in wp["plugins"].items()]
            wp_html += "<h3>Detected Plugins / Components</h3>" + html_table(["Plugin / Component", "Version"], plugin_rows)
        if wp["users_exposed"]:
            user_rows = [[esc(u["id"]), esc(u["name"]), esc(u["slug"])] for u in wp["users_exposed"]]
            wp_html += ("<h3>Exposed User Accounts (wp-json/wp/v2/users)</h3>"
                        + html_table(["ID", "Display Name", "Username/Slug"], user_rows))
    else:
        wp_html = "<p class='notes-list'>This site was not detected as running WordPress.</p>"
    parts.append(f"<div class='section'><h2>WordPress Fingerprint</h2>{wp_html}</div>")

    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML report: content inventory section
# ---------------------------------------------------------------------------

def render_inventory_html(inventory):
    items = inventory["items"]
    types_summary = {}
    for item in items:
        types_summary[item["type"]] = types_summary.get(item["type"], 0) + 1

    pills = "".join(f"<div class='pill'><b>{v}</b>{esc(k)}</div>" for k, v in types_summary.items())
    pills = f"<div class='pill-row'><div class='pill'><b>{len(items)}</b>Total items</div>{pills}</div>"

    notes = ""
    if inventory["truncated"]:
        li = "".join(f"<li>{esc(name)}: {pages} pages of results, only first 50 pages fetched</li>"
                      for name, pages in inventory["truncated"])
        notes = f"<ul class='notes-list'>{li}</ul>"

    if not items:
        return f"<div class='section'><h2>WordPress Content Inventory</h2>{pills}{notes}<p class='notes-list'>No posts or pages were returned by the REST API.</p></div>"

    rows = []
    for it in items:
        if it.get("link"):
            title_cell = f'<a href="{esc(it["link"])}" target="_blank" rel="noopener">{esc(it["title"])}</a>'
        else:
            title_cell = esc(it["title"])
        rows.append([esc(it["id"]), esc(it["type"]), esc(it["date"]), esc(it["categories"] or "-"), title_cell])

    table_html = html_table(["ID", "Type", "Date", "Category", "Title"], rows)
    return f"<div class='section'><h2>WordPress Content Inventory</h2>{pills}{notes}{table_html}</div>"


# ---------------------------------------------------------------------------
# HTML report: analytics / SEO section
# ---------------------------------------------------------------------------

def render_analytics_html(analytics, base_url):
    parts = ["<div class='section'><h2>Analytics &amp; SEO Report</h2>"]

    any_psi = False
    for strategy in ("mobile", "desktop"):
        result = analytics["psi"].get(strategy)
        if result and result.get("ok"):
            any_psi = True
            score_pills = "".join(
                f"<div class='pill'><b>{v}</b>{esc(k)}</div>"
                for k, v in result["scores"].items() if v is not None
            )
            metric_rows = [(k, esc(v)) for k, v in result["metrics"].items() if v]
            parts.append(f"<h3>Lighthouse ({esc(strategy.capitalize())}) via PageSpeed Insights</h3>")
            parts.append(f"<div class='pill-row'>{score_pills}</div>")
            parts.append(html_kv_table(metric_rows))
        elif result:
            parts.append(f"<h3>Lighthouse ({esc(strategy.capitalize())})</h3>"
                          f"<p class='notes-list'>PageSpeed Insights unavailable: {esc(result.get('error'))}</p>")

    if analytics["fallback"]:
        fb = analytics["fallback"]
        score_cls = "good" if fb["score"] >= 90 else ("warn" if fb["score"] >= 50 else "bad")
        detail_rows = [(k.replace("_", " ").title(), esc(v)) for k, v in fb["details"].items()]
        notes_html = "".join(f"<li>{esc(n)}</li>" for n in fb["notes"]) or "<li>No issues found</li>"
        parts.append("<h3>Self-Computed Performance Scorecard</h3>")
        parts.append(f"<div class='pill-row'><div class='pill'><b>{badge(str(fb['score']) + '/100', score_cls)}</b>Score</div></div>")
        parts.append(html_kv_table(detail_rows))
        parts.append(f"<ul class='notes-list'>{notes_html}</ul>")
    elif not any_psi:
        parts.append("<p class='notes-list'>No performance data available.</p>")

    if analytics["pages_skipped"]:
        parts.append(f"<p class='notes-list'>Note: {analytics['pages_skipped']} additional page(s) were not "
                      f"analyzed (showing {analytics['pages_analyzed']} of {analytics['pages_total']}). "
                      f"Increase with --max-pages.</p>")

    page_cards = []
    for page in analytics["pages"]:
        if page.get("error"):
            page_cards.append(f"<div class='page-card'><h4>{esc(page['url'])}</h4>"
                               f"<p class='notes-list'>Error: {esc(page['error'])}</p></div>")
            continue
        issues_html = "".join(f"<li>{esc(i)}</li>" for i in page["issues"]) or "<li>No issues found</li>"
        rows = [
            ("Title", f"{esc(page['title'])} ({page['title_len']} chars)" if page["title"] else badge("missing", "bad")),
            ("Meta Description", f"present ({page['desc_len']} chars)" if page["meta_description"] else badge("missing", "bad")),
            ("H1 Count", esc(page["h1_count"])),
            ("Word Count", esc(page["word_count"])),
            ("Images (missing alt)", esc(f"{page['images']} ({page['images_missing_alt']})")),
            ("Internal / External Links", esc(f"{page['internal_links']} / {page['external_links']}")),
            ("Open Graph / Twitter Tags", esc(f"{page['og_tags']} / {page['twitter_tags']}")),
            ("Structured Data (JSON-LD)", esc(", ".join(page["jsonld_types"])) if page["jsonld_types"] else "none"),
            ("Load Time (TTFB / Total)", esc(f"{page['ttfb_ms']}ms / {page['total_ms']}ms")),
            ("HTTP Status", badge(str(page["status"]), "good" if page["status"] and page["status"] < 400 else "bad")),
        ]
        page_cards.append(
            f"<div class='page-card'><h4><a href='{esc(page['url'])}' target='_blank' rel='noopener'>{esc(page['url'])}</a></h4>"
            + html_kv_table(rows)
            + f"<h3>Issues</h3><ul class='notes-list'>{issues_html}</ul></div>"
        )
    parts.append(f"<h3>Per-Page SEO Breakdown</h3>{''.join(page_cards)}")
    parts.append("</div>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML report: assembly
# ---------------------------------------------------------------------------

def build_html_report(base_url, scan, inventory, analytics, generated_at):
    sections = []
    if scan:
        sections.append(render_scan_html(scan))
    if inventory:
        sections.append(render_inventory_html(inventory))
    if analytics:
        sections.append(render_analytics_html(analytics, base_url))

    if not sections:
        sections.append("<div class='section'><p class='notes-list'>No checks were run.</p></div>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Site Doctor Report - {esc(base_url)}</title>
<style>{HTML_CSS}</style>
</head>
<body>
<div class="header">
  <div class="container">
    <h1>Site Doctor Report</h1>
    <div class="meta">{esc(base_url)} &middot; Generated {esc(generated_at)} &middot; Site Doctor v{VERSION}</div>
  </div>
</div>
<div class="container">
{''.join(sections)}
<div class="footer">Generated by Site Doctor &mdash; a pure-Python diagnostic tool. No data is sent to third
parties except optional Google PageSpeed Insights lookups (PSI).</div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

BANNER = r"""
   _____ _ _         ___           _
  / ____(_) |       |   \ ___  ___| |_ ___ _ _
  \___ \| | __/ -_)_| |) / _ \/ _| __/ _ \ '_|
  ____) | | ||  __/ _|___/\___/\__|\__\___/_|
 |_____/|_|\__\___|
"""


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Site Doctor - WordPress diagnostic scan, content inventory, and analytics/SEO report. "
                     "If none of --scan/--inventory/--analytics are given, all three run.",
        epilog="Examples:\n"
               "  %(prog)s\n"
               "  %(prog)s https://example.com\n"
               "  %(prog)s https://example.com --scan\n"
               "  %(prog)s https://example.com --analytics --max-pages 25 --no-psi\n"
               "  %(prog)s https://example.com --out reports/example.html",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", nargs="?", help="Target site URL, e.g. https://marcdeller.com (prompted if omitted)")
    parser.add_argument("--scan", action="store_true",
                         help="Run the diagnostic scan and health scorecard (default: all modes run)")
    parser.add_argument("--inventory", action="store_true",
                         help="Run the WordPress content inventory (default: all modes run)")
    parser.add_argument("--analytics", action="store_true",
                         help="Run the analytics/SEO report (default: all modes run)")
    parser.add_argument("--max-pages", type=int, default=10,
                         help="Max number of pages to run per-page SEO analysis on (default: 10)")
    parser.add_argument("--no-psi", action="store_true",
                         help="Skip Google PageSpeed Insights and use the self-computed scorecard only")
    parser.add_argument("--out", help="Output HTML report path (default: ./site-doctor-report-<host>-<timestamp>.html)")
    args = parser.parse_args()

    print(c(BANNER, C.CYAN + C.BOLD))

    target = args.url
    if not target:
        target = input("Enter the website URL to probe (e.g. https://marcdeller.com): ").strip()
    if not target:
        print(c("No URL provided. Exiting.", C.RED))
        sys.exit(1)

    base_url = normalize_url(target)

    modes = [m for m, flag in (("scan", args.scan), ("inventory", args.inventory), ("analytics", args.analytics)) if flag]
    if not modes:
        modes = ["scan", "inventory", "analytics"]

    print(c(f"\nTarget : {base_url}", C.BOLD))
    print(c(f"Modes  : {', '.join(modes)}", C.GRAY))

    def log(msg):
        print(c(f"  ... {msg}", C.DIM))

    print()
    scan = run_diagnostic_scan(base_url, log=log)
    if scan.get("fatal_error"):
        print(c(f"\nCould not connect to {base_url}: {scan['fatal_error']}", C.RED))
        sys.exit(1)

    if "scan" in modes:
        print_scan_report(scan)

    inventory = None
    if "inventory" in modes or "analytics" in modes:
        inventory = build_inventory(base_url, log=log)
        if "inventory" in modes:
            print_inventory_report(inventory)

    analytics = None
    if "analytics" in modes:
        analytics = run_analytics(
            base_url, scan["home"], inventory["items"],
            max_pages=args.max_pages, use_psi=not args.no_psi, log=log,
        )
        print_analytics_report(analytics, base_url)

    host = urlparse(base_url).hostname
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = args.out or f"site-doctor-report-{host}-{timestamp}.html"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_report = build_html_report(
        base_url,
        scan if "scan" in modes else None,
        inventory if "inventory" in modes else None,
        analytics if "analytics" in modes else None,
        generated_at,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_report)

    print_header("DONE")
    if "scan" in modes:
        health = scan["health"]
        grade_color = {"A": C.GREEN, "B": C.GREEN, "C": C.YELLOW, "D": C.YELLOW, "F": C.RED}[health["grade"]]
        print(f"  Overall Health: {c(str(health['score']) + '/100', C.BOLD)}   Grade: {c(health['grade'], grade_color + C.BOLD)}")
    print(c(f"  Full HTML report written to: {os.path.abspath(out_path)}", C.BOLD + C.GREEN))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\nInterrupted.", C.YELLOW))
        sys.exit(130)
