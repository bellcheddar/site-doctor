# Site Doctor

A single-file, dependency-free Python 3 tool that diagnoses the health,
content, and SEO/performance profile of a WordPress site — using only the
standard library.

It produces a color-coded report on screen **and** a branded HTML report
on disk, in the same pass.

## Features

By default, Site Doctor runs **all three** checks below against a target URL
in a single pass and writes one combined HTML report. Pass `--scan`,
`--inventory`, and/or `--analytics` to run only a subset.

### 1. Diagnostic Scan (`--scan`)
- Request timing breakdown: DNS, TCP connect, TLS handshake, TTFB, download, total
- HTTP status, response headers, and redirect chain
- Caching behaviour (`Cache-Control`, `ETag`, `Last-Modified`, etc.)
- Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- CORS configuration and mixed-content checks
- SSL/TLS certificate details (issuer, expiry, SANs), supported TLS protocol versions, ALPN/HTTP2 detection
- DNS records (A, AAAA, MX, TXT, NS, CNAME, PTR)
- `robots.txt`, sitemap, favicon, and custom 404 handling checks
- HTTP → HTTPS and www ↔ non-www redirect behaviour
- Server technology / CDN detection (e.g. Cloudflare, Nginx, LiteSpeed)
- WordPress fingerprinting: version disclosure, active theme, plugins, REST API,
  XML-RPC, `readme.html`, `wp-login.php`, and exposed user accounts via
  `/wp-json/wp/v2/users`
- Detected analytics/tracking scripts (Google Analytics, Jetpack Stats, etc.)
- A weighted **Health Scorecard** (0–100, grade A–F) across Security Headers,
  TLS/HTTPS, Performance, WordPress Hygiene, HTTP Behaviour, and SEO Basics

> Note: visitor counts and live CPU/memory load cannot be measured externally
> over HTTP — the report says so explicitly rather than guessing.

### 2. WordPress Content Inventory (`--inventory`)
- Walks every public post type exposed via the WordPress REST API
  (`/wp-json/wp/v2/...`), paginating through results
- De-duplicates by type + ID
- Outputs a clean table: **ID, Type, Date, Category, Title**

### 3. Analytics & SEO Report (`--analytics`)
- Real Lighthouse scores via the public Google PageSpeed Insights API
  (Performance, SEO, Accessibility, Best Practices, plus Core Web Vitals)
- Automatic fallback to a self-computed performance scorecard if PSI is
  unavailable (rate-limited, offline, etc.)
- Per-page SEO breakdown for the site's content: title/meta description
  length, H1 count, word count, image alt coverage, internal/external link
  counts, Open Graph/Twitter tags, structured data (JSON-LD), and load time

## Requirements

- Python 3.8+
- No third-party packages — only the standard library
- Optional: `dig` (used for DNS lookups if available, with a socket-based
  fallback otherwise)

## Usage

```
python3 site_doctor.py [URL] [OPTIONS]
```

If `URL` is omitted, you'll be prompted to enter one interactively (e.g.
`https://example.com`). The scheme defaults to `https://` if not given.

```bash
# Prompt for a URL and run everything (scan + inventory + analytics)
python3 site_doctor.py

# Run everything against a specific site
python3 site_doctor.py https://example.com

# Run only the diagnostic scan and health scorecard
python3 site_doctor.py https://example.com --scan

# Run only the WordPress content inventory
python3 site_doctor.py https://example.com --inventory

# Run only the analytics/SEO report, skipping PageSpeed Insights,
# analyzing 25 pages instead of the default 10
python3 site_doctor.py https://example.com --analytics --max-pages 25 --no-psi

# Run everything and write the HTML report to a custom path
python3 site_doctor.py https://example.com --out reports/example.html
```

### Mode flags (omit all to run everything)

| Flag | Description |
| --- | --- |
| `--scan` | Diagnostic scan: request timing (DNS/connect/TLS/TTFB/download), HTTP headers, caching, security headers, cookies, CORS/mixed content, TLS certificate and protocol support, DNS records, robots.txt/sitemap/favicon, redirect behaviour, server/CDN fingerprint, WordPress core/theme/plugin/user fingerprinting, and the weighted Health Scorecard (0–100, grade A–F). |
| `--inventory` | WordPress content inventory: walks every public post type exposed via `/wp-json/wp/v2/...`, paginates through all results, de-duplicates by type+ID, and prints a table of ID, Type, Date, Category, Title. |
| `--analytics` | Analytics & SEO report: real Lighthouse scores via Google PageSpeed Insights (Performance, SEO, Accessibility, Best Practices, Core Web Vitals), with automatic fallback to a self-computed performance scorecard if PSI is unavailable, plus a per-page SEO breakdown across the site's content. |

If none of `--scan`, `--inventory`, or `--analytics` are given, **all three
run**. Note that `--inventory` and `--analytics` both depend on the content
inventory, so requesting `--analytics` alone will still fetch the inventory
in the background — it just won't be printed/included unless `--inventory`
is also given.

### Other options

| Flag | Description |
| --- | --- |
| `url` | Target site URL (optional — prompted for if omitted), e.g. `https://example.com` |
| `--max-pages N` | Number of pages to run the per-page SEO analysis on during `--analytics` (default: `10`). Increase for a more complete audit of larger sites, at the cost of one extra HTTP request per page. |
| `--no-psi` | Skip the Google PageSpeed Insights API call entirely and go straight to the self-computed performance scorecard. Useful when offline, rate-limited, or for faster runs. |
| `--out PATH` | Output HTML report path (default: `./site-doctor-report-<host>-<timestamp>.html`) |

## Output

- A color-coded report is printed to the terminal (colors auto-disable when
  output isn't a TTY).
- A branded, self-contained HTML report is written to disk, containing every
  section run during that invocation (scorecard, tables, badges, and
  per-page cards).

## How it works

Site Doctor avoids all third-party dependencies by implementing its own
minimal HTTP/1.1 client on top of `socket` and `ssl`, which lets it measure
each phase of a request (DNS, connect, TLS, TTFB, download) precisely. HTML
is parsed with regular expressions rather than a DOM library, DNS records
are fetched via `dig` (with a `socket`-based fallback), and WordPress data is
read entirely from the site's existing public REST API endpoints — no
plugins, authentication, or scraping required.

## Disclaimer

Site Doctor only reads publicly available information (HTTP responses, DNS
records, and public REST API endpoints). Use it against sites you own or are
authorized to test.
