# language: Python 3, file: osint_hacker.py, target: Termux/Linux, no root
# pkg install python whois tor -y
# pip install requests colorama dnspython phonenumbers exifread pysocks beautifulsoup4

__version__ = "4.0.1-HIGH"
__codename__ = "osint-hacker"

import os, sys, json, csv, re, time, socket, ssl, hashlib, sqlite3, logging
import subprocess, ipaddress, random, threading
import html as html_mod
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, quote, urljoin
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from colorama import Fore, Style, init as cinit
    cinit(autoreset=True)
except ImportError:
    print("[!] pip install requests colorama")
    sys.exit(1)

# ─────────────── THEME ───────────────
G=Fore.GREEN; R=Fore.RED; Y=Fore.YELLOW; C=Fore.CYAN
M=Fore.MAGENTA; B=Style.BRIGHT; D=Style.DIM; W=Style.RESET_ALL

BANNER = f"""{G}{B}
  ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██║   ██║███████╗██║██╔██╗ ██║   ██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝
  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{M}{B}     [ OSINT HACKER {__version__} ]
{W}{C}     30 modul · threaded · plugins · API · proxy · tor
{Y}     ──────────────────────────────────────────────
"""

# ─────────────── CONFIG ───────────────
CONFIG_FILE = Path.home() / ".osint_hacker.json"
DEFAULT_CONFIG = {
    "api_keys": {
        "shodan": "", "censys_id": "", "censys_secret": "",
        "virustotal": "", "abuseipdb": "", "urlscan": "",
        "hunterio": "", "hibp": "", "github": "", "securitytrails": "",
    },
    "proxy": {"enabled": False, "list": [], "tor": False, "tor_port": 9050},
    "http": {
        "timeout": 12,
        "retries": 3,
        "user_agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
    },
    "output": {"dir": "results", "format": "json", "save_all": True},
    "scan": {"threads": 30, "rate_limit": 0.05, "subdomain_wordlist": "default"},
    "logging": {"level": "INFO", "file": "osint.log"},
}

def load_config():
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            for k, v in DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
                elif isinstance(v, dict):
                    for kk, vv in v.items():
                        cfg[k].setdefault(kk, vv)
            return cfg
        except Exception:
            pass
    CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
    return json.loads(json.dumps(DEFAULT_CONFIG))

CFG = load_config()

logging.basicConfig(
    level=getattr(logging, CFG["logging"]["level"], logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(CFG["logging"]["file"])],
)
log = logging.getLogger("osint")

# ─────────────── RESULT ───────────────
@dataclass
class Result:
    module: str
    target: str
    ts: str = field(default_factory=lambda: datetime.now().isoformat())
    data: dict = field(default_factory=dict)
    ok: bool = True
    error: str = ""

# ─────────────── HTTP CLIENT ───────────────
class HTTP:
    def __init__(self):
        self.session = requests.Session()
        retry = Retry(
            total=CFG["http"]["retries"],
            backoff_factor=0.4,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({"User-Agent": CFG["http"]["user_agent"]})
        self._proxy_pool = list(CFG["proxy"]["list"])
        self._last_req = 0.0
        self._lock = threading.Lock()

    def _rate(self):
        with self._lock:
            dt = time.time() - self._last_req
            if dt < CFG["scan"]["rate_limit"]:
                time.sleep(CFG["scan"]["rate_limit"] - dt)
            self._last_req = time.time()

    def _proxies(self):
        if CFG["proxy"]["tor"]:
            p = f"socks5h://127.0.0.1:{CFG['proxy']['tor_port']}"
            return {"http": p, "https": p}
        if CFG["proxy"]["enabled"] and self._proxy_pool:
            p = random.choice(self._proxy_pool)
            return {"http": p, "https": p}
        return None

    def get(self, url, **kw):
        self._rate()
        kw.setdefault("timeout", CFG["http"]["timeout"])
        if kw.get("proxies") is None:
            kw["proxies"] = self._proxies()
        try:
            return self.session.get(url, **kw)
        except Exception as e:
            log.debug(f"GET fail {url}: {e}")
            raise

    def post(self, url, **kw):
        self._rate()
        kw.setdefault("timeout", CFG["http"]["timeout"])
        if kw.get("proxies") is None:
            kw["proxies"] = self._proxies()
        return self.session.post(url, **kw)

    def json(self, url, **kw):
        return self.get(url, **kw).json()

HTTPC = HTTP()

# ─────────────── CACHE ───────────────
class Cache:
    def __init__(self, path=".osint_cache.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT, t REAL)")
        self.lock = threading.Lock()

    def get(self, k, ttl=3600):
        with self.lock:
            row = self.conn.execute("SELECT v,t FROM c WHERE k=?", (k,)).fetchone()
        if row and time.time() - row[1] < ttl:
            try:
                return json.loads(row[0])
            except Exception:
                return None
        return None

    def set(self, k, v):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO c VALUES (?,?,?)",
                (k, json.dumps(v, ensure_ascii=False), time.time()),
            )
            self.conn.commit()

CACHE = Cache()

# ─────────────── UI ───────────────
def clear():
    os.system("clear" if os.name != "nt" else "cls")

def banner():
    clear()
    print(BANNER)

def line():
    print(f"{C}{'─' * 56}{W}")

def info(m):
    print(f"{C}[*]{W} {m}")

def good(m):
    print(f"{G}[+]{W} {m}")

def warn(m):
    print(f"{Y}[!]{W} {m}")

def bad(m):
    print(f"{R}[-]{W} {m}")

def kv(k, v):
    print(f"{C}{str(k):16}{W}: {v}")

def pause():
    input(f"\n{Y}[Enter]{W} ")

def out_dir():
    d = Path(CFG["output"]["dir"])
    d.mkdir(exist_ok=True)
    return d

def safe_name(s, n=40):
    return re.sub(r"[^a-zA-Z0-9]", "_", str(s))[:n]

def save(module, target, data, fmt=None):
    if not CFG["output"]["save_all"]:
        return None
    fmt = fmt or CFG["output"]["format"]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir() / f"{module}_{safe_name(target)}_{ts}"
    try:
        if fmt == "json":
            p = base.with_suffix(".json")
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        elif fmt == "csv":
            p = base.with_suffix(".csv")
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if isinstance(data, dict):
                    w.writerow(["key", "value"])
                    for k, v in data.items():
                        w.writerow([k, json.dumps(v, ensure_ascii=False, default=str)])
                elif isinstance(data, list):
                    if data and isinstance(data[0], dict):
                        w.writerow(list(data[0].keys()))
                        for r in data:
                            w.writerow(list(r.values()))
        elif fmt == "html":
            p = base.with_suffix(".html")
            items = data.items() if isinstance(data, dict) else enumerate(data)
            rows = "".join(
                f"<tr><td>{html_mod.escape(str(k))}</td>"
                f"<td><pre>{html_mod.escape(json.dumps(v, indent=2, ensure_ascii=False, default=str))}</pre></td></tr>"
                for k, v in items
            )
            p.write_text(
                f"""<!doctype html><meta charset=utf-8><title>{module} — {target}</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
h1{{color:#3fb950}}table{{border-collapse:collapse;width:100%}}
td{{border:1px solid #30363d;padding:6px;vertical-align:top}}
td:first-child{{color:#58a6ff;width:220px}}</style>
<h1>{html_mod.escape(module)} — {html_mod.escape(str(target))}</h1>
<p>{datetime.now()}</p><table>{rows}</table>"""
            )
        else:
            p = base.with_suffix(".txt")
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        good(f"Saved {p}")
        return p
    except Exception as e:
        bad(f"Save fail: {e}")
        return None

# ─────────────── HELPERS ───────────────
def strip_url(u):
    return u if u.startswith(("http://", "https://")) else "http://" + u

def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def is_domain(s):
    return bool(re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", s, re.I))

def is_email(s):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", s, re.I))

def prompt_target(label="Target"):
    return input(f"{Y}[?] {label}: {W}").strip()

def prompt_int(label, default):
    v = input(f"{Y}[?] {label} [{default}]: {W}").strip()
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        warn(f"Bukan angka, pakai default {default}.")
        return default

# ═══════════════════════════════════════════════════════════════
# MODULES
# ═══════════════════════════════════════════════════════════════

def m_ip_geo():
    q = prompt_target("IP/domain")
    if not q:
        warn("Kosong.")
        return
    try:
        r = HTTPC.json(f"http://ip-api.com/json/{quote(q)}?fields=66846719")
        if r.get("status") != "success":
            bad(r.get("message", "gagal"))
            return
        for k in ["query","country","countryCode","regionName","city","zip","lat","lon",
                  "timezone","isp","org","as","asname","reverse","mobile","proxy","hosting"]:
            if k in r:
                kv(k, r[k])
        save("ip_geo", q, r)
    except Exception as e:
        bad(str(e))

def m_dns():
    d = prompt_target("Domain")
    if not d:
        return
    try:
        import dns.resolver
    except ImportError:
        bad("pip install dnspython")
        return
    out = {}
    for t in ["A","AAAA","MX","NS","TXT","CNAME","SOA","SRV","CAA","PTR","NAPTR","DS","DNSKEY"]:
        try:
            ans = dns.resolver.resolve(d, t, lifetime=5)
            out[t] = [str(x) for x in ans]
            good(f"{t:8}: {', '.join(out[t])[:120]}")
        except Exception:
            pass
    if out:
        save("dns", d, out)

def m_whois():
    d = prompt_target("Domain")
    if not d:
        return
    try:
        r = subprocess.run(["whois", d], capture_output=True, text=True, timeout=25)
        print(r.stdout[:4500])
        save("whois", d, {"raw": r.stdout})
    except FileNotFoundError:
        bad("pkg install whois")
    except Exception as e:
        bad(str(e))

def m_phone():
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
    except ImportError:
        bad("pip install phonenumbers")
        return
    n = prompt_target("Nomor (+62...)")
    if not n:
        return
    try:
        p = phonenumbers.parse(n, None)
        d = {
            "valid": phonenumbers.is_valid_number(p),
            "possible": phonenumbers.is_possible_number(p),
            "region": geocoder.description_for_number(p, "id"),
            "carrier": carrier.name_for_number(p, "en"),
            "tz": list(timezone.time_zones_for_number(p)),
            "e164": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164),
            "intl": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        }
        for k, v in d.items():
            kv(k, v)
        save("phone", n, d)
    except Exception as e:
        bad(str(e))

def m_headers():
    u = strip_url(prompt_target("URL"))
    try:
        r = HTTPC.get(u, allow_redirects=True)
        kv("final", r.url)
        kv("status", r.status_code)
        kv("server", r.headers.get("Server", "-"))
        line()
        for k, v in r.headers.items():
            print(f"{C}{k}{W}: {v}")
        line()
        sec = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
               "X-Content-Type-Options","Referrer-Policy","Permissions-Policy",
               "Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy"]
        info("Security headers:")
        for s in sec:
            good(s) if s in r.headers else bad(f"{s} (missing)")
        save("headers", u, {"url": r.url, "status": r.status_code, "headers": dict(r.headers)})
    except Exception as e:
        bad(str(e))

WORDLIST = """www mail api dev test staging admin ftp vpn portal blog shop cdn ns1 ns2 smtp pop imap
db mysql app m mobile static assets img docs support help secure login auth dashboard panel cpanel
webmail git gitlab jenkins jira confluence beta alpha demo sandbox vpn2 remote office meet chat
forum store pay payment billing account accounts user users id sso autodiscover autoconfig
calendar mail2 news wiki redmine trac svn hg repo code ci cd build deploy stage prod production
test1 test2 dev1 dev2 qa uat preprod internal intranet extranet partner partners vendor vendors
api2 api-v1 api-v2 rest graphql ws wss socket stream media video images files upload uploads
download downloads backup backups old new temp tmp cache cdn2 edge origin proxy gateway
monitor monitoring status health metrics grafana kibana prometheus alertmanager""".split()

def m_subdomain():
    d = prompt_target("Domain")
    if not d:
        return
    found = []
    info(f"Scanning {len(WORDLIST)} subdomain...")

    def resolve(h):
        try:
            return h, socket.gethostbyname(h)
        except Exception:
            return h, None

    with ThreadPoolExecutor(max_workers=CFG["scan"]["threads"]) as ex:
        for h, ip in ex.map(resolve, [f"{s}.{d}" for s in WORDLIST]):
            if ip:
                good(f"{h:42} -> {ip}")
                found.append({"host": h, "ip": ip})
    if found:
        save("subdomains", d, {"domain": d, "count": len(found), "found": found})
    else:
        warn("Tidak ada.")

PORTS = [21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,514,587,631,636,
         993,995,1080,1433,1521,1723,2049,2082,2083,2181,2222,2375,2376,3000,3306,
         3389,3690,4000,4443,5000,5432,5601,5900,5984,6379,6443,7001,7002,8000,8008,
         8080,8081,8082,8086,8088,8443,8888,9000,9001,9042,9090,9200,9300,10000,
         11211,15672,27017,27018,50000,50070]

def m_portscan():
    h = prompt_target("Host / IP")
    if not h:
        return
    info(f"Scanning {len(PORTS)} port...")

    def scan(p):
        s = socket.socket()
        s.settimeout(1.0)
        try:
            s.connect((h, p))
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode(errors="ignore").split("\n")[0].strip()
            except Exception:
                banner = ""
            return p, True, banner
        except Exception:
            return p, False, ""
        finally:
            s.close()

    op = []
    with ThreadPoolExecutor(max_workers=CFG["scan"]["threads"]) as ex:
        for p, ok, bn in ex.map(scan, PORTS):
            if ok:
                good(f"{p:6} OPEN   {bn[:80]}")
                op.append({"port": p, "banner": bn})
    if op:
        save("ports", h, {"host": h, "open": op})
    else:
        warn("Tidak ada port terbuka.")

def m_ssl():
    h = prompt_target("Host (domain/IP)")
    if not h:
        return
    port = prompt_int("Port", 443)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((h, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=h) as ss:
                cert = ss.getpeercert()
                cipher = ss.cipher()
                ver = ss.version()
        kv("version", ver)
        kv("cipher", cipher)
        for k in ["subject","issuer","notBefore","notAfter","serialNumber","subjectAltName"]:
            if k in cert:
                kv(k, cert[k])
        save("ssl", h, {
            "host": h, "port": port,
            "cert": {k: str(v) for k, v in cert.items()},
            "cipher": str(cipher), "version": ver,
        })
    except Exception as e:
        bad(str(e))

def m_breach():
    e = prompt_target("Email")
    if not e:
        return
    try:
        key = CFG["api_keys"]["hibp"]
        h = {"User-Agent": "osint-hacker"}
        if key:
            h["hibp-api-key"] = key
        r = HTTPC.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(e)}",
            headers=h,
        )
        if r.status_code == 200:
            for b in r.json():
                bad(f"{b['Name']:25} ({b['BreachDate']}) — {b.get('PwnCount',0):,}")
            save("breach", e, r.json())
        elif r.status_code == 404:
            good("Bersih.")
        elif r.status_code == 401:
            warn("Butuh API key (isi di ~/.osint_hacker.json)")
        else:
            warn(f"Status {r.status_code}")
    except Exception as ex:
        bad(str(ex))

U_SITES = {
    "GitHub":"https://github.com/{}","Instagram":"https://instagram.com/{}",
    "Twitter/X":"https://x.com/{}","Reddit":"https://reddit.com/user/{}",
    "TikTok":"https://tiktok.com/@{}","Telegram":"https://t.me/{}",
    "Pinterest":"https://pinterest.com/{}","Medium":"https://medium.com/@{}",
    "Twitch":"https://twitch.tv/{}","YouTube":"https://youtube.com/@{}",
    "Steam":"https://steamcommunity.com/id/{}","Spotify":"https://open.spotify.com/user/{}",
    "GitLab":"https://gitlab.com/{}","Keybase":"https://keybase.io/{}",
    "About.me":"https://about.me/{}","Facebook":"https://facebook.com/{}",
    "Snapchat":"https://snapchat.com/add/{}","SoundCloud":"https://soundcloud.com/{}",
    "DeviantArt":"https://deviantart.com/{}","Flickr":"https://flickr.com/people/{}",
    "VK":"https://vk.com/{}","Tumblr":"https://{}.tumblr.com",
    "Roblox":"https://roblox.com/user.aspx?username={}",
    "HackerNews":"https://news.ycombinator.com/user?id={}",
    "Codepen":"https://codepen.io/{}","Behance":"https://behance.net/{}",
    "Dribbble":"https://dribbble.com/{}","HackerOne":"https://hackerone.com/{}",
    "Bugcrowd":"https://bugcrowd.com/{}","TryHackMe":"https://tryhackme.com/p/{}",
    "HackTheBox":"https://app.hackthebox.com/users/{}","LeetCode":"https://leetcode.com/{}",
    "Codeforces":"https://codeforces.com/profile/{}","Kaggle":"https://kaggle.com/{}",
    "Replit":"https://replit.com/@{}","ProductHunt":"https://producthunt.com/@{}",
    "AngelList":"https://angel.co/u/{}","Mastodon.social":"https://mastodon.social/@{}",
    "Threads":"https://threads.net/@{}","Bluesky":"https://bsky.app/profile/{}.bsky.social",
}

def m_username():
    u = prompt_target("Username")
    if not u:
        return
    hits = []
    info(f"Cek {len(U_SITES)} platform...")

    def ck(a):
        n, t, x = a
        try:
            r = HTTPC.get(t.format(x), timeout=8, allow_redirects=True)
            return n, t.format(x), r.status_code
        except Exception:
            return n, t.format(x), 0

    with ThreadPoolExecutor(max_workers=15) as ex:
        for n, url, c in ex.map(ck, [(n, t, u) for n, t in U_SITES.items()]):
            if c == 200:
                good(f"{n:16} {url}")
                hits.append({"site": n, "url": url})
            elif c == 0:
                bad(f"{n:16} timeout")
            else:
                print(f"{Y}[-]{W} {n:16} {c}")
    if hits:
        save("username", u, {"username": u, "found": hits})

def m_expand():
    u = strip_url(prompt_target("URL"))
    try:
        r = HTTPC.get(u, allow_redirects=True)
        kv("final", r.url)
        kv("status", r.status_code)
        for h in r.history:
            print(f"   {Y}->{W} {h.status_code} {h.url}")
        save("url_expand", u, {"original": u, "final": r.url, "chain": [h.url for h in r.history]})
    except Exception as e:
        bad(str(e))

SIGS = {
    "WordPress":["wp-content","wp-includes","wordpress"],"Joomla":["/components/com_","joomla"],
    "Drupal":["sites/default/files","drupal"],"Magento":["mage/","magento","/skin/frontend/"],
    "Shopify":["cdn.shopify","shopify.com"],"Wix":["wix.com","wixstatic"],"Squarespace":["squarespace"],
    "React":["_next/static","__NEXT_DATA__","react"],"Vue.js":["vue.min.js","__vue__","vue@3"],
    "Angular":["ng-version","angular.min.js"],"Svelte":["svelte","__svelte"],
    "Bootstrap":["bootstrap.min.css","bootstrap.bundle"],"Tailwind":["tailwind"],
    "jQuery":["jquery.min.js","jquery-"],"Cloudflare":["cf-ray","cloudflare"],
    "Nginx":["nginx"],"Apache":["apache"],"LiteSpeed":["litespeed"],
    "PHP":["x-powered-by: php",".php"],"ASP.NET":["asp.net","x-aspnet-version"],
    "Laravel":["laravel_session"],"Django":["csrftoken","django"],"Flask":["werkzeug"],
    "Express":["x-powered-by: express"],"Rails":["x-powered-by: phusion"],
    "Ghost":["ghost-"],"Strapi":["strapi"],"FastAPI":["fastapi"],
    "Vercel":["vercel"],"Netlify":["netlify"],"Heroku":["heroku"],
    "AWS":["amazonaws","x-amz"],"Google Cloud":["googleusercontent","gstatic"],
    "Grafana":["grafana"],"Kibana":["kibana"],"Jenkins":["jenkins"],
}

def m_tech():
    u = strip_url(prompt_target("URL"))
    try:
        r = HTTPC.get(u)
        blob = (r.text[:400000] + "\n".join(f"{k}:{v}" for k, v in r.headers.items())).lower()
        found = [t for t, sigs in SIGS.items() if any(s in blob for s in sigs)]
        for t in found:
            good(t)
        if found:
            save("tech", u, {"url": r.url, "detected": found})
        else:
            warn("Tidak ada signature.")
    except Exception as e:
        bad(str(e))

def m_geomap():
    q = prompt_target("IP/domain")
    if not q:
        return
    try:
        r = HTTPC.json(f"http://ip-api.com/json/{quote(q)}")
        if r.get("status") != "success":
            bad("gagal")
            return
        lat, lon = r["lat"], r["lon"]
        kv("lokasi", f"{r['city']}, {r['regionName']}, {r['country']}")
        kv("koordinat", f"{lat}, {lon}")
        kv("Google", f"https://www.google.com/maps?q={lat},{lon}")
        kv("OSM", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=13/{lat}/{lon}")
        save("geomap", q, r)
    except Exception as e:
        bad(str(e))

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

def m_harvest():
    mode = input(f"{Y}[1] URL  [2] Domain [1]: {W}").strip() or "1"
    if mode == "1":
        urls = [strip_url(prompt_target("URL"))]
    else:
        d = prompt_target("Domain")
        if not d:
            return
        base = strip_url(d)
        urls = [base, base+"/contact", base+"/about", base+"/about-us",
                base+"/team", base+"/contact-us", base+"/support", base+"/impressum",
                base+"/privacy", base+"/terms"]
    found = set()
    for u in urls:
        try:
            r = HTTPC.get(u, timeout=10)
            emails = EMAIL_RE.findall(r.text)
            for e in emails:
                found.add(e.lower())
            info(f"{u} — {len(emails)} hits")
        except Exception:
            pass
    found = {e for e in found if not e.endswith((".png",".jpg",".jpeg",".gif",".svg",".webp",".css",".js"))}
    if found:
        for e in sorted(found):
            good(e)
        save("emails", urls[0], {"urls": urls, "emails": sorted(found)})
    else:
        warn("Kosong.")

def m_dork():
    t = prompt_target("Target")
    if not t:
        return
    dorks = {
        "Login": f'site:{t} (inurl:login OR inurl:admin OR inurl:signin)',
        "Config": f'site:{t} (ext:env OR ext:config OR ext:ini OR ext:log OR ext:yaml OR ext:yml)',
        "Backup": f'site:{t} (ext:bak OR ext:old OR ext:backup OR ext:sql OR ext:tar OR ext:zip)',
        "Index of": f'site:{t} intitle:"index of"',
        "SQL err": f'site:{t} intext:"SQL syntax" OR intext:"mysql_fetch" OR intext:"ORA-"',
        "PHP err": f'site:{t} intext:"Warning: include" OR intext:"Fatal error"',
        "Docs": f'site:{t} (ext:pdf OR ext:doc OR ext:xls OR ext:csv OR ext:ppt)',
        "Emails": f'site:{t} intext:"@{t}"',
        "Subs": f'site:*.{t} -www',
        "Cams": f'site:{t} (inurl:view/index.shtml OR inurl:"axis-cgi")',
        "Redirect": f'site:{t} (inurl:redirect= OR inurl:url= OR inurl:next=)',
        "API keys": f'site:{t} (intext:"api_key" OR intext:"apikey" OR intext:"secret" OR intext:"password")',
        ".git": f'site:{t} inurl:.git',
        "Env files": f'site:{t} inurl:.env',
        "phpMyAdmin": f'site:{t} (inurl:phpmyadmin OR inurl:pma)',
        "Jenkins": f'site:{t} inurl:jenkins',
        "Kibana": f'site:{t} inurl:app/kibana',
        "Grafana": f'site:{t} inurl:grafana',
        "Jira": f'site:{t} inurl:jira',
        "RDP web": f'site:{t} inurl:rdweb',
        "VPN": f'site:{t} (inurl:vpn OR intitle:"SSL VPN")',
        "Swagger": f'site:{t} (inurl:swagger OR inurl:api-docs)',
        "GraphQL": f'site:{t} inurl:graphql',
        "Pastebin": f'site:pastebin.com "{t}"',
        "GitHub": f'site:github.com "{t}" (password OR secret OR token OR api_key)',
        "LinkedIn": f'site:linkedin.com/in "{t}"',
        "Trello": f'site:trello.com "{t}"',
        "Cloud buckets": f'site:s3.amazonaws.com "{t}"',
        "Backups open": f'"{t}" intitle:"index of" (backup OR db OR dump)',
    }
    for k, v in dorks.items():
        print(f"{C}{k:15}{W}: {Y}{v}{W}")
    save("dorks", t, dorks)

def m_wayback():
    d = prompt_target("Domain")
    if not d:
        return
    try:
        r = HTTPC.get(
            f"http://web.archive.org/cdx/search/cdx?url={quote(d)}/*&output=json"
            f"&limit=1000&fl=original,timestamp,statuscode,mimetype"
        )
        data = r.json()
        if len(data) < 2:
            warn("Kosong.")
            return
        rows = data[1:]
        for row in rows[:80]:
            print(f"{C}{row[1]}{W} [{row[2]}] {row[0][:110]}")
        if len(rows) > 80:
            info(f"... +{len(rows)-80} lagi")
        save("wayback", d, {"count": len(rows), "urls": rows})
    except Exception as e:
        bad(str(e))

def m_pastebin():
    q = prompt_target("Keyword")
    if not q:
        return
    try:
        r = HTTPC.get(f"https://www.google.com/search?q=site:pastebin.com+{quote(q)}")
        links = list(dict.fromkeys(re.findall(r"https://pastebin\.com/[A-Za-z0-9]+", r.text)))[:25]
        for l in links:
            good(l)
        if links:
            save("pastebin", q, {"query": q, "links": links})
        else:
            warn("Kosong (Google block).")
    except Exception as e:
        bad(str(e))

def m_github():
    q = prompt_target("Keyword")
    if not q:
        return
    h = {"Accept": "application/vnd.github+json"}
    key = CFG["api_keys"]["github"]
    if key:
        h["Authorization"] = f"token {key}"
    try:
        r = HTTPC.get(f"https://api.github.com/search/code?q={quote(q)}", headers=h)
        if r.status_code == 401:
            warn("Butuh GitHub token.")
            return
        if r.status_code != 200:
            warn(f"Status {r.status_code}")
            return
        data = r.json()
        kv("total", data.get("total_count", 0))
        for it in data.get("items", [])[:20]:
            print(f"{G}{it['repository']['full_name']}{W} :: {it['path']}")
            print(f"   {C}{it['html_url']}{W}")
        save("github", q, data)
    except Exception as e:
        bad(str(e))

def m_meta():
    try:
        import exifread
    except ImportError:
        bad("pip install exifread")
        return
    p = prompt_target("Path file")
    if not os.path.exists(p):
        bad("File tidak ada.")
        return
    try:
        with open(p, "rb") as f:
            tags = exifread.process_file(f, details=True)
        if not tags:
            warn("Tidak ada EXIF.")
        for k, v in tags.items():
            if k in ("JPEGThumbnail", "TIFFThumbnail"):
                continue
            print(f"{C}{k:35}{W}: {v}")
        save("metadata", p, {k: str(v) for k, v in tags.items()})
    except Exception as e:
        bad(str(e))

def m_email_acc():
    e = prompt_target("Email")
    if not e:
        return
    checks = [
        ("Pinterest", "https://www.pinterest.com/resource/EmailExistsResource/get/",
         {"data": json.dumps({"options": {"email": e}})}),
        ("Spotify", "https://www.spotify.com/api/signup/validate",
         {"email": e, "format": "json"}),
    ]
    found = []
    for name, url, payload in checks:
        try:
            r = HTTPC.post(url, data=payload, headers={"X-Requested-With": "XMLHttpRequest"})
            snippet = r.text[:120].replace("\n", " ")
            print(f"{C}{name:12}{W} [{r.status_code}] {snippet}")
            if r.status_code == 200 and ("true" in r.text.lower() or "exists" in r.text.lower()):
                good(f"{name}: TERDAFTAR")
                found.append(name)
        except Exception as ex:
            bad(f"{name}: {ex}")
    if found:
        save("email_acc", e, {"email": e, "registered": found})

def m_shodan():
    key = CFG["api_keys"]["shodan"]
    if not key:
        warn("Isi shodan key di ~/.osint_hacker.json")
        return
    q = prompt_target("IP / query")
    try:
        r = HTTPC.get(f"https://api.shodan.io/shodan/host/{quote(q)}?key={key}")
        if r.status_code != 200:
            bad(f"{r.status_code}")
            return
        d = r.json()
        for k in ["ip_str","org","isp","country_name","city","os","hostnames","domains","ports"]:
            if k in d:
                kv(k, d[k])
        for svc in d.get("data", [])[:10]:
            print(f"{C}port {svc.get('port')}{W}: {svc.get('product','')} {svc.get('version','')}")
        save("shodan", q, d)
    except Exception as e:
        bad(str(e))

def m_vt():
    key = CFG["api_keys"]["virustotal"]
    if not key:
        warn("Isi virustotal key.")
        return
    t = prompt_target("IP / domain / hash")
    if not t:
        return
    kind = "ip_addresses" if is_ip(t) else ("domains" if is_domain(t) else "files")
    url = f"https://www.virustotal.com/api/v3/{kind}/{quote(t)}"
    try:
        r = HTTPC.get(url, headers={"x-apikey": key})
        if r.status_code != 200:
            bad(f"{r.status_code}")
            return
        d = r.json().get("data", {}).get("attributes", {})
        for k in ["last_analysis_stats","reputation","country","as_owner","registrar","creation_date"]:
            if k in d:
                kv(k, d[k])
        save("vt", t, d)
    except Exception as e:
        bad(str(e))

def m_abuse():
    key = CFG["api_keys"]["abuseipdb"]
    if not key:
        warn("Isi abuseipdb key.")
        return
    ip = prompt_target("IP")
    try:
        r = HTTPC.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
        )
        if r.status_code != 200:
            bad(f"{r.status_code}")
            return
        d = r.json().get("data", {})
        for k, v in d.items():
            kv(k, v)
        save("abuseipdb", ip, d)
    except Exception as e:
        bad(str(e))

def m_urlscan():
    key = CFG["api_keys"]["urlscan"]
    u = strip_url(prompt_target("URL"))
    try:
        h = {"api-key": key} if key else {}
        r = HTTPC.post(
            "https://urlscan.io/api/v1/scan/",
            headers=h,
            json={"url": u, "visibility": "public"},
        )
        if r.status_code not in (200, 201):
            bad(f"{r.status_code} {r.text[:100]}")
            return
        d = r.json()
        kv("uuid", d.get("uuid"))
        kv("result", d.get("result"))
        save("urlscan", u, d)
    except Exception as e:
        bad(str(e))

def m_axfr():
    d = prompt_target("Domain")
    if not d:
        return
    try:
        import dns.resolver, dns.query, dns.zone
        ns_ans = dns.resolver.resolve(d, "NS", lifetime=5)
        found = False
        for ns in ns_ans:
            host = str(ns).rstrip(".")
            info(f"Coba AXFR {host}...")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(host, d, timeout=8))
                names = [str(n) for n in z.nodes.keys()]
                for n in names:
                    good(f"{n}.{d}")
                found = True
                save("axfr", d, {"ns": host, "records": names})
            except Exception as ex:
                bad(f"  {ex}")
        if not found:
            warn("Tidak ada NS yang allow AXFR.")
    except Exception as e:
        bad(str(e))

def m_revip():
    ip = prompt_target("IP")
    if not ip:
        return
    try:
        r = HTTPC.get(f"https://api.hackertarget.com/reverseiplookup/?q={quote(ip)}")
        print(r.text[:1500])
        save("revip", ip, {"raw": r.text})
    except Exception as e:
        bad(str(e))

def m_asn():
    q = prompt_target("IP / ASN (AS123)")
    if not q:
        return
    try:
        r = HTTPC.get(f"https://api.hackertarget.com/aslookup/?q={quote(q)}")
        print(r.text[:1500])
        save("asn", q, {"raw": r.text})
    except Exception as e:
        bad(str(e))

def m_js():
    u = strip_url(prompt_target("URL"))
    try:
        r = HTTPC.get(u)
        html_txt = r.text
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_txt)
        endpoints = set()
        for s in scripts[:15]:
            full = urljoin(u, s)
            try:
                js = HTTPC.get(full, timeout=10).text
                for pat in [
                    r'["\'](/[a-zA-Z0-9_\-/\.]+)["\']',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                ]:
                    endpoints.update(re.findall(pat, js))
            except Exception:
                pass
        for e in sorted(endpoints)[:200]:
            good(e)
        if endpoints:
            save("js_endpoints", u, {"url": u, "endpoints": sorted(endpoints)})
        else:
            warn("Kosong.")
    except Exception as e:
        bad(str(e))

TAKEOVER_SIGS = {
    "github.io": ["There isn't a GitHub Pages site here", "For root URLs"],
    "herokuapp.com": ["No such app", "heroku | no such app"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "azurewebsites.net": ["Error 404 - Web app not found"],
    "cloudfront.net": ["Bad request", "ERROR: The request could not be satisfied"],
    "netlify.app": ["Not Found - Request ID"],
    "vercel.app": ["The deployment could not be found"],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["Repository not found"],
    "readthedocs.io": ["unknown to Read the Docs"],
    "shopify.com": ["Sorry, this shop is currently unavailable"],
    "tumblr.com": ["There's nothing here"],
    "wordpress.com": ["Do you want to register"],
    "teamwork.com": ["Oops - We didn't find your site"],
    "pantheonsite.io": ["The gods are wise"],
}

def m_takeover():
    hosts = prompt_target("Subdomain(s), pisah koma").split(",")
    found = []
    for h in hosts:
        h = h.strip()
        if not h:
            continue
        try:
            socket.gethostbyname(h)
            r = HTTPC.get(f"http://{h}", timeout=8, allow_redirects=True)
            blob = r.text[:5000].lower()
            hit = False
            for svc, sigs in TAKEOVER_SIGS.items():
                if any(s.lower() in blob for s in sigs):
                    bad(f"{h} -> VULNERABLE ({svc})")
                    found.append({"host": h, "service": svc})
                    hit = True
                    break
            if not hit:
                good(f"{h} -> ok")
        except Exception as e:
            warn(f"{h}: {e}")
    if found:
        save("takeover", ",".join(hosts), {"vulnerable": found})

def m_cve():
    p = prompt_target("Product (contoh: wordpress 5.0)")
    if not p:
        return
    try:
        r = HTTPC.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": p, "resultsPerPage": 20},
        )
        data = r.json()
        for v in data.get("vulnerabilities", []):
            c = v["cve"]
            desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
            print(f"{R}{c['id']}{W} — {desc[:150]}")
        save("cve", p, data)
    except Exception as e:
        bad(str(e))

# ═══════════════════════════════════════════════════════════════
# FULL RECON
# ═══════════════════════════════════════════════════════════════
def m_fullrecon():
    t = prompt_target("Target (domain / IP / email)")
    if not t:
        return
    line()
    info(f"FULL RECON: {t}")
    line()
    results = {"target": t, "ts": datetime.now().isoformat(), "modules": {}}

    try:
        r = HTTPC.json(f"http://ip-api.com/json/{quote(t)}")
        if r.get("status") == "success":
            good(f"Geo: {r['query']} — {r['city']}, {r['country']} ({r['isp']})")
            results["modules"]["ip"] = r
    except Exception:
        pass

    try:
        import dns.resolver
        dns_out = {}
        for rec in ["A","MX","NS","TXT","CNAME","SOA","CAA"]:
            try:
                dns_out[rec] = [str(x) for x in dns.resolver.resolve(t, rec, lifetime=5)]
            except Exception:
                pass
        if dns_out:
            for k, v in dns_out.items():
                good(f"DNS {k}: {', '.join(v)[:80]}")
            results["modules"]["dns"] = dns_out
    except Exception:
        pass

    if "." in t and "@" not in t and not is_ip(t):
        found = []

        def res(h):
            try:
                return h, socket.gethostbyname(h)
            except Exception:
                return h, None

        with ThreadPoolExecutor(max_workers=CFG["scan"]["threads"]) as ex:
            for h, ip in ex.map(res, [f"{s}.{t}" for s in WORDLIST[:60]]):
                if ip:
                    found.append({"host": h, "ip": ip})
        if found:
            good(f"Subdomain: {len(found)}")
            results["modules"]["subdomains"] = found

    if "." in t and "@" not in t:
        op = []

        def sc(p):
            s = socket.socket()
            s.settimeout(1.0)
            try:
                s.connect((t, p))
                return p, True
            except Exception:
                return p, False
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=25) as ex:
            for p, ok in ex.map(sc, PORTS[:30]):
                if ok:
                    op.append(p)
        if op:
            good(f"Open ports: {op}")
            results["modules"]["ports"] = op

    if "@" not in t and not is_ip(t):
        try:
            r = HTTPC.get(strip_url(t))
            em = set(EMAIL_RE.findall(r.text))
            if em:
                good(f"Emails: {len(em)}")
                results["modules"]["emails"] = sorted(em)
        except Exception:
            pass

    if "@" not in t:
        try:
            r = HTTPC.get(strip_url(t))
            blob = (r.text[:300000] + "\n".join(f"{k}:{v}" for k, v in r.headers.items())).lower()
            tech = [t2 for t2, sigs in SIGS.items() if any(s in blob for s in sigs)]
            if tech:
                good(f"Tech: {', '.join(tech)}")
                results["modules"]["tech"] = tech
        except Exception:
            pass

    save("full_recon", t, results)
    line()
    good("Done.")

# ═══════════════════════════════════════════════════════════════
# SETTINGS
# ═══════════════════════════════════════════════════════════════
def m_settings():
    global CFG
    while True:
        line()
        info("SETTINGS")
        line()
        print(f"{C}[1]{W} Lihat config")
        print(f"{C}[2]{W} Set API key")
        print(f"{C}[3]{W} Set output format (json/csv/html/txt)")
        print(f"{C}[4]{W} Set thread count")
        print(f"{C}[5]{W} Set timeout")
        print(f"{C}[6]{W} Proxy: enable/disable/list")
        print(f"{C}[7]{W} Tor: enable/disable")
        print(f"{C}[8]{W} Reset config default")
        print(f"{C}[0]{W} Kembali")
        c = input(f"{Y}> {W}").strip()
        if c == "0":
            return
        elif c == "1":
            print(json.dumps(CFG, indent=2, ensure_ascii=False))
        elif c == "2":
            for k in CFG["api_keys"]:
                print(f"  - {k}")
            k = input(f"{Y} key name: {W}").strip()
            if k in CFG["api_keys"]:
                CFG["api_keys"][k] = input(f"{Y} value: {W}").strip()
                CONFIG_FILE.write_text(json.dumps(CFG, indent=2))
                good("Saved.")
            else:
                bad("Unknown key.")
        elif c == "3":
            f = input(f"{Y} format (json/csv/html/txt): {W}").strip()
            if f in ("json", "csv", "html", "txt"):
                CFG["output"]["format"] = f
                CONFIG_FILE.write_text(json.dumps(CFG, indent=2))
                good("Saved.")
        elif c == "4":
            try:
                CFG["scan"]["threads"] = int(input(f"{Y} threads: {W}").strip() or "30")
                CONFIG_FILE.write_text(json.dumps(CFG, indent=2))
                good("Saved.")
            except ValueError:
                bad("Harus angka.")
        elif c == "5":
            try:
                CFG["http"]["timeout"] = int(input(f"{Y} timeout(s): {W}").strip() or "12")
                CONFIG_FILE.write_text(json.dumps(CFG, indent=2))
                good("Saved.")
            except ValueError:
                bad("Harus angka.")
        elif c == "6":
            CFG["proxy"]["enabled"] = input(f"{Y} enable? (y/n): {W}").strip().lower() == "y"
            if CFG["proxy"]["enabled"]:
                lst = input(f"{Y} proxies (comma, http://ip:port): {W}").strip()
                CFG["proxy"]["list"] = [p.strip() for p in lst.split(",") if p.strip()]
            CONFIG_FILE.write_text(json.dumps(CFG, indent=2))
            good("Saved.")
        elif c == "7":
            CFG["proxy"]["tor"] = input(f"{Y} tor? (y/n): {W}").strip().lower() == "y"
            CONFIG_FILE.write_text(json.dumps(CFG, indent=2))
            good("Saved.")
        elif c == "8":
            CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
            CFG = load_config()
            HTTPC.session.headers.update({"User-Agent": CFG["http"]["user_agent"]})
            good("Reset.")

# ═══════════════════════════════════════════════════════════════
# MENU
# ═══════════════════════════════════════════════════════════════
MENU = f"""{C}┌──────────────────────────────────────────────────┐
│ {G}[1]{W}  IP Geo           {C}│ {G}[16]{W} Wayback URLs
│ {G}[2]{W}  DNS Records      {C}│ {G}[17]{W} Pastebin Search
│ {G}[3]{W}  Whois            {C}│ {G}[18]{W} GitHub Leak
│ {G}[4]{W}  Phone Info       {C}│ {G}[19]{W} Metadata EXIF
│ {G}[5]{W}  HTTP Headers     {C}│ {G}[20]{W} Email→Accounts
│ {G}[6]{W}  Subdomain Scan   {C}│ {G}[21]{W} Shodan
│ {G}[7]{W}  Port Scan        {C}│ {G}[22]{W} VirusTotal
│ {G}[8]{W}  SSL Cert         {C}│ {G}[23]{W} AbuseIPDB
│ {G}[9]{W}  Email Breach     {C}│ {G}[24]{W} URLScan.io
│ {G}[10]{W} Username Search  {C}│ {G}[25]{W} DNS Zone Transfer
│ {G}[11]{W} URL Expander     {C}│ {G}[26]{W} Reverse IP
│ {G}[12]{W} Tech Fingerprint {C}│ {G}[27]{W} ASN Lookup
│ {G}[13]{W} Geo Map          {C}│ {G}[28]{W} JS Endpoints
│ {G}[14]{W} Email Harvester  {C}│ {G}[29]{W} Takeover Check
│ {G}[15]{W} Google Dork Gen  {C}│ {G}[30]{W} CVE Search
│                              {C}│ {G}[99]{W} FULL RECON
│ {G}[98]{W} Settings         {C}│ {G}[0]{W}  Keluar
{C}└──────────────────────────────────────────────────┘{W}"""

ACTIONS = {
    "1":("IP Geo", m_ip_geo), "2":("DNS", m_dns), "3":("Whois", m_whois),
    "4":("Phone", m_phone), "5":("Headers", m_headers), "6":("Subdomain", m_subdomain),
    "7":("Port Scan", m_portscan), "8":("SSL", m_ssl), "9":("Breach", m_breach),
    "10":("Username", m_username), "11":("URL Expand", m_expand), "12":("Tech FP", m_tech),
    "13":("Geo Map", m_geomap), "14":("Harvest", m_harvest), "15":("Dork", m_dork),
    "16":("Wayback", m_wayback), "17":("Pastebin", m_pastebin), "18":("GitHub", m_github),
    "19":("Metadata", m_meta), "20":("Email→Acc", m_email_acc), "21":("Shodan", m_shodan),
    "22":("VirusTotal", m_vt), "23":("AbuseIPDB", m_abuse), "24":("URLScan", m_urlscan),
    "25":("AXFR", m_axfr), "26":("Reverse IP", m_revip), "27":("ASN", m_asn),
    "28":("JS Endpoints", m_js), "29":("Takeover", m_takeover), "30":("CVE", m_cve),
    "99":("FULL RECON", m_fullrecon), "98":("Settings", m_settings),
}

def main():
    while True:
        banner()
        print(MENU)
        c = input(f"{G}{B}osint-hacker>{W} ").strip()
        if c == "0":
            print(f"{M}[*] Stay dark.{W}")
            break
        if c in ACTIONS:
            name, fn = ACTIONS[c]
            line()
            info(f"Modul: {name}")
            line()
            t0 = time.time()
            try:
                fn()
            except KeyboardInterrupt:
                print(f"\n{Y}[!] Dibatalkan.{W}")
            except Exception as e:
                bad(f"Crash: {e}")
                log.exception("module crash")
            line()
            info(f"Durasi: {time.time()-t0:.2f}s")
            pause()
        else:
            warn("Pilihan tidak valid.")
            time.sleep(0.5)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{M}[*] Keluar.{W}")
