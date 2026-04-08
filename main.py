from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import httpx
import geoip2.database
import geoip2.errors
import ipaddress
import asyncio
import csv
import io
import re
import os
import json
from pathlib import Path
import anthropic

app = FastAPI(title="VPN Detector API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR  = Path(__file__).parent
MMDB_ASN  = BASE_DIR / "mmdb" / "GeoLite2-ASN.mmdb"
MMDB_CITY = BASE_DIR / "mmdb" / "GeoLite2-City.mmdb"

PROXYCHECK_KEY   = os.environ.get("PROXYCHECK_KEY", "")
ANTHROPIC_KEY    = os.environ.get("ANTHROPIC_API_KEY", "")

# ── Legal suffix cleanup ──────────────────────────────────────────────────────
LEGAL_SUFFIXES = re.compile(
    r'\b(LLC|Ltd|Limited|Inc|Corp|Corporation|GmbH|S\.A\.|S\.A|AG|B\.V\.|BV|'
    r'AB|AS|OY|SRL|S\.R\.L|SARL|PLC|LLP|LP|Co\.|Company|Pvt|Private|'
    r'Technologies|Technology|Networks|Network|Communications|Services|'
    r'Hosting|Solutions|Systems|Group|International|Global|Telecom|'
    r'Internet|Broadband|Digital)\b\.?',
    re.IGNORECASE
)

def clean_org(org: str) -> str:
    cleaned = LEGAL_SUFFIXES.sub('', org)
    cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip(' ,.-')
    return cleaned or org

# ── Known VPN IP ranges → exact provider name ─────────────────────────────────
# Priority 1: IP range match = most accurate, shows exact name like nodedata.io
VPN_IP_RANGES: list[tuple[str, str, str]] = [
    # (provider_name, cidr, website)
    ("Mullvad VPN",               "185.213.154.0/24",  "https://mullvad.net"),
    ("Mullvad VPN",               "185.65.134.0/23",   "https://mullvad.net"),
    ("Mullvad VPN",               "193.138.218.0/24",  "https://mullvad.net"),
    ("Mullvad VPN",               "91.90.44.0/23",     "https://mullvad.net"),
    ("Mullvad VPN",               "45.83.220.0/22",    "https://mullvad.net"),
    ("Mullvad VPN",               "194.165.16.0/22",   "https://mullvad.net"),
    ("Mullvad VPN",               "45.83.223.0/24",    "https://mullvad.net"),
    ("Mullvad VPN",               "89.45.90.0/24",     "https://mullvad.net"),
    ("NordVPN",                   "103.86.96.0/22",    "https://nordvpn.com"),
    ("NordVPN",                   "185.234.216.0/22",  "https://nordvpn.com"),
    ("NordVPN",                   "37.120.217.0/24",   "https://nordvpn.com"),
    ("NordVPN",                   "45.134.212.0/22",   "https://nordvpn.com"),
    ("ExpressVPN",                "91.207.174.0/24",   "https://expressvpn.com"),
    ("ExpressVPN",                "92.223.88.0/24",    "https://expressvpn.com"),
    ("ExpressVPN",                "45.129.56.0/22",    "https://expressvpn.com"),
    ("ProtonVPN",                 "185.159.156.0/22",  "https://protonvpn.com"),
    ("ProtonVPN",                 "37.19.198.0/23",    "https://protonvpn.com"),
    ("ProtonVPN",                 "185.107.80.0/22",   "https://protonvpn.com"),
    ("Surfshark",                 "45.139.48.0/22",    "https://surfshark.com"),
    ("Surfshark",                 "156.146.56.0/22",   "https://surfshark.com"),
    ("IPVanish",                  "198.8.80.0/20",     "https://ipvanish.com"),
    ("CyberGhost VPN",            "93.115.24.0/22",    "https://cyberghostvpn.com"),
    ("CyberGhost VPN",            "77.247.96.0/20",    "https://cyberghostvpn.com"),
    ("CyberGhost VPN",            "5.254.64.0/20",     "https://cyberghostvpn.com"),
    ("Private Internet Access",   "198.8.80.0/20",     "https://privateinternetaccess.com"),
    ("Private Internet Access",   "209.222.18.0/23",   "https://privateinternetaccess.com"),
    ("TorGuard",                  "23.19.244.0/23",    "https://torguard.net"),
    ("Windscribe",                "185.242.4.0/22",    "https://windscribe.com"),
    ("Windscribe",                "64.44.32.0/20",     "https://windscribe.com"),
    ("Windscribe",                "23.81.0.0/20",      "https://windscribe.com"),
    ("Browsec VPN",               "146.70.0.0/16",     "https://browsec.com"),
    ("Hola VPN",                  "185.121.240.0/22",  "https://hola.org"),
    ("PureVPN",                   "91.109.4.0/22",     "https://purevpn.com"),
    ("PureVPN",                   "185.94.96.0/22",    "https://purevpn.com"),
    ("HideMyAss VPN",             "37.19.200.0/21",    "https://hidemyass.com"),
    ("Hotspot Shield",            "66.187.76.0/22",    "https://hotspotshield.com"),
    ("Astrill VPN",               "185.195.232.0/22",  "https://astrill.com"),
    ("TunnelBear",                "216.245.212.0/22",  "https://tunnelbear.com"),
    ("VyprVPN",                   "91.108.4.0/22",     "https://vyprvpn.com"),
    ("SoftEther VPN",             "124.18.0.0/16",     "https://softether.org"),
    ("SoftEther VPN",             "219.117.0.0/16",    "https://softether.org"),
    ("VPN Gate",                  "219.100.0.0/15",    "https://vpngate.net"),
    ("VPN Gate",                  "220.100.0.0/14",    "https://vpngate.net"),
    ("VPN Gate",                  "133.9.0.0/16",      "https://vpngate.net"),
    ("Cloudflare WARP",           "162.159.192.0/24",  "https://cloudflare.com"),
    ("Cloudflare WARP",           "162.159.193.0/24",  "https://cloudflare.com"),
    ("Tor Exit Node",             "185.220.100.0/22",  "https://torproject.org"),
    ("Tor Exit Node",             "185.220.101.0/24",  "https://torproject.org"),
    ("Tor Exit Node",             "51.15.0.0/16",      "https://torproject.org"),
    ("Tor Exit Node",             "199.87.154.0/23",   "https://torproject.org"),
    ("Tor Exit Node",             "171.25.193.0/24",   "https://torproject.org"),
    ("Tor Exit Node",             "62.102.148.0/22",   "https://torproject.org"),
]

# Pre-compile all networks once at startup for fast lookup
_COMPILED_RANGES: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
for _name, _cidr, _site in VPN_IP_RANGES:
    try:
        _COMPILED_RANGES.append((_name, ipaddress.ip_network(_cidr, strict=False), _site))
    except ValueError:
        pass

def detect_by_ip_range(ip: str) -> tuple[str, str] | tuple[None, None]:
    """Returns (provider_name, website) or (None, None)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for name, net, site in _COMPILED_RANGES:
            if ip_obj in net:
                return name, site
    except Exception:
        pass
    return None, None

# ── VPN keyword lists ─────────────────────────────────────────────────────────
VPN_KEYWORDS = [
    "vpn","mullvad","nordvpn","expressvpn","protonvpn","surfshark",
    "ipvanish","cyberghost","pia","private internet access","hidemyass",
    "torguard","windscribe","tunnelbear","hotspot shield","purevpn",
    "hide.me","vyprvpn","strongvpn","ivacy","perfect privacy",
    "astrill","cactusvpn","fastestvpn","safervpn","zenmate",
    "privatevpn","anonine","ovpn","azirevpn","trust.zone",
    "softether","openvpn","wireguard","l2tp","ikev2","pptp","sstp",
    "vpngate","vpn gate","freevpn","anonymizer","anonymous","anon",
    "tor","torproject","exit node","relay",
    "browsec","hola",
]
DATACENTER_KEYWORDS = [
    "amazon","aws","google","microsoft","azure","digitalocean",
    "linode","vultr","hetzner","ovh","cloudflare","leaseweb",
    "hostinger","contabo","scaleway","choopa","wholesale",
    "datacenter","data center","hosting","colocation","colo",
    "server","cloud","vps","packethub","packetexchange",
    "m247","datacamp","tzulo","psychz","sharktech","quadranet",
    "spartanhost","frantech","buyvm","ramnode","akamai","fastly","cdn",
]

# ── Provider catalogue ────────────────────────────────────────────────────────
PROVIDER_DB: dict[str, dict] = {
    "mullvad":           {"type":"VPN Provider","website":"https://mullvad.net",               "logo":"https://logo.clearbit.com/mullvad.net"},
    "nordvpn":           {"type":"VPN Provider","website":"https://nordvpn.com",                "logo":"https://logo.clearbit.com/nordvpn.com"},
    "expressvpn":        {"type":"VPN Provider","website":"https://expressvpn.com",             "logo":"https://logo.clearbit.com/expressvpn.com"},
    "protonvpn":         {"type":"VPN Provider","website":"https://protonvpn.com",              "logo":"https://logo.clearbit.com/protonvpn.com"},
    "surfshark":         {"type":"VPN Provider","website":"https://surfshark.com",              "logo":"https://logo.clearbit.com/surfshark.com"},
    "ipvanish":          {"type":"VPN Provider","website":"https://ipvanish.com",               "logo":"https://logo.clearbit.com/ipvanish.com"},
    "cyberghost":        {"type":"VPN Provider","website":"https://cyberghostvpn.com",          "logo":"https://logo.clearbit.com/cyberghostvpn.com"},
    "private internet":  {"type":"VPN Provider","website":"https://privateinternetaccess.com",  "logo":"https://logo.clearbit.com/privateinternetaccess.com"},
    "torguard":          {"type":"VPN Provider","website":"https://torguard.net",               "logo":"https://logo.clearbit.com/torguard.net"},
    "windscribe":        {"type":"VPN Provider","website":"https://windscribe.com",             "logo":"https://logo.clearbit.com/windscribe.com"},
    "purevpn":           {"type":"VPN Provider","website":"https://purevpn.com",                "logo":"https://logo.clearbit.com/purevpn.com"},
    "hidemyass":         {"type":"VPN Provider","website":"https://hidemyass.com",              "logo":"https://logo.clearbit.com/hidemyass.com"},
    "hide.me":           {"type":"VPN Provider","website":"https://hide.me",                    "logo":"https://logo.clearbit.com/hide.me"},
    "strongvpn":         {"type":"VPN Provider","website":"https://strongvpn.com",              "logo":"https://logo.clearbit.com/strongvpn.com"},
    "vyprvpn":           {"type":"VPN Provider","website":"https://vyprvpn.com",                "logo":"https://logo.clearbit.com/vyprvpn.com"},
    "tunnelbear":        {"type":"VPN Provider","website":"https://tunnelbear.com",             "logo":"https://logo.clearbit.com/tunnelbear.com"},
    "hotspot shield":    {"type":"VPN Provider","website":"https://hotspotshield.com",          "logo":"https://logo.clearbit.com/hotspotshield.com"},
    "zenmate":           {"type":"VPN Provider","website":"https://zenmate.com",                "logo":"https://logo.clearbit.com/zenmate.com"},
    "astrill":           {"type":"VPN Provider","website":"https://astrill.com",                "logo":"https://logo.clearbit.com/astrill.com"},
    "ivacy":             {"type":"VPN Provider","website":"https://ivacy.com",                  "logo":"https://logo.clearbit.com/ivacy.com"},
    "softether":         {"type":"VPN Provider","website":"https://softether.org",              "logo":"https://logo.clearbit.com/softether.org"},
    "vpn gate":          {"type":"VPN Provider","website":"https://vpngate.net",                "logo":"https://logo.clearbit.com/vpngate.net"},
    "vpngate":           {"type":"VPN Provider","website":"https://vpngate.net",                "logo":"https://logo.clearbit.com/vpngate.net"},
    "warp":              {"type":"VPN Provider","website":"https://cloudflare.com",             "logo":"https://logo.clearbit.com/cloudflare.com"},
    "torproject":        {"type":"Tor Exit",    "website":"https://torproject.org",             "logo":"https://logo.clearbit.com/torproject.org"},
    "tor exit":          {"type":"Tor Exit",    "website":"https://torproject.org",             "logo":"https://logo.clearbit.com/torproject.org"},
    "amazon":            {"type":"Cloud",       "website":"https://aws.amazon.com",             "logo":"https://logo.clearbit.com/aws.amazon.com"},
    "google":            {"type":"Cloud",       "website":"https://cloud.google.com",           "logo":"https://logo.clearbit.com/google.com"},
    "microsoft":         {"type":"Cloud",       "website":"https://azure.microsoft.com",        "logo":"https://logo.clearbit.com/microsoft.com"},
    "cloudflare":        {"type":"Cloud",       "website":"https://cloudflare.com",             "logo":"https://logo.clearbit.com/cloudflare.com"},
    "digitalocean":      {"type":"Cloud",       "website":"https://digitalocean.com",           "logo":"https://logo.clearbit.com/digitalocean.com"},
    "linode":            {"type":"Cloud",       "website":"https://linode.com",                 "logo":"https://logo.clearbit.com/linode.com"},
    "vultr":             {"type":"Cloud",       "website":"https://vultr.com",                  "logo":"https://logo.clearbit.com/vultr.com"},
    "hetzner":           {"type":"Cloud",       "website":"https://hetzner.com",                "logo":"https://logo.clearbit.com/hetzner.com"},
    "ovh":               {"type":"Cloud",       "website":"https://ovhcloud.com",               "logo":"https://logo.clearbit.com/ovhcloud.com"},
    "leaseweb":          {"type":"Cloud",       "website":"https://leaseweb.com",               "logo":"https://logo.clearbit.com/leaseweb.com"},
    "contabo":           {"type":"Cloud",       "website":"https://contabo.com",                "logo":"https://logo.clearbit.com/contabo.com"},
    "scaleway":          {"type":"Cloud",       "website":"https://scaleway.com",               "logo":"https://logo.clearbit.com/scaleway.com"},
    "packethub":         {"type":"Datacenter",  "website":"https://packethub.net",              "logo":None},
    "m247":              {"type":"Datacenter",  "website":"https://m247.com",                   "logo":"https://logo.clearbit.com/m247.com"},
    "akamai":            {"type":"CDN",         "website":"https://akamai.com",                 "logo":"https://logo.clearbit.com/akamai.com"},
    "fastly":            {"type":"CDN",         "website":"https://fastly.com",                 "logo":"https://logo.clearbit.com/fastly.com"},
    "hostinger":         {"type":"Cloud",       "website":"https://hostinger.com",              "logo":"https://logo.clearbit.com/hostinger.com"},
    "frantech":          {"type":"Datacenter",  "website":"https://frantech.ca",                "logo":None},
    "browsec":           {"type":"VPN Provider","website":"https://browsec.com",               "logo":"https://logo.clearbit.com/browsec.com"},
    "hola":              {"type":"VPN Provider","website":"https://hola.org",                  "logo":"https://logo.clearbit.com/hola.org"},
}

def get_provider_info(name: str) -> dict:
    name_lower = (name or "").lower()
    for key, info in PROVIDER_DB.items():
        if key in name_lower:
            return info
    return {"type": "ISP", "website": None, "logo": None}

def provider_type_from_name(name: str) -> str:
    n = (name or "").lower()
    if "tor" in n:                  return "Tor Exit"
    if "gate" in n or "vpn" in n:   return "VPN Provider"
    if "softether" in n:            return "VPN Provider"
    if "warp" in n:                 return "VPN Provider"
    return "VPN Provider"

# ── External API fetchers ─────────────────────────────────────────────────────
async def fetch_proxycheck(ip: str, client: httpx.AsyncClient) -> dict:
    result = {"vpn":False,"proxy":False,"type":None,"operator":None,"risk":0,"ok":False}
    try:
        params = {"vpn":1,"asn":1,"risk":1}
        if PROXYCHECK_KEY: params["key"] = PROXYCHECK_KEY
        resp = await client.get(f"https://proxycheck.io/v2/{ip}", params=params, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            ip_data = data.get(ip, {})
            if ip_data:
                result["ok"]       = True
                result["vpn"]      = ip_data.get("vpn","no") == "yes"
                result["proxy"]    = ip_data.get("proxy","no") == "yes"
                result["type"]     = ip_data.get("type")
                result["operator"] = ip_data.get("operator")
                result["risk"]     = int(ip_data.get("risk", 0))
    except Exception: pass
    return result

async def fetch_ipapiis(ip: str, client: httpx.AsyncClient) -> dict:
    result = {"is_vpn":False,"is_tor":False,"is_proxy":False,"is_datacenter":False,
              "is_abuser":False,"company_type":None,"abuse_score":0,"ok":False}
    try:
        resp = await client.get(f"https://api.ipapi.is/?q={ip}", timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            abuse   = data.get("abuse", {})
            company = data.get("company", {})
            result["ok"]            = True
            result["is_vpn"]        = bool(data.get("is_vpn", False))
            result["is_tor"]        = bool(data.get("is_tor", False))
            result["is_proxy"]      = bool(data.get("is_proxy", False))
            result["is_datacenter"] = bool(data.get("is_datacenter", False))
            result["is_abuser"]     = bool(abuse.get("is_abuser", False))
            result["abuse_score"]   = int(abuse.get("abuse_score", 0))
            result["company_type"]  = company.get("type")
    except Exception: pass
    return result

async def fetch_getipintel(ip: str, client: httpx.AsyncClient) -> dict:
    result = {"score":0.0,"ok":False}
    try:
        resp = await client.get(
            "https://check.getipintel.net/check.php",
            params={"ip":ip,"contact":"info@vpndetector.app","flags":"m","format":"json"},
            timeout=6.0
        )
        if resp.status_code == 200:
            data = resp.json()
            if str(data.get("status")) == "success":
                result["score"] = float(data.get("result", 0))
                result["ok"]    = True
    except Exception: pass
    return result

# ── Scoring ───────────────────────────────────────────────────────────────────
def score_vpn(org: str, ip_api: dict, proxycheck: dict, ipapiis: dict,
              getipintel: dict, ip_range_hit: bool) -> dict:
    org_lower = (org or "").lower()
    score = 0
    flags: set[str] = set()

    # IP range match — highest confidence signal
    if ip_range_hit:
        score += 80; flags.add("known_vpn_range")

    # ASN keyword
    for kw in VPN_KEYWORDS:
        if kw in org_lower:
            score += 50; flags.add("known_vpn_provider"); break
    for kw in DATACENTER_KEYWORDS:
        if kw in org_lower:
            score += 25; flags.add("datacenter"); break

    # ip-api.com
    if ip_api.get("proxy"):   score += 20; flags.add("proxy")
    if ip_api.get("hosting"): score += 15; flags.add("hosting")
    if ip_api.get("vpn"):     score += 35; flags.add("vpn_flag")

    # proxycheck.io
    if proxycheck.get("ok"):
        if proxycheck.get("vpn"):   score += 40; flags.add("vpn_confirmed")
        if proxycheck.get("proxy"): score += 25; flags.add("proxy_confirmed")
        ptype = (proxycheck.get("type") or "").upper()
        if ptype == "TOR":              score += 50; flags.add("tor_exit")
        elif ptype in ("SOCKS4","SOCKS5","WEB","HTTPS"): score += 20; flags.add(f"proxy_{ptype.lower()}")
        risk = proxycheck.get("risk", 0)
        if risk >= 80:   score += 15; flags.add("high_risk")
        elif risk >= 50: score += 8;  flags.add("medium_risk")
        if proxycheck.get("operator"): flags.add("operator_identified")

    # ipapi.is
    if ipapiis.get("ok"):
        if ipapiis.get("is_vpn"):        score += 40; flags.add("vpn_confirmed")
        if ipapiis.get("is_tor"):        score += 50; flags.add("tor_exit")
        if ipapiis.get("is_proxy"):      score += 25; flags.add("proxy_confirmed")
        if ipapiis.get("is_datacenter"): score += 20; flags.add("datacenter")
        if ipapiis.get("is_abuser"):     score += 15; flags.add("abuser")

    # getipintel
    if getipintel.get("ok"):
        s = getipintel.get("score", 0)
        if s >= 0.99:   score += 30; flags.add("intel_definite")
        elif s >= 0.90: score += 20; flags.add("intel_high")
        elif s >= 0.70: score += 10; flags.add("intel_medium")

    score = min(score, 100)
    if score >= 60:   verdict, level = "VPN / Proxy",        "high"
    elif score >= 30: verdict, level = "Datacenter / Cloud", "medium"
    else:             verdict, level = "Residential",        "low"
    return {"score": score, "verdict": verdict, "level": level, "flags": sorted(flags)}

class BulkRequest(BaseModel):
    ips: list[str]

def is_valid_ip(ip: str) -> bool:
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

async def lookup_single(ip: str) -> dict:
    result = {
        "ip": ip, "asn": None, "org": "Unknown", "org_clean": "Unknown",
        "country": None, "country_code": None, "city": None,
        "latitude": None, "longitude": None, "timezone": None, "isp": None,
        "vpn_name": None, "vpn_name_source": None,
        "detection": {}, "provider": {},
        "raw_ip_api": {}, "raw_proxycheck": {}, "raw_ipapiis": {}, "raw_getipintel": {},
        "mmdb_available": False, "sources": {}
    }

    if not is_valid_ip(ip):
        result["error"] = "Invalid IP address"; return result

    # ── 1. MMDB ───────────────────────────────────────────────────────────────
    if MMDB_ASN.exists():
        try:
            with geoip2.database.Reader(str(MMDB_ASN)) as r:
                a = r.asn(ip)
                result["asn"] = f"AS{a.autonomous_system_number}"
                result["org"] = a.autonomous_system_organization or "Unknown"
                result["mmdb_available"] = True
        except geoip2.errors.AddressNotFoundError: pass

    if MMDB_CITY.exists():
        try:
            with geoip2.database.Reader(str(MMDB_CITY)) as r:
                c = r.city(ip)
                result["country"]      = c.country.name
                result["country_code"] = c.country.iso_code
                result["city"]         = c.city.name
                result["latitude"]     = c.location.latitude
                result["longitude"]    = c.location.longitude
                result["timezone"]     = c.location.time_zone
        except geoip2.errors.AddressNotFoundError: pass

    # ── 2. All external APIs in parallel ──────────────────────────────────────
    async with httpx.AsyncClient() as client:
        ip_api_task, pc_task, ia_task, gi_task = await asyncio.gather(
            client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields":"status,message,country,countryCode,city,isp,org,as,proxy,hosting,vpn,timezone,lat,lon"},
                timeout=5.0
            ),
            fetch_proxycheck(ip, client),
            fetch_ipapiis(ip, client),
            fetch_getipintel(ip, client),
            return_exceptions=True
        )

    # Parse ip-api
    ip_api_data: dict = {}
    if not isinstance(ip_api_task, Exception):
        try:
            ip_api_data = ip_api_task.json()
            if ip_api_data.get("status") == "success":
                result["raw_ip_api"] = ip_api_data
                if not result["country"]:      result["country"]      = ip_api_data.get("country")
                if not result["country_code"]: result["country_code"] = ip_api_data.get("countryCode")
                if not result["city"]:         result["city"]         = ip_api_data.get("city")
                if not result["timezone"]:     result["timezone"]     = ip_api_data.get("timezone")
                if not result["latitude"]:     result["latitude"]     = ip_api_data.get("lat")
                if not result["longitude"]:    result["longitude"]    = ip_api_data.get("lon")
                if not result["asn"]:          result["asn"]          = ip_api_data.get("as","").split(" ")[0]
                result["isp"] = ip_api_data.get("isp")
                if result["org"] == "Unknown":
                    result["org"] = ip_api_data.get("org") or ip_api_data.get("isp") or "Unknown"
        except Exception: pass

    proxycheck_data = pc_task if not isinstance(pc_task, Exception) else {}
    ipapiis_data    = ia_task if not isinstance(ia_task, Exception) else {}
    getipintel_data = gi_task if not isinstance(gi_task, Exception) else {}

    result["raw_proxycheck"] = proxycheck_data
    result["raw_ipapiis"]    = ipapiis_data
    result["raw_getipintel"] = getipintel_data

    # ── 3. Determine VPN name — priority chain ────────────────────────────────
    #  P1: IP range match  (e.g. "VPN Gate", "SoftEther VPN", "Mullvad VPN")
    #  P2: proxycheck operator field  (e.g. "Mullvad VPN", "NordVPN")
    #  P3: ASN keyword match → cleaned org name
    vpn_name: str | None = None
    vpn_name_source: str | None = None
    vpn_website: str | None = None

    range_name, range_site = detect_by_ip_range(ip)
    if range_name:
        vpn_name        = range_name
        vpn_name_source = "ip_range"
        vpn_website     = range_site
    elif isinstance(proxycheck_data, dict) and proxycheck_data.get("operator"):
        vpn_name        = proxycheck_data["operator"]
        vpn_name_source = "proxycheck"
    
    result["vpn_name"]        = vpn_name
    result["vpn_name_source"] = vpn_name_source

    # Build org_clean and provider block
    if vpn_name:
        result["org_clean"] = vpn_name
        pinfo = get_provider_info(vpn_name)
        result["provider"] = {
            "type":    pinfo.get("type") or provider_type_from_name(vpn_name),
            "website": vpn_website or pinfo.get("website"),
            "logo":    pinfo.get("logo"),
            "source":  vpn_name_source,
        }
    else:
        result["org_clean"] = clean_org(result["org"])
        pinfo = get_provider_info(result["org"])
        result["provider"]  = {**pinfo, "source": "asn_keyword"}

    ip_range_hit = bool(range_name)
    result["detection"] = score_vpn(result["org"], ip_api_data, proxycheck_data,
                                    ipapiis_data, getipintel_data, ip_range_hit)

    result["sources"] = {
        "mmdb":       result["mmdb_available"],
        "ip_api":     bool(ip_api_data.get("status") == "success"),
        "proxycheck": bool(isinstance(proxycheck_data, dict) and proxycheck_data.get("ok")),
        "ipapiis":    bool(isinstance(ipapiis_data, dict) and ipapiis_data.get("ok")),
        "getipintel": bool(isinstance(getipintel_data, dict) and getipintel_data.get("ok")),
        "ip_range":   ip_range_hit,
    }
    return result

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "mmdb_asn":      MMDB_ASN.exists(),
        "mmdb_city":     MMDB_CITY.exists(),
        "proxycheck_key":bool(PROXYCHECK_KEY),
        "ip_ranges":     len(_COMPILED_RANGES),
    }

@app.get("/api/lookup/{ip}")
async def lookup_ip(ip: str):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    return await lookup_single(ip)

@app.post("/api/bulk")
async def bulk_lookup(req: BulkRequest):
    if len(req.ips) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 IPs per request")
    ips = [ip.strip() for ip in req.ips if ip.strip()]
    results = []
    for i, ip in enumerate(ips):
        results.append(await lookup_single(ip))
        if (i + 1) % 10 == 0: await asyncio.sleep(1.0)
    return {"results": results, "total": len(results)}

@app.post("/api/export/csv")
async def export_csv(req: BulkRequest):
    ips = [ip.strip() for ip in req.ips if ip.strip()]
    results = []
    for i, ip in enumerate(ips):
        results.append(await lookup_single(ip))
        if (i + 1) % 10 == 0: await asyncio.sleep(1.0)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP","VPN Name","VPN Name Source","Verdict","Risk Score","Level",
        "Provider Type","ASN","Provider/Org","Org (Clean)","ISP",
        "Country","City","Timezone","Latitude","Longitude","Flags",
        "ProxyCheck VPN","ProxyCheck Operator","ProxyCheck Risk",
        "ipapi.is VPN","ipapi.is Tor","ipapi.is Proxy","ipapi.is Datacenter",
        "GetIPIntel Score","IP Range Match","Website","MMDB Available"
    ])
    for r in results:
        det = r.get("detection",{}); prov = r.get("provider",{})
        pc  = r.get("raw_proxycheck",{}); ia = r.get("raw_ipapiis",{}); gi = r.get("raw_getipintel",{})
        src = r.get("sources",{})
        writer.writerow([
            r.get("ip",""), r.get("vpn_name",""), r.get("vpn_name_source",""),
            det.get("verdict",""), det.get("score",""), det.get("level",""),
            prov.get("type",""), r.get("asn",""), r.get("org",""), r.get("org_clean",""),
            r.get("isp",""), r.get("country",""), r.get("city",""), r.get("timezone",""),
            r.get("latitude",""), r.get("longitude",""), ", ".join(det.get("flags",[])),
            pc.get("vpn",""), pc.get("operator",""), pc.get("risk",""),
            ia.get("is_vpn",""), ia.get("is_tor",""), ia.get("is_proxy",""), ia.get("is_datacenter",""),
            gi.get("score",""), src.get("ip_range",""), prov.get("website",""), r.get("mmdb_available",False)
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition":"attachment; filename=vpn_lookup_results.csv"}
    )


# ── AI helpers ────────────────────────────────────────────────────────────────
def _ip_context(r: dict) -> str:
    """Serialize a lookup result into a compact text context for Claude."""
    det  = r.get("detection", {})
    prov = r.get("provider", {})
    pc   = r.get("raw_proxycheck", {})
    ia   = r.get("raw_ipapiis", {})
    gi   = r.get("raw_getipintel", {})
    src  = r.get("sources", {})
    return f"""IP: {r.get("ip")}
VPN Name: {r.get("vpn_name") or "not identified"}
VPN Name Source: {r.get("vpn_name_source") or "n/a"}
Provider/Org: {r.get("org_clean") or r.get("org")}
Raw ASN Org: {r.get("org")}
ASN: {r.get("asn")}
ISP: {r.get("isp")}
Provider Type: {prov.get("type")}
Country: {r.get("country")} ({r.get("country_code")})
City: {r.get("city")}
Timezone: {r.get("timezone")}
Coordinates: {r.get("latitude")}, {r.get("longitude")}

--- Detection ---
Verdict: {det.get("verdict")}
Risk Score: {det.get("score")}/100
Level: {det.get("level")}
Flags: {", ".join(det.get("flags", []))}

--- Source Signals ---
IP Range Match: {src.get("ip_range", False)}
ProxyCheck VPN: {pc.get("vpn", "n/a")}  Proxy: {pc.get("proxy", "n/a")}  Type: {pc.get("type", "n/a")}  Operator: {pc.get("operator", "n/a")}  Risk: {pc.get("risk", "n/a")}
ipapi.is VPN: {ia.get("is_vpn")}  Tor: {ia.get("is_tor")}  Proxy: {ia.get("is_proxy")}  Datacenter: {ia.get("is_datacenter")}  Abuser: {ia.get("is_abuser")}
GetIPIntel Score: {gi.get("score", "n/a")}
"""

class AnalyzeRequest(BaseModel):
    result: dict

class ChatRequest(BaseModel):
    result: dict
    messages: list[dict]

class ReportRequest(BaseModel):
    results: list[dict]

def _claude_client():
    if not ANTHROPIC_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")
    return anthropic.Anthropic(api_key=ANTHROPIC_KEY)


# ── POST /api/ai/analyze ─────────────────────────────────────────────────────
@app.post("/api/ai/analyze")
async def ai_analyze(req: AnalyzeRequest):
    """Stream an AI threat analysis for a single IP lookup result."""
    client = _claude_client()
    ctx = _ip_context(req.result)

    system = """You are a cybersecurity analyst specializing in IP intelligence and threat assessment.
Given structured IP lookup data, produce a clear, actionable threat analysis.
Format your response in these exact sections using markdown:

## Summary
One sentence verdict.

## What this IP is
Explain what the provider/service is. Be specific — name the VPN product, datacenter, or ISP.

## Why it scored {score}/100
Walk through the signals: which flags fired, what each means.

## Risk assessment
Concrete risk level with real-world context. Who typically uses this IP? What threats does it pose?

## Recommended action
Clear, specific action: block / monitor / allow / investigate. Include any filter rules if relevant.

Keep each section concise — 2-4 sentences. No bullet spam. Plain professional language."""

    def generate():
        with client.messages.stream(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            system=system,
            messages=[{"role": "user", "content": f"Analyze this IP:\n\n{ctx}"}]
        ) as stream:
            for text in stream.text_stream:
                yield f"data: {json.dumps({'text': text})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── POST /api/ai/chat ────────────────────────────────────────────────────────
@app.post("/api/ai/chat")
async def ai_chat(req: ChatRequest):
    """Stream a conversational reply about an IP."""
    client = _claude_client()
    ctx = _ip_context(req.result)

    system = f"""You are a cybersecurity analyst. Answer questions about the following IP address.
Be concise, technical, and helpful. When asked yes/no questions, lead with the answer.
If you don't know something not in the data, say so honestly.

IP DATA:
{ctx}"""

    messages = [{"role": m["role"], "content": m["content"]} for m in req.messages]

    def generate():
        with client.messages.stream(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            system=system,
            messages=messages
        ) as stream:
            for text in stream.text_stream:
                yield f"data: {json.dumps({'text': text})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── POST /api/ai/report ──────────────────────────────────────────────────────
@app.post("/api/ai/report")
async def ai_report(req: ReportRequest):
    """Generate a markdown threat report for bulk results, returned as a downloadable .md file."""
    client = _claude_client()

    if not req.results:
        raise HTTPException(status_code=400, detail="No results provided")

    # Build summary table
    rows = []
    high, medium, low = [], [], []
    for r in req.results[:50]:  # cap at 50 for token limit
        det = r.get("detection", {})
        lvl = det.get("level", "low")
        if lvl == "high":   high.append(r)
        elif lvl == "medium": medium.append(r)
        else: low.append(r)
        rows.append(
            f"| {r.get('ip')} | {r.get('vpn_name') or r.get('org_clean') or r.get('org')} "
            f"| {det.get('verdict')} | {det.get('score')}/100 "
            f"| {r.get('country','')} | {', '.join(det.get('flags',[])[:3])} |"
        )

    table = "| IP | Provider | Verdict | Score | Country | Signals |
|---|---|---|---|---|---|
" + "
".join(rows)

    prompt = f"""You are a senior cybersecurity analyst. Write a professional threat intelligence report for the following bulk IP scan results.

SCAN SUMMARY:
- Total IPs scanned: {len(req.results)}
- High risk (VPN/Proxy): {len(high)}
- Medium risk (Datacenter): {len(medium)}
- Low risk (Residential/ISP): {len(low)}

RESULTS TABLE:
{table}

HIGH RISK IPs: {', '.join(r.get('ip','') for r in high[:10])}
MEDIUM RISK IPs: {', '.join(r.get('ip','') for r in medium[:10])}

Write the report in this exact structure:

# IP Threat Intelligence Report

## Executive Summary
3-4 sentences: total scanned, key findings, overall risk posture.

## Key Findings
Most important patterns — which VPN providers appeared, datacenter clusters, geographic anomalies.

## High Risk IPs
For each high-risk IP: IP, provider, why it's high risk, recommended action.

## Medium Risk IPs  
Brief overview of datacenter/cloud IPs and their significance.

## Recommendations
3-5 specific, actionable recommendations based on the findings.

## Conclusion
One paragraph closing summary.

---
*Report generated by VPN Detector AI · {len(req.results)} IPs analyzed*"""

    msg = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    report_md = msg.content[0].text

    return Response(
        content=report_md.encode("utf-8"),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=vpn_threat_report.md"}
    )


FRONTEND_DIR = BASE_DIR / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
