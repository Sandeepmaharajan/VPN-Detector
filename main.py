from fastapi import FastAPI, HTTPException
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
from pathlib import Path

app = FastAPI(title="VPN Detector API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR  = Path(__file__).parent
MMDB_ASN  = BASE_DIR / "mmdb" / "GeoLite2-ASN.mmdb"
MMDB_CITY = BASE_DIR / "mmdb" / "GeoLite2-City.mmdb"

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

# ── Known VPN IP ranges → provider name ─────────────────────────────────────
# Add more ranges as you discover them
VPN_IP_RANGES: dict[str, list[str]] = {
    "Mullvad VPN":          ["185.213.154.0/24","185.65.134.0/23","193.138.218.0/24","91.90.44.0/23","45.83.220.0/22","194.165.16.0/22"],
    "NordVPN":              ["103.86.96.0/22","185.234.216.0/22","194.165.16.0/22","37.120.217.0/24","45.134.212.0/22"],
    "ExpressVPN":           ["91.207.174.0/24","92.223.88.0/24","105.235.237.0/24","119.28.136.0/24"],
    "ProtonVPN":            ["185.159.156.0/22","37.19.198.0/23","185.107.80.0/22","149.88.104.0/23"],
    "Surfshark":            ["45.139.48.0/22","156.146.56.0/22","194.165.16.0/22","185.230.124.0/22"],
    "IPVanish":             ["198.8.80.0/20","209.95.50.0/24","64.120.0.0/16"],
    "CyberGhost":           ["93.115.24.0/22","77.247.96.0/20","185.189.112.0/22"],
    "Private Internet Access": ["198.8.80.0/20","209.222.18.0/23","104.200.128.0/18"],
    "TorGuard":             ["23.19.244.0/23","192.72.220.0/22","104.192.2.0/23"],
    "Windscribe":           ["185.242.4.0/22","64.44.32.0/20","149.34.0.0/17"],
    "PureVPN":              ["91.109.4.0/22","185.94.96.0/22","37.120.152.0/22"],
    "HideMyAss":            ["37.19.200.0/21","93.94.95.0/24","199.115.116.0/22"],
    "Hotspot Shield":       ["66.187.76.0/22","52.20.155.0/24","69.197.128.0/18"],
    "Astrill":              ["185.195.232.0/22","188.166.0.0/17","45.136.28.0/22"],
    "TunnelBear":           ["216.245.212.0/22","23.129.64.0/18","45.152.66.0/23"],
    "VyprVPN":              ["91.108.4.0/22","195.181.160.0/21","37.120.197.0/24"],
    "SoftEther VPN":        ["124.18.0.0/16","219.117.0.0/16","150.246.0.0/16"],
    "Tor":                  ["185.220.100.0/22","185.220.101.0/24","51.15.0.0/16","199.87.154.0/23","171.25.193.0/24","62.102.148.0/22"],
    "Cloudflare WARP":      ["162.159.192.0/24","162.159.193.0/24","162.159.195.0/24"],
}

def detect_vpn_by_ip_range(ip: str) -> str | None:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for provider, ranges in VPN_IP_RANGES.items():
            for r in ranges:
                if ip_obj in ipaddress.ip_network(r, strict=False):
                    return provider
    except Exception:
        pass
    return None

# ── VPN protocol / technology keywords ───────────────────────────────────────
VPN_KEYWORDS = [
    "vpn","mullvad","nordvpn","expressvpn","protonvpn","surfshark",
    "ipvanish","cyberghost","pia","private internet access","hidemyass",
    "torguard","windscribe","tunnelbear","hotspot shield","purevpn",
    "hide.me","vyprvpn","strongvpn","ivacy","perfect privacy",
    "astrill","cactusvpn","fastestvpn","safervpn","zenmate",
    "privatevpn","anonine","ovpn","azirevpn","trust.zone",
    "softether","openvpn","wireguard","l2tp","ikev2","pptp","sstp",
    "tor","torproject","exit node","anonymizer","anonymous","anon",
    "proxy","socks","socks5","vpngate","vpnjantit","freevpn",
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
PROVIDER_DB = {
    "mullvad":           {"type":"VPN Provider","website":"https://mullvad.net",                    "logo":"https://logo.clearbit.com/mullvad.net"},
    "nordvpn":           {"type":"VPN Provider","website":"https://nordvpn.com",                    "logo":"https://logo.clearbit.com/nordvpn.com"},
    "expressvpn":        {"type":"VPN Provider","website":"https://expressvpn.com",                 "logo":"https://logo.clearbit.com/expressvpn.com"},
    "protonvpn":         {"type":"VPN Provider","website":"https://protonvpn.com",                  "logo":"https://logo.clearbit.com/protonvpn.com"},
    "surfshark":         {"type":"VPN Provider","website":"https://surfshark.com",                  "logo":"https://logo.clearbit.com/surfshark.com"},
    "ipvanish":          {"type":"VPN Provider","website":"https://ipvanish.com",                   "logo":"https://logo.clearbit.com/ipvanish.com"},
    "cyberghost":        {"type":"VPN Provider","website":"https://cyberghostvpn.com",              "logo":"https://logo.clearbit.com/cyberghostvpn.com"},
    "private internet":  {"type":"VPN Provider","website":"https://privateinternetaccess.com",      "logo":"https://logo.clearbit.com/privateinternetaccess.com"},
    "torguard":          {"type":"VPN Provider","website":"https://torguard.net",                   "logo":"https://logo.clearbit.com/torguard.net"},
    "windscribe":        {"type":"VPN Provider","website":"https://windscribe.com",                 "logo":"https://logo.clearbit.com/windscribe.com"},
    "purevpn":           {"type":"VPN Provider","website":"https://purevpn.com",                    "logo":"https://logo.clearbit.com/purevpn.com"},
    "hidemyass":         {"type":"VPN Provider","website":"https://hidemyass.com",                  "logo":"https://logo.clearbit.com/hidemyass.com"},
    "hide.me":           {"type":"VPN Provider","website":"https://hide.me",                        "logo":"https://logo.clearbit.com/hide.me"},
    "strongvpn":         {"type":"VPN Provider","website":"https://strongvpn.com",                  "logo":"https://logo.clearbit.com/strongvpn.com"},
    "vyprvpn":           {"type":"VPN Provider","website":"https://vyprvpn.com",                    "logo":"https://logo.clearbit.com/vyprvpn.com"},
    "tunnelbear":        {"type":"VPN Provider","website":"https://tunnelbear.com",                 "logo":"https://logo.clearbit.com/tunnelbear.com"},
    "hotspot shield":    {"type":"VPN Provider","website":"https://hotspotshield.com",              "logo":"https://logo.clearbit.com/hotspotshield.com"},
    "zenmate":           {"type":"VPN Provider","website":"https://zenmate.com",                    "logo":"https://logo.clearbit.com/zenmate.com"},
    "astrill":           {"type":"VPN Provider","website":"https://astrill.com",                    "logo":"https://logo.clearbit.com/astrill.com"},
    "ivacy":             {"type":"VPN Provider","website":"https://ivacy.com",                      "logo":"https://logo.clearbit.com/ivacy.com"},
    "softether":         {"type":"VPN Provider","website":"https://softether.org",                  "logo":"https://logo.clearbit.com/softether.org"},
    "warp":              {"type":"VPN Provider","website":"https://cloudflare.com",                 "logo":"https://logo.clearbit.com/cloudflare.com"},
    "torproject":        {"type":"Tor Exit",    "website":"https://torproject.org",                 "logo":"https://logo.clearbit.com/torproject.org"},
    "tor exit":          {"type":"Tor Exit",    "website":"https://torproject.org",                 "logo":"https://logo.clearbit.com/torproject.org"},
    "amazon":            {"type":"Cloud",       "website":"https://aws.amazon.com",                 "logo":"https://logo.clearbit.com/aws.amazon.com"},
    "google":            {"type":"Cloud",       "website":"https://cloud.google.com",               "logo":"https://logo.clearbit.com/google.com"},
    "microsoft":         {"type":"Cloud",       "website":"https://azure.microsoft.com",            "logo":"https://logo.clearbit.com/microsoft.com"},
    "cloudflare":        {"type":"Cloud",       "website":"https://cloudflare.com",                 "logo":"https://logo.clearbit.com/cloudflare.com"},
    "digitalocean":      {"type":"Cloud",       "website":"https://digitalocean.com",               "logo":"https://logo.clearbit.com/digitalocean.com"},
    "linode":            {"type":"Cloud",       "website":"https://linode.com",                     "logo":"https://logo.clearbit.com/linode.com"},
    "vultr":             {"type":"Cloud",       "website":"https://vultr.com",                      "logo":"https://logo.clearbit.com/vultr.com"},
    "hetzner":           {"type":"Cloud",       "website":"https://hetzner.com",                    "logo":"https://logo.clearbit.com/hetzner.com"},
    "ovh":               {"type":"Cloud",       "website":"https://ovhcloud.com",                   "logo":"https://logo.clearbit.com/ovhcloud.com"},
    "leaseweb":          {"type":"Cloud",       "website":"https://leaseweb.com",                   "logo":"https://logo.clearbit.com/leaseweb.com"},
    "contabo":           {"type":"Cloud",       "website":"https://contabo.com",                    "logo":"https://logo.clearbit.com/contabo.com"},
    "scaleway":          {"type":"Cloud",       "website":"https://scaleway.com",                   "logo":"https://logo.clearbit.com/scaleway.com"},
    "packethub":         {"type":"Datacenter",  "website":"https://packethub.net",                  "logo":None},
    "m247":              {"type":"Datacenter",  "website":"https://m247.com",                       "logo":"https://logo.clearbit.com/m247.com"},
    "akamai":            {"type":"CDN",         "website":"https://akamai.com",                     "logo":"https://logo.clearbit.com/akamai.com"},
    "fastly":            {"type":"CDN",         "website":"https://fastly.com",                     "logo":"https://logo.clearbit.com/fastly.com"},
}

def get_provider_info(org: str) -> dict:
    org_lower = org.lower()
    for key, info in PROVIDER_DB.items():
        if key in org_lower:
            return info
    return {"type": None, "website": None, "logo": None}

def score_vpn(org: str, ip_api_data: dict, ip_range_hit: bool) -> dict:
    org_lower = org.lower()
    score, flags = 0, []

    if ip_range_hit:
        score += 75
        flags.append("known_vpn_range")

    for kw in VPN_KEYWORDS:
        if kw in org_lower:
            score += 60; flags.append("known_vpn_provider"); break

    for kw in DATACENTER_KEYWORDS:
        if kw in org_lower:
            score += 30; flags.append("datacenter"); break

    if ip_api_data.get("proxy"):  score += 25; flags.append("proxy")
    if ip_api_data.get("hosting"):score += 20; flags.append("hosting")
    if ip_api_data.get("vpn"):    score += 40; flags.append("vpn_flag")

    # proxycheck operator signal
    operator = ip_api_data.get("_proxycheck_operator")
    if operator:
        score += 50; flags.append("operator_match")

    score = min(score, 100)
    if score >= 60:   verdict, level = "VPN / Proxy",        "high"
    elif score >= 30: verdict, level = "Datacenter / Cloud", "medium"
    else:             verdict, level = "Residential",        "low"
    return {"score": score, "verdict": verdict, "level": level, "flags": list(set(flags))}

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
        "detection": {}, "provider": {}, "raw_ip_api": {},
        "mmdb_available": False, "vpn_name": None,
    }
    if not is_valid_ip(ip):
        result["error"] = "Invalid IP address"; return result

    # ── 1. MMDB ──────────────────────────────────────────────────────────────
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

    # ── 2. ip-api.com ─────────────────────────────────────────────────────────
    ip_api_data: dict = {}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,city,isp,org,as,proxy,hosting,vpn,timezone,lat,lon"},
            )
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    ip_api_data = d
                    result["raw_ip_api"] = d
                    if not result["country"]:      result["country"]      = d.get("country")
                    if not result["country_code"]: result["country_code"] = d.get("countryCode")
                    if not result["city"]:         result["city"]         = d.get("city")
                    if not result["timezone"]:     result["timezone"]     = d.get("timezone")
                    if not result["latitude"]:     result["latitude"]     = d.get("lat")
                    if not result["longitude"]:    result["longitude"]    = d.get("lon")
                    if not result["asn"]:          result["asn"]          = d.get("as","").split(" ")[0]
                    result["isp"] = d.get("isp")
                    if result["org"] == "Unknown":
                        result["org"] = d.get("org") or d.get("isp") or "Unknown"
    except Exception: pass

    # ── 3. IP range detection (highest accuracy) ──────────────────────────────
    vpn_name = detect_vpn_by_ip_range(ip)
    ip_range_hit = vpn_name is not None

    if vpn_name:
        result["vpn_name"]  = vpn_name
        result["org_clean"] = vpn_name
        result["provider"]  = {
            "type": "Tor Exit" if "tor" in vpn_name.lower() else "VPN Provider",
            "website": PROVIDER_DB.get(vpn_name.lower().split()[0], {}).get("website"),
            "logo":    PROVIDER_DB.get(vpn_name.lower().split()[0], {}).get("logo"),
        }
    else:
        result["org_clean"] = clean_org(result["org"])
        result["provider"]  = get_provider_info(result["org"])

    # ── 4. Score ──────────────────────────────────────────────────────────────
    result["detection"] = score_vpn(result["org"], ip_api_data, ip_range_hit)
    return result

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
        if (i + 1) % 40 == 0: await asyncio.sleep(1.5)
    return {"results": results, "total": len(results)}

@app.post("/api/export/csv")
async def export_csv(req: BulkRequest):
    ips = [ip.strip() for ip in req.ips if ip.strip()]
    results = []
    for i, ip in enumerate(ips):
        results.append(await lookup_single(ip))
        if (i + 1) % 40 == 0: await asyncio.sleep(1.5)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["IP","VPN Name","Verdict","Score","Level","Provider Type","ASN","Org","Org Clean","ISP","Country","City","Timezone","Lat","Lon","Flags","Website","MMDB"])
    for r in results:
        det = r.get("detection",{}); p = r.get("provider",{})
        w.writerow([r.get("ip",""), r.get("vpn_name",""), det.get("verdict",""),
            det.get("score",""), det.get("level",""), p.get("type",""),
            r.get("asn",""), r.get("org",""), r.get("org_clean",""),
            r.get("isp",""), r.get("country",""), r.get("city",""),
            r.get("timezone",""), r.get("latitude",""), r.get("longitude",""),
            ", ".join(det.get("flags",[])), p.get("website",""), r.get("mmdb_available",False)])
    out.seek(0)
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition":"attachment; filename=vpn_lookup_results.csv"})

FRONTEND_DIR = BASE_DIR / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
