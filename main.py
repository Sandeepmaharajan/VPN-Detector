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
import os
from pathlib import Path

app = FastAPI(title="VPN Detector API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR  = Path(__file__).parent
MMDB_ASN  = BASE_DIR / "mmdb" / "GeoLite2-ASN.mmdb"
MMDB_CITY = BASE_DIR / "mmdb" / "GeoLite2-City.mmdb"

# Optional: set PROXYCHECK_KEY env var for higher limits (free key from proxycheck.io)
PROXYCHECK_KEY = os.environ.get("PROXYCHECK_KEY", "")

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

# ── Provider catalogue ────────────────────────────────────────────────────────
PROVIDER_DB = {
    "mullvad":          {"type": "VPN Provider", "website": "https://mullvad.net",               "logo": "https://logo.clearbit.com/mullvad.net"},
    "nordvpn":          {"type": "VPN Provider", "website": "https://nordvpn.com",                "logo": "https://logo.clearbit.com/nordvpn.com"},
    "expressvpn":       {"type": "VPN Provider", "website": "https://expressvpn.com",             "logo": "https://logo.clearbit.com/expressvpn.com"},
    "protonvpn":        {"type": "VPN Provider", "website": "https://protonvpn.com",              "logo": "https://logo.clearbit.com/protonvpn.com"},
    "surfshark":        {"type": "VPN Provider", "website": "https://surfshark.com",              "logo": "https://logo.clearbit.com/surfshark.com"},
    "ipvanish":         {"type": "VPN Provider", "website": "https://ipvanish.com",               "logo": "https://logo.clearbit.com/ipvanish.com"},
    "cyberghost":       {"type": "VPN Provider", "website": "https://cyberghostvpn.com",          "logo": "https://logo.clearbit.com/cyberghostvpn.com"},
    "private internet": {"type": "VPN Provider", "website": "https://privateinternetaccess.com",  "logo": "https://logo.clearbit.com/privateinternetaccess.com"},
    "torguard":         {"type": "VPN Provider", "website": "https://torguard.net",               "logo": "https://logo.clearbit.com/torguard.net"},
    "windscribe":       {"type": "VPN Provider", "website": "https://windscribe.com",             "logo": "https://logo.clearbit.com/windscribe.com"},
    "purevpn":          {"type": "VPN Provider", "website": "https://purevpn.com",                "logo": "https://logo.clearbit.com/purevpn.com"},
    "hidemyass":        {"type": "VPN Provider", "website": "https://hidemyass.com",              "logo": "https://logo.clearbit.com/hidemyass.com"},
    "hide.me":          {"type": "VPN Provider", "website": "https://hide.me",                    "logo": "https://logo.clearbit.com/hide.me"},
    "strongvpn":        {"type": "VPN Provider", "website": "https://strongvpn.com",              "logo": "https://logo.clearbit.com/strongvpn.com"},
    "vyprvpn":          {"type": "VPN Provider", "website": "https://vyprvpn.com",                "logo": "https://logo.clearbit.com/vyprvpn.com"},
    "tunnelbear":       {"type": "VPN Provider", "website": "https://tunnelbear.com",             "logo": "https://logo.clearbit.com/tunnelbear.com"},
    "hotspot shield":   {"type": "VPN Provider", "website": "https://hotspotshield.com",          "logo": "https://logo.clearbit.com/hotspotshield.com"},
    "zenmate":          {"type": "VPN Provider", "website": "https://zenmate.com",                "logo": "https://logo.clearbit.com/zenmate.com"},
    "astrill":          {"type": "VPN Provider", "website": "https://astrill.com",                "logo": "https://logo.clearbit.com/astrill.com"},
    "ivacy":            {"type": "VPN Provider", "website": "https://ivacy.com",                  "logo": "https://logo.clearbit.com/ivacy.com"},
    "privatevpn":       {"type": "VPN Provider", "website": "https://privatevpn.com",             "logo": "https://logo.clearbit.com/privatevpn.com"},
    "cactusvpn":        {"type": "VPN Provider", "website": "https://cactusvpn.com",              "logo": "https://logo.clearbit.com/cactusvpn.com"},
    "fastestvpn":       {"type": "VPN Provider", "website": "https://fastestvpn.com",             "logo": "https://logo.clearbit.com/fastestvpn.com"},
    "ovpn":             {"type": "VPN Provider", "website": "https://www.ovpn.com",               "logo": "https://logo.clearbit.com/ovpn.com"},
    "torproject":       {"type": "Tor Exit",     "website": "https://torproject.org",             "logo": "https://logo.clearbit.com/torproject.org"},
    "tor exit":         {"type": "Tor Exit",     "website": "https://torproject.org",             "logo": "https://logo.clearbit.com/torproject.org"},
    "amazon":           {"type": "Cloud",        "website": "https://aws.amazon.com",             "logo": "https://logo.clearbit.com/aws.amazon.com"},
    "google":           {"type": "Cloud",        "website": "https://cloud.google.com",           "logo": "https://logo.clearbit.com/google.com"},
    "microsoft":        {"type": "Cloud",        "website": "https://azure.microsoft.com",        "logo": "https://logo.clearbit.com/microsoft.com"},
    "cloudflare":       {"type": "Cloud",        "website": "https://cloudflare.com",             "logo": "https://logo.clearbit.com/cloudflare.com"},
    "digitalocean":     {"type": "Cloud",        "website": "https://digitalocean.com",           "logo": "https://logo.clearbit.com/digitalocean.com"},
    "linode":           {"type": "Cloud",        "website": "https://linode.com",                 "logo": "https://logo.clearbit.com/linode.com"},
    "akamai":           {"type": "CDN",          "website": "https://akamai.com",                 "logo": "https://logo.clearbit.com/akamai.com"},
    "vultr":            {"type": "Cloud",        "website": "https://vultr.com",                  "logo": "https://logo.clearbit.com/vultr.com"},
    "hetzner":          {"type": "Cloud",        "website": "https://hetzner.com",                "logo": "https://logo.clearbit.com/hetzner.com"},
    "ovh":              {"type": "Cloud",        "website": "https://ovhcloud.com",               "logo": "https://logo.clearbit.com/ovhcloud.com"},
    "leaseweb":         {"type": "Cloud",        "website": "https://leaseweb.com",               "logo": "https://logo.clearbit.com/leaseweb.com"},
    "contabo":          {"type": "Cloud",        "website": "https://contabo.com",                "logo": "https://logo.clearbit.com/contabo.com"},
    "scaleway":         {"type": "Cloud",        "website": "https://scaleway.com",               "logo": "https://logo.clearbit.com/scaleway.com"},
    "packethub":        {"type": "Datacenter",   "website": "https://packethub.net",              "logo": None},
    "m247":             {"type": "Datacenter",   "website": "https://m247.com",                   "logo": "https://logo.clearbit.com/m247.com"},
    "fastly":           {"type": "CDN",          "website": "https://fastly.com",                 "logo": "https://logo.clearbit.com/fastly.com"},
    "frantech":         {"type": "Datacenter",   "website": "https://frantech.ca",                "logo": None},
    "hostinger":        {"type": "Cloud",        "website": "https://hostinger.com",              "logo": "https://logo.clearbit.com/hostinger.com"},
}

VPN_KEYWORDS = [
    "vpn","mullvad","nordvpn","expressvpn","protonvpn","surfshark",
    "ipvanish","cyberghost","pia","private internet access","hidemyass",
    "torguard","windscribe","tunnelbear","hotspot shield","purevpn",
    "avast","hide.me","vyprvpn","strongvpn","ivacy","perfect privacy",
    "astrill","cactusvpn","fastestvpn","safervpn","zenmate",
    "privatevpn","anonine","ovpn","azirevpn","trust.zone",
    "tor","torproject","exit node","anonymizer","anonymous",
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

def get_provider_info(org: str) -> dict:
    org_lower = (org or "").lower()
    for key, info in PROVIDER_DB.items():
        if key in org_lower:
            return info
    return {"type": "ISP", "website": None, "logo": None}

# ── Source: proxycheck.io ─────────────────────────────────────────────────────
async def fetch_proxycheck(ip: str, client: httpx.AsyncClient) -> dict:
    result = {"vpn": False, "proxy": False, "type": None, "operator": None, "risk": 0, "ok": False}
    try:
        params = {"vpn": 1, "asn": 1, "risk": 1}
        if PROXYCHECK_KEY:
            params["key"] = PROXYCHECK_KEY
        resp = await client.get(f"https://proxycheck.io/v2/{ip}", params=params, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            ip_data = data.get(ip, {})
            if ip_data:
                result["ok"]       = True
                result["vpn"]      = ip_data.get("vpn", "no") == "yes"
                result["proxy"]    = ip_data.get("proxy", "no") == "yes"
                result["type"]     = ip_data.get("type")
                result["operator"] = ip_data.get("operator")   # e.g. "Mullvad VPN" ← best field
                result["risk"]     = int(ip_data.get("risk", 0))
    except Exception:
        pass
    return result

# ── Source: ipapi.is ──────────────────────────────────────────────────────────
async def fetch_ipapiis(ip: str, client: httpx.AsyncClient) -> dict:
    result = {"is_vpn": False, "is_tor": False, "is_proxy": False,
              "is_datacenter": False, "is_abuser": False,
              "company_type": None, "abuse_score": 0, "ok": False}
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
    except Exception:
        pass
    return result

# ── Source: getipintel.net ────────────────────────────────────────────────────
async def fetch_getipintel(ip: str, client: httpx.AsyncClient) -> dict:
    result = {"score": 0.0, "ok": False}
    try:
        resp = await client.get(
            "https://check.getipintel.net/check.php",
            params={"ip": ip, "contact": "info@vpndetector.app", "flags": "m", "format": "json"},
            timeout=6.0
        )
        if resp.status_code == 200:
            data = resp.json()
            if str(data.get("status")) == "success":
                result["score"] = float(data.get("result", 0))
                result["ok"]    = True
    except Exception:
        pass
    return result

# ── Unified scoring (5 sources) ───────────────────────────────────────────────
def score_vpn(org: str, ip_api: dict, proxycheck: dict, ipapiis: dict, getipintel: dict) -> dict:
    org_lower = (org or "").lower()
    score = 0
    flags = set()

    # ASN keyword match
    for kw in VPN_KEYWORDS:
        if kw in org_lower:
            score += 55; flags.add("known_vpn_provider"); break
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
        if ptype == "TOR":
            score += 50; flags.add("tor_exit")
        elif ptype in ("SOCKS4","SOCKS5","WEB","HTTPS"):
            score += 20; flags.add(f"proxy_{ptype.lower()}")
        risk = proxycheck.get("risk", 0)
        if risk >= 80:   score += 15; flags.add("high_risk")
        elif risk >= 50: score += 8;  flags.add("medium_risk")

    # ipapi.is
    if ipapiis.get("ok"):
        if ipapiis.get("is_vpn"):        score += 40; flags.add("vpn_confirmed")
        if ipapiis.get("is_tor"):        score += 50; flags.add("tor_exit")
        if ipapiis.get("is_proxy"):      score += 25; flags.add("proxy_confirmed")
        if ipapiis.get("is_datacenter"): score += 20; flags.add("datacenter")
        if ipapiis.get("is_abuser"):     score += 15; flags.add("abuser")

    # getipintel probability
    if getipintel.get("ok"):
        s = getipintel.get("score", 0)
        if s >= 0.99:   score += 30; flags.add("intel_definite")
        elif s >= 0.90: score += 20; flags.add("intel_high")
        elif s >= 0.70: score += 10; flags.add("intel_medium")

    score = min(score, 100)

    if score >= 60:   verdict, level = "VPN / Proxy",        "high"
    elif score >= 30: verdict, level = "Datacenter / Cloud", "medium"
    else:             verdict, level = "Residential",         "low"

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
        "detection": {}, "provider": {},
        "raw_ip_api": {}, "raw_proxycheck": {}, "raw_ipapiis": {}, "raw_getipintel": {},
        "mmdb_available": False, "sources": {}
    }

    if not is_valid_ip(ip):
        result["error"] = "Invalid IP address"; return result

    # MMDB (local, fast)
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

    # All 4 external APIs in parallel
    async with httpx.AsyncClient() as client:
        ip_api_task, pc_task, ia_task, gi_task = await asyncio.gather(
            client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,city,isp,org,as,proxy,hosting,vpn,timezone,lat,lon"},
                timeout=5.0
            ),
            fetch_proxycheck(ip, client),
            fetch_ipapiis(ip, client),
            fetch_getipintel(ip, client),
            return_exceptions=True
        )

    # Parse ip-api
    ip_api_data = {}
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

    # Use proxycheck operator name if available — it's the most accurate provider name
    operator = proxycheck_data.get("operator") if isinstance(proxycheck_data, dict) else None
    result["org_clean"] = operator if operator else clean_org(result["org"])
    result["provider"]  = get_provider_info(operator or result["org"])
    result["detection"] = score_vpn(result["org"], ip_api_data, proxycheck_data, ipapiis_data, getipintel_data)

    result["sources"] = {
        "mmdb":       result["mmdb_available"],
        "ip_api":     bool(isinstance(result["raw_ip_api"], dict) and result["raw_ip_api"].get("status") == "success"),
        "proxycheck": bool(isinstance(proxycheck_data, dict) and proxycheck_data.get("ok")),
        "ipapiis":    bool(isinstance(ipapiis_data, dict) and ipapiis_data.get("ok")),
        "getipintel": bool(isinstance(getipintel_data, dict) and getipintel_data.get("ok")),
    }

    return result


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "mmdb_asn":  MMDB_ASN.exists(),
        "mmdb_city": MMDB_CITY.exists(),
        "proxycheck_key": bool(PROXYCHECK_KEY),
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
        if (i + 1) % 10 == 0:
            await asyncio.sleep(1.0)
    return {"results": results, "total": len(results)}

@app.post("/api/export/csv")
async def export_csv(req: BulkRequest):
    ips = [ip.strip() for ip in req.ips if ip.strip()]
    results = []
    for i, ip in enumerate(ips):
        results.append(await lookup_single(ip))
        if (i + 1) % 10 == 0:
            await asyncio.sleep(1.0)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP","Verdict","Risk Score","Level","Provider Type","ASN",
        "Provider/Org","Org (Clean)","ISP","Country","City","Timezone",
        "Latitude","Longitude","Flags",
        "ProxyCheck VPN","ProxyCheck Operator","ProxyCheck Risk",
        "ipapi.is VPN","ipapi.is Tor","ipapi.is Proxy","ipapi.is Datacenter",
        "GetIPIntel Score","Website","MMDB Available"
    ])
    for r in results:
        det = r.get("detection", {}); prov = r.get("provider", {})
        pc  = r.get("raw_proxycheck", {}); ia = r.get("raw_ipapiis", {}); gi = r.get("raw_getipintel", {})
        writer.writerow([
            r.get("ip",""), det.get("verdict",""), det.get("score",""), det.get("level",""),
            prov.get("type",""), r.get("asn",""), r.get("org",""), r.get("org_clean",""),
            r.get("isp",""), r.get("country",""), r.get("city",""), r.get("timezone",""),
            r.get("latitude",""), r.get("longitude",""), ", ".join(det.get("flags",[])),
            pc.get("vpn",""), pc.get("operator",""), pc.get("risk",""),
            ia.get("is_vpn",""), ia.get("is_tor",""), ia.get("is_proxy",""), ia.get("is_datacenter",""),
            gi.get("score",""), prov.get("website",""), r.get("mmdb_available",False)
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vpn_lookup_results.csv"}
    )

FRONTEND_DIR = BASE_DIR / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
