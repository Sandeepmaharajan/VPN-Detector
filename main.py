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

# ── Provider catalogue: name → {type, website, logo} ────────────────────────
PROVIDER_DB = {
    # VPN providers
    "mullvad":              {"type": "VPN Provider",  "website": "https://mullvad.net",        "logo": "https://logo.clearbit.com/mullvad.net"},
    "nordvpn":              {"type": "VPN Provider",  "website": "https://nordvpn.com",         "logo": "https://logo.clearbit.com/nordvpn.com"},
    "expressvpn":           {"type": "VPN Provider",  "website": "https://expressvpn.com",      "logo": "https://logo.clearbit.com/expressvpn.com"},
    "protonvpn":            {"type": "VPN Provider",  "website": "https://protonvpn.com",       "logo": "https://logo.clearbit.com/protonvpn.com"},
    "surfshark":            {"type": "VPN Provider",  "website": "https://surfshark.com",       "logo": "https://logo.clearbit.com/surfshark.com"},
    "ipvanish":             {"type": "VPN Provider",  "website": "https://ipvanish.com",        "logo": "https://logo.clearbit.com/ipvanish.com"},
    "cyberghost":           {"type": "VPN Provider",  "website": "https://cyberghostvpn.com",   "logo": "https://logo.clearbit.com/cyberghostvpn.com"},
    "private internet":     {"type": "VPN Provider",  "website": "https://privateinternetaccess.com", "logo": "https://logo.clearbit.com/privateinternetaccess.com"},
    "torguard":             {"type": "VPN Provider",  "website": "https://torguard.net",        "logo": "https://logo.clearbit.com/torguard.net"},
    "windscribe":           {"type": "VPN Provider",  "website": "https://windscribe.com",      "logo": "https://logo.clearbit.com/windscribe.com"},
    "purevpn":              {"type": "VPN Provider",  "website": "https://purevpn.com",         "logo": "https://logo.clearbit.com/purevpn.com"},
    "hidemyass":            {"type": "VPN Provider",  "website": "https://hidemyass.com",       "logo": "https://logo.clearbit.com/hidemyass.com"},
    "hide.me":              {"type": "VPN Provider",  "website": "https://hide.me",             "logo": "https://logo.clearbit.com/hide.me"},
    "strongvpn":            {"type": "VPN Provider",  "website": "https://strongvpn.com",       "logo": "https://logo.clearbit.com/strongvpn.com"},
    "vyprvpn":              {"type": "VPN Provider",  "website": "https://vyprvpn.com",         "logo": "https://logo.clearbit.com/vyprvpn.com"},
    "tunnelbear":           {"type": "VPN Provider",  "website": "https://tunnelbear.com",      "logo": "https://logo.clearbit.com/tunnelbear.com"},
    "hotspot shield":       {"type": "VPN Provider",  "website": "https://hotspotshield.com",   "logo": "https://logo.clearbit.com/hotspotshield.com"},
    "zenmate":              {"type": "VPN Provider",  "website": "https://zenmate.com",         "logo": "https://logo.clearbit.com/zenmate.com"},
    "astrill":              {"type": "VPN Provider",  "website": "https://astrill.com",         "logo": "https://logo.clearbit.com/astrill.com"},
    "ivacy":                {"type": "VPN Provider",  "website": "https://ivacy.com",           "logo": "https://logo.clearbit.com/ivacy.com"},
    # Tor
    "torproject":           {"type": "Tor Exit",      "website": "https://torproject.org",      "logo": "https://logo.clearbit.com/torproject.org"},
    "tor exit":             {"type": "Tor Exit",      "website": "https://torproject.org",      "logo": "https://logo.clearbit.com/torproject.org"},
    # Cloud / Datacenter
    "amazon":               {"type": "Cloud",         "website": "https://aws.amazon.com",      "logo": "https://logo.clearbit.com/aws.amazon.com"},
    "google":               {"type": "Cloud",         "website": "https://cloud.google.com",    "logo": "https://logo.clearbit.com/google.com"},
    "microsoft":            {"type": "Cloud",         "website": "https://azure.microsoft.com", "logo": "https://logo.clearbit.com/microsoft.com"},
    "cloudflare":           {"type": "Cloud",         "website": "https://cloudflare.com",      "logo": "https://logo.clearbit.com/cloudflare.com"},
    "digitalocean":         {"type": "Cloud",         "website": "https://digitalocean.com",    "logo": "https://logo.clearbit.com/digitalocean.com"},
    "linode":               {"type": "Cloud",         "website": "https://linode.com",          "logo": "https://logo.clearbit.com/linode.com"},
    "vultr":                {"type": "Cloud",         "website": "https://vultr.com",           "logo": "https://logo.clearbit.com/vultr.com"},
    "hetzner":              {"type": "Cloud",         "website": "https://hetzner.com",         "logo": "https://logo.clearbit.com/hetzner.com"},
    "ovh":                  {"type": "Cloud",         "website": "https://ovhcloud.com",        "logo": "https://logo.clearbit.com/ovhcloud.com"},
    "leaseweb":             {"type": "Cloud",         "website": "https://leaseweb.com",        "logo": "https://logo.clearbit.com/leaseweb.com"},
    "contabo":              {"type": "Cloud",         "website": "https://contabo.com",         "logo": "https://logo.clearbit.com/contabo.com"},
    "scaleway":             {"type": "Cloud",         "website": "https://scaleway.com",        "logo": "https://logo.clearbit.com/scaleway.com"},
    "hetzner":              {"type": "Cloud",         "website": "https://hetzner.com",         "logo": "https://logo.clearbit.com/hetzner.com"},
    "packethub":            {"type": "Datacenter",    "website": "https://packethub.net",       "logo": None},
    "m247":                 {"type": "Datacenter",    "website": "https://m247.com",            "logo": "https://logo.clearbit.com/m247.com"},
    "akamai":               {"type": "CDN",           "website": "https://akamai.com",          "logo": "https://logo.clearbit.com/akamai.com"},
    "fastly":               {"type": "CDN",           "website": "https://fastly.com",          "logo": "https://logo.clearbit.com/fastly.com"},
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
    org_lower = org.lower()
    for key, info in PROVIDER_DB.items():
        if key in org_lower:
            return info
    return {"type": None, "website": None, "logo": None}

def score_vpn(org: str, ip_api_data: dict) -> dict:
    org_lower = org.lower()
    score, flags = 0, []
    for kw in VPN_KEYWORDS:
        if kw in org_lower:
            score += 60; flags.append("known_vpn_provider"); break
    for kw in DATACENTER_KEYWORDS:
        if kw in org_lower:
            score += 30; flags.append("datacenter"); break
    if ip_api_data.get("proxy"):  score += 25; flags.append("proxy")
    if ip_api_data.get("hosting"):score += 20; flags.append("hosting")
    if ip_api_data.get("vpn"):    score += 40; flags.append("vpn_flag")
    score = min(score, 100)
    if score >= 60:   verdict, level = "VPN / Proxy",       "high"
    elif score >= 30: verdict, level = "Datacenter / Cloud","medium"
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
        "detection": {}, "provider": {}, "raw_ip_api": {}, "mmdb_available": False,
    }
    if not is_valid_ip(ip):
        result["error"] = "Invalid IP address"; return result

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

    ip_api_data = {}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,city,isp,org,as,proxy,hosting,vpn,timezone,lat,lon"},
            )
            if resp.status_code == 200:
                ip_api_data = resp.json()
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

    result["org_clean"] = clean_org(result["org"])
    result["provider"]  = get_provider_info(result["org"])
    result["detection"] = score_vpn(result["org"], ip_api_data)
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
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP","Verdict","Risk Score","Level","Provider Type","ASN","Provider/Org","Org (Clean)","ISP","Country","City","Timezone","Latitude","Longitude","Flags","Website","MMDB Available"])
    for r in results:
        det = r.get("detection", {}); prov = r.get("provider", {})
        writer.writerow([r.get("ip",""), det.get("verdict",""), det.get("score",""), det.get("level",""),
            prov.get("type",""), r.get("asn",""), r.get("org",""), r.get("org_clean",""),
            r.get("isp",""), r.get("country",""), r.get("city",""), r.get("timezone",""),
            r.get("latitude",""), r.get("longitude",""), ", ".join(det.get("flags",[])),
            prov.get("website",""), r.get("mmdb_available",False)])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vpn_lookup_results.csv"})

FRONTEND_DIR = BASE_DIR / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
