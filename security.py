import sqlite3
import requests

DB = "security.db"


# ==================================================
# VPN PROVIDERS
# ==================================================

VPN_KEYWORDS = [

    "proton",
    "nord",
    "nforce"
    "surfshark",
    "expressvpn",
    "cyberghost",
    "pia",
    "vpn",
    "proxy",
    "hola",
    "urban vpn",
    "browsec",
    "touch vpn",
    "setupvpn",
    "windscribe",
    "mullvad",
    "opera vpn",

    # Additional Providers

    "as212238",
    "as62240",
    "as136557",

    "dataforest",
    "m247",
    "datacamp",
    "zenlayer",
    "host universal"

]

# ==================================================
# DATACENTER / CLOUD PROVIDERS
# ==================================================

DATACENTER_KEYWORDS = [

    "host",
    "hosting",
    "cloud",
    "nforce",
    "nforce entertainment",
    "as43350",
    "server",
    "vps",
    "datacenter",
    "colo",

    "amazon",
    "aws",
    "google",
    "azure",
    "oracle",

    "digitalocean",
    "linode",
    "ovh",
    "vultr",
    "choopa",
    "m247",
    "zenlayer",
    "datacamp",
    "iomart",
    "akamai",

    "cdn",
    "edge",
    "proxy",

    "latitude",
    "latitude.sh",

    "hetzner",
    "contabo",
    "leaseweb",
    "scaleway",
    "netcup",
    "hostinger",
    "cloudflare",

    # Additional Matches

    "host universal",
    "as136557",
    "as62240"
]

# ==================================================
# BAD USER AGENTS
# ==================================================

BAD_USER_AGENTS = [

    "sqlmap",
    "nikto",
    "curl",
    "python",
    "scanner",
    "bot",
    "wget"

]
  
def get_ip_info(ip):

    try:

        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=10
        )

        data = response.json()

        return {
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "org": data.get("org", "").lower()
        }

    except:

        return {
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "org": ""
        }


def is_tor(ip):

    try:

        data = requests.get(
            "https://check.torproject.org/torbulkexitlist",
            timeout=10
        ).text

        return ip in data

    except:
        return False


def is_vpn(org):

    for vpn in VPN_KEYWORDS:

        if vpn in org:
            return True

    return False


def is_datacenter(org):

    for item in DATACENTER_KEYWORDS:

        if item in org:
            return True

    return False


def is_bad_user_agent(ua):

    ua = ua.lower()

    for agent in BAD_USER_AGENTS:

        if agent in ua:
            return True

    return False

def calculate_risk_score(
    org,
    failed_attempts,
    tor_detected,
    bad_agent
):

    score = 0

    if is_vpn(org):
        score += 20

    if is_datacenter(org):
        score += 30

    if tor_detected:
        score += 100

    if bad_agent:
        score += 50

    score += failed_attempts * 10

    return score
def block_ip(ip, reason):

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(
        """
        INSERT OR IGNORE INTO blocked_ips
        (ip,reason)
        VALUES (?,?)
        """,
        (ip, reason)
    )

    conn.commit()
    conn.close()


def is_blocked(ip):

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(
        "SELECT ip FROM blocked_ips WHERE ip=?",
        (ip,)
    )

    row = cur.fetchone()

    conn.close()

    return row is not None
