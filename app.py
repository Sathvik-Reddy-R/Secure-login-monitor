from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    flash
)
import hashlib
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message

import sqlite3
import random

from config import Config
from database import init_db
from security import (
    get_ip_info,
    is_tor,
    is_vpn,
    is_datacenter,
    is_bad_user_agent,
    is_blocked,
    block_ip
)

# ==================================================
# APP CONFIG
# ==================================================

app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
mail = Mail(app)

DB = Config.DB_NAME

# ==================================================
# MAIL ALERT
# ==================================================

def send_alert(subject, body):

    try:

        msg = Message(
            subject=subject,
            sender=Config.MAIL_USERNAME,
            recipients=[Config.MAIL_USERNAME]
        )

        msg.body = body

        mail.send(msg)

    except Exception as e:

        print("MAIL ERROR:", e)

# ==================================================
# HELPER FUNCTIONS
# ==================================================

def generate_fingerprint():

    user_agent = request.headers.get(
        "User-Agent",
        ""
    )

    accept_language = request.headers.get(
        "Accept-Language",
        ""
    )

    fingerprint = hashlib.sha256(
        (
            user_agent +
            accept_language
        ).encode()
    ).hexdigest()

    return fingerprint


def generate_otp():

    return str(
        random.randint(
            100000,
            999999
        )
    )


def save_otp(email, otp):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT OR REPLACE INTO otp_codes
        VALUES (?, ?, datetime('now','+5 minutes'))
        """,
        (email, otp)
    )

    conn.commit()
    conn.close()


def is_trusted_device(username, device_hash):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT *
        FROM trusted_devices
        WHERE username=?
        AND device_hash=?
        """,
        (
            username,
            device_hash
        )
    )

    result = cur.fetchone()
    conn.close()

    return result is not None


def save_trusted_device(username, device_hash):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO trusted_devices
        (
            username,
            device_hash
        )
        VALUES (?,?)
        """,
        (
            username,
            device_hash
        )
    )

    conn.commit()
    conn.close()

# ==================================================
# SECURITY CHECK
# ==================================================

def security_check(ip):

    if ip in Config.WHITELIST_IPS:
        return None

    if is_blocked(ip):
        return "ACCESS DENIED"

    info = get_ip_info(ip)
    org = info["org"].lower()

    vpn_or_datacenter = (
        is_vpn(org) or
        is_datacenter(org)
    )

    if vpn_or_datacenter:

        attempts = track_request(ip)

        print(
            f"[VPN REQUEST] {ip} -> {attempts}"
        )

        if attempts >= 5:

            block_ip(
                ip,
                "VPN PAGE LIMIT"
            )

            send_alert(
                "[BLOCKED] VPN PAGE LIMIT",
                f"""
IP: {ip}
ORG: {org}
REQUESTS: {attempts}
"""
            )

            return "ACCESS BLOCKED"

    user_agent = request.headers.get(
        "User-Agent",
        ""
    )

    if is_bad_user_agent(user_agent):

        block_ip(
            ip,
            "Bad User Agent"
        )

        return "ACCESS BLOCKED"

    if is_tor(ip):

        block_ip(
            ip,
            "TOR Exit Node"
        )
        info = get_ip_info(ip)

        print(f"[TOR BLOCKED] {ip}")

        send_alert(
             "[BLOCKED] TOR ACCESS DETECTED",
             f"""
IP: {ip}

City: {info['city']}

Region: {info['region']}

Country: {info['country']}

Organization: {info['org']}

Reason:
TOR Exit Node Detected

Action:
IP Blocked Automatically
"""
    )

        return "TOR ACCESS BLOCKED"

    return None

# ==================================================
# LOGIN ATTEMPTS
# ==================================================

def track_login_attempt(ip):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT attempts
        FROM login_attempts
        WHERE ip=?
        """,
        (ip,)
    )

    row = cur.fetchone()

    if row:

        attempts = row[0] + 1

        cur.execute(
            """
            UPDATE login_attempts
            SET attempts=?
            WHERE ip=?
            """,
            (attempts, ip)
        )

    else:

        attempts = 1

        cur.execute(
            """
            INSERT INTO login_attempts
            (ip,attempts)
            VALUES (?,?)
            """,
            (ip, attempts)
        )

    conn.commit()
    conn.close()

    return attempts

# ==================================================
# RESET ATTEMPTS
# ==================================================

def reset_attempts(ip):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM login_attempts
        WHERE ip=?
        """,
        (ip,)
    )

    conn.commit()
    conn.close()

# ==================================================
# TRACK REQUESTS
# ==================================================

def track_request(ip):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        "SELECT attempts FROM ip_requests WHERE ip=?",
        (ip,)
    )

    row = cur.fetchone()

    if row:

        attempts = row[0] + 1

        cur.execute(
            """
            UPDATE ip_requests
            SET attempts=?
            WHERE ip=?
            """,
            (attempts, ip)
        )

    else:

        attempts = 1

        cur.execute(
            """
            INSERT INTO ip_requests(ip,attempts)
            VALUES (?,?)
            """,
            (ip, attempts)
        )

    conn.commit()
    conn.close()

    return attempts

# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    return redirect("/login")

# ==================================================
# REGISTER
# ==================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    ip = request.remote_addr

    result = security_check(ip)

    if result:
        return result

    if request.method == "POST":

        username = request.form["username"].strip()

        email = request.form["email"].strip()

        password = request.form["password"]

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        try:

            conn = sqlite3.connect(DB)
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password
                )
                VALUES (?,?,?)
                """,
                (
                    username,
                    email,
                    hashed_password
                )
            )

            conn.commit()
            conn.close()

            flash(
                "Registration Successful",
                "success"
            )

            return redirect("/login")

        except Exception as e:

            flash(
                "Username or Email Exists",
                "danger"
            )

            print(e)

    return render_template(
        "register.html"
    )

# ==================================================
# LOGIN
# ==================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    ip = request.remote_addr

    result = security_check(ip)

    if result:
        return result

    error = ""

    if request.method == "POST":

        user_input = request.form["input"]

        password = request.form["password"]

        conn = sqlite3.connect(DB)
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                username,
                password
            FROM users
            WHERE
                username=?
                OR email=?
            """,
            (
                user_input,
                user_input
            )
        )

        user = cur.fetchone()

        conn.close()

        if user:

            if bcrypt.check_password_hash(
                user[1],
                password
            ):

                info = get_ip_info(ip)

                org = info["org"].lower()

                device_hash = generate_fingerprint()

                vpn_detected = (
                    is_vpn(org) or
                    is_datacenter(org)
                )

                if vpn_detected:

                    if not is_trusted_device(
                        user[0],
                        device_hash
                    ):

                        otp = generate_otp()

                        save_otp(
                            user_input,
                            otp
                        )

                        send_alert(
                            "VPN Login OTP",
                            f"""
Your verification code:

{otp}

Valid for 5 minutes.
"""
                        )

                        session["pending_user"] = user[0]

                        session["device_hash"] = device_hash

                        return redirect(
                            "/verify-otp"
                        )

                session["user"] = user[0]

                reset_attempts(ip)

                return redirect("/welcome")

        attempts = track_login_attempt(ip)

        print(
            f"[TRACKING] {ip} -> {attempts}"
        )

        info = get_ip_info(ip)

        org = info["org"].lower()

        residential_keywords = [
            "airtel",
            "jio",
            "verizon",
            "comcast",
            "act",
            "vodafone",
            "telecom",
            "att",
            "tmobile"
        ]

        vpn_keywords = [
            "proton",
            "nord",
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
            "opera vpn"
        ]

        datacenter_keywords = [
            "host",
            "hosting",
            "cloud",
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
            "as62240",
            "cloudflare"
        ]

        is_residential = any(
            keyword in org
            for keyword in residential_keywords
        )

        is_vpn_provider = any(
            keyword in org
            for keyword in vpn_keywords
        )

        is_datacenter_provider = any(
            keyword in org
            for keyword in datacenter_keywords
        )

        print("=" * 60)
        print(f"IP          : {ip}")
        print(f"ORG         : {org}")
        print(f"ATTEMPTS    : {attempts}")
        print(f"RESIDENTIAL : {is_residential}")
        print(f"VPN         : {is_vpn_provider}")
        print(f"DATACENTER  : {is_datacenter_provider}")
        print("=" * 60)

        # VPN / Datacenter -> block after 5 failed attempts

        if is_vpn_provider or is_datacenter_provider:

            if attempts >= 5:

                block_ip(
                    ip,
                    "VPN/DATACENTER FAILED LOGIN LIMIT"
                )

                send_alert(
                    "[BLOCKED] VPN/DATACENTER USER",
                    f"""
IP: {ip}

ORG: {org}

ATTEMPTS: {attempts}
"""
                )

                return "ACCESS BLOCKED"

        # Residential -> warn after 10

        elif is_residential:

            if attempts >= 10:

                send_alert(
                    "[WARNING] Residential Login Abuse",
                    f"""
IP: {ip}

ORG: {org}

ATTEMPTS: {attempts}
"""
                )

        # Unknown network -> block after 10

        else:

            if attempts >= 10:

                block_ip(
                    ip,
                    "UNKNOWN NETWORK FAILED LOGIN LIMIT"
                )

                return "ACCESS BLOCKED"

        error = "Invalid Credentials"

    return render_template(
        "login.html",
        error=error
    )

# ==================================================
# VERIFY OTP
# ==================================================

@app.route(
    "/verify-otp",
    methods=["GET", "POST"]
)
def verify_otp():

    error = ""

    if request.method == "POST":

        entered_otp = request.form["otp"]

        username = session.get(
            "pending_user"
        )

        device_hash = session.get(
            "device_hash"
        )

        conn = sqlite3.connect(DB)
        cur = conn.cursor()

        cur.execute(
            """
            SELECT otp
            FROM otp_codes
            ORDER BY rowid DESC
            LIMIT 1
            """
        )

        row = cur.fetchone()

        conn.close()

        if row:

            stored_otp = row[0]

            if entered_otp == stored_otp:

                save_trusted_device(
                    username,
                    device_hash
                )

                session["user"] = username

                session.pop(
                    "pending_user",
                    None
                )

                session.pop(
                    "device_hash",
                    None
                )

                return redirect(
                    "/welcome"
                )

        error = "Invalid OTP"

    return render_template(
        "verify_otp.html",
        error=error
    )

# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

# ==================================================
# FORGOT PASSWORD
# ==================================================

@app.route("/forgot")
def forgot():

    ip = request.remote_addr

    result = security_check(ip)

    if result:
        return result

    info = get_ip_info(ip)

    send_alert(
        "[INFO] Forgot Password Request",
        f"""
IP: {ip}

City:
{info['city']}

Region:
{info['region']}

Country:
{info['country']}

Organization:
{info['org']}
"""
    )

    return """
    <h2>Password Reset Request Logged</h2>
    <p>Administrator has been notified.</p>
    """

# ==================================================
# WELCOME
# ==================================================

@app.route("/welcome")
def welcome():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "welcome.html",
        user=session["user"]
    )

# ==================================================
# BLOCKED IPS PAGE
# ==================================================

@app.route("/admin/blocked")
def blocked_ips():

    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            ip,
            reason,
            created_at
        FROM blocked_ips
        ORDER BY created_at DESC
        """
    )

    rows = cur.fetchall()

    conn.close()

    html = """
    <h2>Blocked IPs</h2>
    <table border=1>
    <tr>
    <th>IP</th>
    <th>Reason</th>
    <th>Date</th>
    </tr>
    """

    for row in rows:

        html += f"""
        <tr>
        <td>{row[0]}</td>
        <td>{row[1]}</td>
        <td>{row[2]}</td>
        </tr>
        """

    html += "</table>"

    return html

# ==================================================
# START
# ==================================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
